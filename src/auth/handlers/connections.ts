import { Request, Response, NextFunction } from 'express';
import { getProvider } from '../providers';
import { decrypt } from '../../crypto/tokens';
import { query } from '../../db/client';

interface OAuthConnectionMetaRow {
  provider: string;
  scopes: string[];
  created_at: Date | string;
}

interface OAuthConnectionSecretRow {
  access_token: string;
  refresh_token: string | null;
}

/**
 * GET /auth/connections
 * Returns a list of active OAuth connections for the authenticated user.
 * Strictly returns metadata only (provider, scopes, connectedAt). Never returns tokens.
 */
export async function handleGetConnections(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    if (!req.user || !req.user.userId) {
      res.status(401).json({ error: 'unauthorized', message: 'User context is missing' });
      return;
    }

    const result = await query<OAuthConnectionMetaRow>(
      `SELECT provider, scopes, created_at
       FROM oauth_connections
       WHERE user_id = $1
       ORDER BY created_at ASC;`,
      [req.user.userId]
    );

    const connections = result.rows.map(row => ({
      provider: row.provider,
      scopes: row.scopes || [],
      connectedAt: row.created_at
    }));

    res.status(200).json(connections);
  } catch (error) {
    next(error);
  }
}

/**
 * DELETE /auth/:provider/disconnect
 * Disconnects an OAuth provider connection for the authenticated user.
 * Attempts best-effort token revocation if provider.revokeUrl is configured.
 * Revocation errors are logged server-side but do NOT fail the disconnect.
 */
export async function handleDisconnect(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const providerName = typeof req.params.provider === 'string' ? req.params.provider : undefined;
    if (!providerName) {
      res.status(400).json({ error: 'invalid_request', message: 'Provider parameter is required' });
      return;
    }

    if (!req.user || !req.user.userId) {
      res.status(401).json({ error: 'unauthorized', message: 'User context is missing' });
      return;
    }

    let provider;
    try {
      provider = getProvider(providerName);
    } catch (err) {
      const message = err instanceof Error ? err.message : `Provider '${providerName}' not found`;
      res.status(400).json({ error: 'invalid_provider', message });
      return;
    }

    // Check if a connection exists for this user and provider
    const existingRes = await query<OAuthConnectionSecretRow>(
      `SELECT access_token, refresh_token
       FROM oauth_connections
       WHERE user_id = $1 AND provider = $2;`,
      [req.user.userId, provider.name]
    );

    const row = existingRes.rows[0];

    if (row && provider.revokeUrl) {
      // Best-effort token revocation (I9)
      try {
        const tokenToRevoke = row.refresh_token
          ? decrypt(row.refresh_token)
          : decrypt(row.access_token);

        const revokeBody = new URLSearchParams({
          token: tokenToRevoke
        });

        const revokeRes = await fetch(provider.revokeUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          body: revokeBody.toString()
        });

        if (!revokeRes.ok) {
          const errText = await revokeRes.text();
          console.warn(`Best-effort token revocation warning for ${provider.name} (HTTP ${revokeRes.status}):`, errText);
        }
      } catch (revokeErr) {
        // Revoke failure must not fail the disconnect
        console.warn(`Best-effort token revocation network failure for ${provider.name}:`, revokeErr);
      }
    }

    // Delete row from database
    await query(
      `DELETE FROM oauth_connections
       WHERE user_id = $1 AND provider = $2;`,
      [req.user.userId, provider.name]
    );

    res.status(200).json({
      success: true
    });
  } catch (error) {
    next(error);
  }
}
