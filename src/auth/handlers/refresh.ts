import { Request, Response, NextFunction } from 'express';
import { getProvider } from '../providers';
import { encrypt, decrypt } from '../../crypto/tokens';
import { query } from '../../db/client';

export class OAuthConnectionNotFound extends Error {
  constructor(message = 'OAuth connection not found') {
    super(message);
    this.name = 'OAuthConnectionNotFound';
  }
}

export class OAuthRefreshFailed extends Error {
  constructor(message = 'OAuth token refresh failed') {
    super(message);
    this.name = 'OAuthRefreshFailed';
  }
}

interface OAuthConnectionRow {
  id: string;
  user_id: string;
  provider: string;
  access_token: string;
  refresh_token: string | null;
  prev_refresh_token: string | null;
  expires_at: Date | string | null;
}

const REFRESH_BUFFER_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Returns a valid, decrypted access token for a user and provider.
 * Callable as a plain server-side function by background tasks/cron jobs.
 * Proactively refreshes the token if it is within 5 minutes of expiry.
 */
export async function getValidToken(userId: string, provider: string): Promise<string> {
  const normalizedProvider = provider.toLowerCase().trim();

  const res = await query<OAuthConnectionRow>(
    `SELECT id, user_id, provider, access_token, refresh_token, prev_refresh_token, expires_at
     FROM oauth_connections
     WHERE user_id = $1 AND provider = $2;`,
    [userId, normalizedProvider]
  );

  const row = res.rows[0];
  if (!row) {
    throw new OAuthConnectionNotFound(
      `No active OAuth connection found for user '${userId}' and provider '${normalizedProvider}'`
    );
  }

  const expiresAtMs = row.expires_at ? new Date(row.expires_at).getTime() : null;

  // If token is present and expires more than 5 minutes from now, return it directly
  if (expiresAtMs !== null && expiresAtMs - Date.now() > REFRESH_BUFFER_MS) {
    return decrypt(row.access_token);
  }

  // Token is expired, expiring within 5 minutes, or has no recorded expiry: refresh required
  if (!row.refresh_token) {
    throw new OAuthRefreshFailed(
      `No refresh token available to refresh connection for user '${userId}' and provider '${normalizedProvider}'`
    );
  }

  const currentRefreshToken = decrypt(row.refresh_token);
  const oauthProvider = getProvider(normalizedProvider);

  const requestBody = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: currentRefreshToken,
    client_id: oauthProvider.clientId,
    client_secret: oauthProvider.clientSecret
  });

  let rawResponse: unknown;
  try {
    const tokenRes = await fetch(oauthProvider.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json'
      },
      body: requestBody.toString()
    });

    if (!tokenRes.ok) {
      const errorText = await tokenRes.text();
      console.error(`Token refresh HTTP ${tokenRes.status} from ${normalizedProvider}:`, errorText);
      throw new OAuthRefreshFailed(
        `Provider rejected token refresh request with status HTTP ${tokenRes.status}`
      );
    }

    rawResponse = await tokenRes.json();
  } catch (error) {
    if (error instanceof OAuthRefreshFailed) {
      throw error;
    }
    console.error(`Network error during token refresh for ${normalizedProvider}:`, error);
    throw new OAuthRefreshFailed(
      `Network error communicating with provider '${normalizedProvider}' during token refresh`
    );
  }

  let normalizedTokens;
  try {
    normalizedTokens = oauthProvider.parseTokenResponse(rawResponse);
  } catch (parseErr) {
    console.error(`Failed to parse refresh token response for ${normalizedProvider}:`, parseErr);
    throw new OAuthRefreshFailed(
      `Invalid refresh token response structure from provider '${normalizedProvider}'`
    );
  }

  const newEncryptedAccessToken = encrypt(normalizedTokens.accessToken);
  const newExpiresAt = normalizedTokens.expiresInSeconds
    ? new Date(Date.now() + normalizedTokens.expiresInSeconds * 1000)
    : null;

  // Token rotation with buffer window:
  // If provider returned a new refresh token that differs from current, rotate and store previous in prev_refresh_token
  if (normalizedTokens.refreshToken && normalizedTokens.refreshToken !== currentRefreshToken) {
    const newEncryptedRefreshToken = encrypt(normalizedTokens.refreshToken);
    const prevEncryptedRefreshToken = row.refresh_token; // current token becomes previous

    await query(
      `UPDATE oauth_connections
       SET access_token = $1,
           refresh_token = $2,
           prev_refresh_token = $3,
           expires_at = $4,
           updated_at = NOW()
       WHERE id = $5;`,
      [
        newEncryptedAccessToken,
        newEncryptedRefreshToken,
        prevEncryptedRefreshToken,
        newExpiresAt,
        row.id
      ]
    );
  } else {
    // Standard path (Google): no new refresh token returned; keep existing refresh_token and prev_refresh_token
    await query(
      `UPDATE oauth_connections
       SET access_token = $1,
           expires_at = $2,
           updated_at = NOW()
       WHERE id = $3;`,
      [newEncryptedAccessToken, newExpiresAt, row.id]
    );
  }

  return normalizedTokens.accessToken;
}

/**
 * Clears the prev_refresh_token column for a connection.
 * Called after PREV_TOKEN_BUFFER_SECONDS has elapsed following rotation.
 */
// TODO: Schedule clearPrevRefreshToken to run after PREV_TOKEN_BUFFER_SECONDS following each rotation
export async function clearPrevRefreshToken(userId: string, provider: string): Promise<void> {
  const normalizedProvider = provider.toLowerCase().trim();
  await query(
    `UPDATE oauth_connections
     SET prev_refresh_token = NULL,
         updated_at = NOW()
     WHERE user_id = $1 AND provider = $2;`,
    [userId, normalizedProvider]
  );
}

/**
 * POST /auth/:provider/refresh
 * Manual testing endpoint only: triggers getValidToken and returns { success: true }.
 * Never returns the plaintext access token over HTTP.
 */
export async function handleRefreshRoute(req: Request, res: Response, next: NextFunction): Promise<void> {
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

    await getValidToken(req.user.userId, providerName);

    res.status(200).json({
      success: true
    });
  } catch (error) {
    if (error instanceof OAuthConnectionNotFound) {
      res.status(404).json({ error: 'connection_not_found', message: error.message });
      return;
    }
    if (error instanceof OAuthRefreshFailed) {
      res.status(502).json({ error: 'refresh_failed', message: error.message });
      return;
    }
    next(error);
  }
}
