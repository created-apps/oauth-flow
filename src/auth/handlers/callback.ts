import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { getProvider } from '../providers';
import { getAuthSession } from '../session';
import { encrypt } from '../../crypto/tokens';
import { query } from '../../db/client';
import { env } from '../../config/env';

const callbackQuerySchema = z.object({
  code: z.string().optional(),
  state: z.string().optional(),
  error: z.string().optional(),
  error_description: z.string().optional()
});

/**
 * Validates that a redirect URL belongs to an allowlisted FRONTEND_ORIGIN.
 */
function isValidRedirectUrl(urlStr: string | undefined): boolean {
  if (!urlStr) return false;
  try {
    const url = new URL(urlStr);
    return env.frontendOrigins.includes(url.origin);
  } catch {
    return false;
  }
}

/**
 * Sanitizes the raw OAuth token response according to I5:
 * Keeps an allowlist of safe metadata keys only (scope, token_type, expires_in)
 * and strictly omits all token-bearing fields (access_token, refresh_token, id_token).
 */
function sanitizeRawResponse(raw: unknown): Record<string, unknown> {
  if (!raw || typeof raw !== 'object') {
    return {};
  }
  const allowedKeys = ['scope', 'token_type', 'expires_in'];
  const sanitized: Record<string, unknown> = {};
  const rawObj = raw as Record<string, unknown>;

  for (const key of allowedKeys) {
    if (key in rawObj && rawObj[key] !== undefined) {
      sanitized[key] = rawObj[key];
    }
  }

  return sanitized;
}

/**
 * GET /auth/:provider/callback
 * Handles the OAuth provider callback, verifies CSRF state & PKCE codeVerifier,
 * exchanges authorization code for tokens, encrypts tokens with AES-256-GCM,
 * and upserts into oauth_connections table.
 */
export async function handleCallback(req: Request, res: Response, next: NextFunction): Promise<void> {
  const providerName = typeof req.params.provider === 'string' ? req.params.provider : undefined;

  const shouldUseRedirect =
    isValidRedirectUrl(env.OAUTH_SUCCESS_REDIRECT) && isValidRedirectUrl(env.OAUTH_ERROR_REDIRECT);

  const sendError = (status: number, errorCode: string, message?: string) => {
    if (shouldUseRedirect && env.OAUTH_ERROR_REDIRECT) {
      const errorUrl = new URL(env.OAUTH_ERROR_REDIRECT);
      errorUrl.searchParams.set('error', errorCode);
      if (providerName) {
        errorUrl.searchParams.set('provider', providerName);
      }
      res.redirect(302, errorUrl.toString());
      return;
    }
    res.status(status).json({ error: errorCode, ...(message ? { message } : {}) });
  };

  try {
    const queryParse = callbackQuerySchema.safeParse(req.query);
    if (!queryParse.success) {
      sendError(400, 'invalid_request', 'Invalid callback query parameters');
      return;
    }

    const { code, state, error: providerError, error_description } = queryParse.data;

    // Handle provider-reported errors (e.g. user cancelled consent)
    if (providerError) {
      const safeErrorCode = providerError.slice(0, 50);
      const safeDescription = (error_description || 'Provider reported an authorization error').slice(0, 200);
      sendError(400, safeErrorCode, safeDescription);
      return;
    }

    if (!code || !state) {
      sendError(400, 'invalid_request', 'Missing required query parameters: code and state');
      return;
    }

    if (!providerName) {
      sendError(400, 'invalid_provider', 'Provider parameter is required');
      return;
    }

    let provider;
    try {
      provider = getProvider(providerName);
    } catch (err) {
      sendError(400, 'invalid_provider', err instanceof Error ? err.message : 'Provider not found');
      return;
    }

    // Retrieve and consume the session (single-use CSRF & PKCE verifier)
    let session;
    try {
      session = getAuthSession(state);
    } catch {
      sendError(400, 'invalid_state', 'Invalid or expired state parameter');
      return;
    }

    // Cross-check provider: ensure state was not minted for a different provider
    if (session.provider !== provider.name) {
      sendError(400, 'invalid_state', 'State session does not match provider');
      return;
    }

    // Perform token exchange with PKCE code_verifier
    const tokenRequestBody = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: provider.redirectUri,
      client_id: provider.clientId,
      client_secret: provider.clientSecret,
      code_verifier: session.codeVerifier
    });

    let rawTokenResponse: unknown;
    try {
      const response = await fetch(provider.tokenUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json'
        },
        body: tokenRequestBody.toString()
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error(`Token exchange HTTP ${response.status} from ${provider.name}:`, errorText);
        sendError(502, 'token_exchange_failed', 'Failed to exchange authorization code for tokens');
        return;
      }

      rawTokenResponse = await response.json();
    } catch (fetchErr) {
      console.error(`Network error during token exchange with ${provider.name}:`, fetchErr);
      sendError(502, 'token_exchange_failed', 'Network error during token exchange');
      return;
    }

    // Parse and normalize provider token response
    let normalizedTokens;
    try {
      normalizedTokens = provider.parseTokenResponse(rawTokenResponse);
    } catch (parseErr) {
      console.error(`Failed to parse token response for ${provider.name}:`, parseErr);
      sendError(502, 'token_exchange_failed', 'Invalid token response structure from provider');
      return;
    }

    // Encrypt tokens at rest (AES-256-GCM)
    const encryptedAccessToken = encrypt(normalizedTokens.accessToken);
    const encryptedRefreshToken = normalizedTokens.refreshToken
      ? encrypt(normalizedTokens.refreshToken)
      : null;

    const expiresAt = normalizedTokens.expiresInSeconds
      ? new Date(Date.now() + normalizedTokens.expiresInSeconds * 1000)
      : null;

    const sanitizedRaw = sanitizeRawResponse(rawTokenResponse);

    // Upsert into oauth_connections
    await query(
      `INSERT INTO oauth_connections (
        user_id,
        provider,
        provider_account_id,
        access_token,
        refresh_token,
        token_type,
        scopes,
        expires_at,
        raw_response,
        updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
      ON CONFLICT (user_id, provider) DO UPDATE SET
        provider_account_id = EXCLUDED.provider_account_id,
        access_token = EXCLUDED.access_token,
        refresh_token = COALESCE(EXCLUDED.refresh_token, oauth_connections.refresh_token),
        token_type = EXCLUDED.token_type,
        scopes = EXCLUDED.scopes,
        expires_at = EXCLUDED.expires_at,
        raw_response = EXCLUDED.raw_response,
        updated_at = NOW();`,
      [
        session.userId,
        provider.name,
        normalizedTokens.providerAccountId || null,
        encryptedAccessToken,
        encryptedRefreshToken,
        normalizedTokens.tokenType || 'Bearer',
        normalizedTokens.scopes,
        expiresAt,
        JSON.stringify(sanitizedRaw)
      ]
    );

    // Success response: Redirect or JSON
    if (shouldUseRedirect && env.OAUTH_SUCCESS_REDIRECT) {
      const successUrl = new URL(env.OAUTH_SUCCESS_REDIRECT);
      successUrl.searchParams.set('connected', provider.name);
      res.redirect(302, successUrl.toString());
      return;
    }

    res.status(200).json({
      success: true,
      provider: provider.name,
      userId: session.userId
    });
  } catch (error) {
    next(error);
  }
}
