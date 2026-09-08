import { Request, Response, NextFunction } from 'express';
import { getProvider } from '../providers';
import { createAuthSession } from '../session';

/**
 * GET /auth/:provider/authorize
 * Initiates the OAuth flow by creating a PKCE + CSRF session and generating
 * the provider authorization URL. Returns JSON { authUrl } so the client can redirect.
 */
export async function handleAuthorize(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const providerName = typeof req.params.provider === 'string' ? req.params.provider : undefined;
    if (!providerName) {
      res.status(400).json({ error: 'invalid_request', message: 'Provider parameter is required' });
      return;
    }

    let provider;
    try {
      provider = getProvider(providerName);
    } catch (error) {
      const message = error instanceof Error ? error.message : `Provider '${providerName}' not found`;
      res.status(400).json({ error: 'invalid_provider', message });
      return;
    }

    if (!req.user || !req.user.userId) {
      res.status(401).json({ error: 'unauthorized', message: 'User context is missing' });
      return;
    }

    const session = createAuthSession(req.user.userId, provider.name);

    const authUrl = new URL(provider.authorizationUrl);
    authUrl.searchParams.set('client_id', provider.clientId);
    authUrl.searchParams.set('redirect_uri', provider.redirectUri);
    authUrl.searchParams.set('response_type', 'code');

    if (provider.scopes.length > 0) {
      authUrl.searchParams.set('scope', provider.scopes.join(' '));
    }

    authUrl.searchParams.set('state', session.state);
    authUrl.searchParams.set('code_challenge', session.codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    // Provider-agnostic extra params (e.g. Google's access_type=offline & prompt=consent)
    if (provider.extraAuthorizeParams) {
      for (const [key, value] of Object.entries(provider.extraAuthorizeParams)) {
        authUrl.searchParams.set(key, value);
      }
    }

    res.status(200).json({
      authUrl: authUrl.toString()
    });
  } catch (error) {
    next(error);
  }
}
