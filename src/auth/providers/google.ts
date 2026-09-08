import jwt from 'jsonwebtoken';
import { OAuthProvider, NormalizedTokenResponse, requireEnv } from './index';

interface GoogleTokenRaw {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  token_type?: string;
  id_token?: string;
  error?: string;
  error_description?: string;
}

export function googleProvider(): OAuthProvider {
  const clientId = requireEnv('GOOGLE_CLIENT_ID');
  const clientSecret = requireEnv('GOOGLE_CLIENT_SECRET');
  const redirectUri = requireEnv('GOOGLE_REDIRECT_URI');

  return {
    name: 'google',
    clientId,
    clientSecret,
    authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    revokeUrl: 'https://oauth2.googleapis.com/revoke',
    scopes: ['openid', 'email', 'profile'],
    redirectUri,
    extraAuthorizeParams: {
      access_type: 'offline',
      prompt: 'consent'
    },
    parseTokenResponse(raw: unknown): NormalizedTokenResponse {
      if (!raw || typeof raw !== 'object') {
        throw new Error('Invalid token response from Google: response is not an object');
      }

      const data = raw as GoogleTokenRaw;

      if (data.error) {
        throw new Error(`Google token error: ${data.error_description || data.error}`);
      }

      if (!data.access_token) {
        throw new Error('Invalid token response from Google: missing access_token');
      }

      const scopes = data.scope ? data.scope.split(/\s+/).filter(Boolean) : [];

      // Extract stable Google user account ID ('sub') from id_token JWT if present
      let providerAccountId: string | undefined;
      if (data.id_token) {
        try {
          const decoded = jwt.decode(data.id_token) as { sub?: string } | null;
          if (decoded && typeof decoded.sub === 'string') {
            providerAccountId = decoded.sub;
          }
        } catch {
          // Ignore decode errors; providerAccountId remains undefined
        }
      }

      return {
        accessToken: data.access_token,
        refreshToken: data.refresh_token || undefined,
        expiresInSeconds: typeof data.expires_in === 'number' ? data.expires_in : undefined,
        scopes,
        tokenType: data.token_type || 'Bearer',
        providerAccountId
      };
    }
  };
}
