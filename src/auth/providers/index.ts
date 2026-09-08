import 'dotenv/config'; // Ensures .env is loaded when providers are accessed in standalone tasks/scripts
import { googleProvider } from './google';

export interface NormalizedTokenResponse {
  accessToken: string;
  refreshToken?: string;      // absent if provider didn't return one
  expiresInSeconds?: number;  // absent if provider didn't return one
  scopes: string[];
  tokenType: string;          // default 'Bearer'
  providerAccountId?: string;
}

export interface OAuthProvider {
  name: string;
  clientId: string;
  clientSecret: string;
  authorizationUrl: string;
  tokenUrl: string;
  scopes: string[];
  redirectUri: string;
  revokeUrl?: string;         // token revocation endpoint, if the provider has one (Google: yes)
  extraAuthorizeParams?: Record<string, string>;
  parseTokenResponse(raw: unknown): NormalizedTokenResponse;
}

/**
 * Shared helper to extract and validate required provider environment variables.
 */
export function requireEnv(key: string): string {
  const value = process.env[key];
  if (!value || value.trim().length === 0) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
  return value.trim();
}

const providers: Record<string, () => OAuthProvider> = {
  google: googleProvider
};

/**
 * Retrieves the OAuth provider configuration and handlers by name.
 * Throws if the provider is not supported or if required env vars are missing.
 */
export function getProvider(name: string): OAuthProvider {
  const normalizedName = name.toLowerCase().trim();
  const providerFn = providers[normalizedName];
  if (!providerFn) {
    throw new Error(`Provider '${name}' not found. Supported providers are: ${Object.keys(providers).join(', ')}`);
  }
  return providerFn();
}
