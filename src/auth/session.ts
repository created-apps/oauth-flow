import crypto from 'crypto';

export interface AuthSession {
  codeVerifier: string;
  userId: string;
  provider: string;
  expiresAt: number;
}

export interface CreatedAuthSession {
  state: string;
  codeChallenge: string;
  codeVerifier: string;
}

const SESSION_TTL_MS = 10 * 60 * 1000; // 10 minutes
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

const sessionStore = new Map<string, AuthSession>();

/**
 * Creates a new OAuth authentication session with CSRF state and PKCE challenge.
 * Stores the session in memory with a 10-minute TTL.
 */
export function createAuthSession(userId: string, provider: string): CreatedAuthSession {
  // 32 random bytes -> 64 hex chars
  const state = crypto.randomBytes(32).toString('hex');

  // PKCE: 32 random bytes -> 43 base64url characters (RFC 7636 compliant)
  const codeVerifier = crypto.randomBytes(32).toString('base64url');

  // code_challenge = base64url(SHA256(code_verifier))
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  const expiresAt = Date.now() + SESSION_TTL_MS;

  sessionStore.set(state, {
    codeVerifier,
    userId,
    provider,
    expiresAt
  });

  return {
    state,
    codeChallenge,
    codeVerifier
  };
}

/**
 * Retrieves and immediately consumes the OAuth session by state.
 * Throws if the state is not found, expired, or has already been consumed.
 */
export function getAuthSession(state: string): AuthSession {
  const session = sessionStore.get(state);

  if (!session) {
    throw new Error('Invalid or expired OAuth state session');
  }

  // Delete immediately to enforce single-use CSRF/PKCE state
  sessionStore.delete(state);

  if (Date.now() > session.expiresAt) {
    throw new Error('OAuth state session has expired');
  }

  return session;
}

/**
 * Removes expired sessions from the store.
 */
export function cleanupExpiredSessions(): number {
  const now = Date.now();
  let expiredCount = 0;

  for (const [state, session] of sessionStore.entries()) {
    if (now > session.expiresAt) {
      sessionStore.delete(state);
      expiredCount++;
    }
  }

  return expiredCount;
}

// Periodic cleanup every 5 minutes (unref so it doesn't hold open process shutdown)
const cleanupTimer = setInterval(cleanupExpiredSessions, CLEANUP_INTERVAL_MS);
if (cleanupTimer.unref) {
  cleanupTimer.unref();
}
