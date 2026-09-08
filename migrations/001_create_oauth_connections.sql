-- migrations/001_create_oauth_connections.sql

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE oauth_connections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,                        -- OAuth provider, e.g. 'google' (Slack is not stored here)
  provider_account_id TEXT,                      -- the user's ID on the provider side
  access_token TEXT NOT NULL,                    -- AES-256-GCM encrypted
  refresh_token TEXT,                            -- AES-256-GCM encrypted (nullable if provider doesn't issue one)
  prev_refresh_token TEXT,                       -- AES-256-GCM encrypted; holds the previous refresh token during rotation buffer window
  token_type TEXT NOT NULL DEFAULT 'Bearer',
  scopes TEXT[],                                 -- array of granted scopes
  expires_at TIMESTAMPTZ,                        -- when the access_token expires
  raw_response JSONB,                            -- full token response, sanitized (no plaintext tokens)
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(user_id, provider)                      -- one active connection per provider per user
);

CREATE INDEX idx_oauth_connections_user_id ON oauth_connections(user_id);
CREATE INDEX idx_oauth_connections_provider ON oauth_connections(provider);

-- ============================================================
-- Row Level Security (RLS) — STAGED / DORMANT
-- Note: auth.uid() only resolves for Supabase Auth JWTs.
-- This service connects with the service role and uses its own
-- custom JWTs (Slice 4), bypassing RLS. Cross-user isolation is
-- actively enforced at the application layer by filtering on
-- req.user.userId. These policies are staged for future migration
-- to Supabase Auth.
-- ============================================================

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_connections ENABLE ROW LEVEL SECURITY;

-- Users can only read/update their own row
CREATE POLICY "users_own_row" ON users
  FOR ALL
  USING (id = auth.uid());

-- Users can only read/update their own oauth_connections
CREATE POLICY "oauth_connections_own_rows" ON oauth_connections
  FOR ALL
  USING (user_id = auth.uid());
