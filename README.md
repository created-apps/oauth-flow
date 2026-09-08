# oauth-flow

In-house backend service that owns the OAuth / credential layer currently handled by
Zapier. It connects users' third-party accounts, stores their tokens encrypted, keeps
them fresh, and hands valid tokens to server-side background jobs.

**Stack:** Node.js · Express 5 · TypeScript · Supabase (PostgreSQL)

- **Google** — per-user OAuth 2.0 (Authorization Code + PKCE), tokens stored per user.
- **Slack** — a single static workspace bot token (not OAuth); team-level.

See [`FEATURES.md`](FEATURES.md) for the capability list, [`implementation_plan.md`](implementation_plan.md)
for the build, and [`oauth_proposal.md`](oauth_proposal.md) for the rationale.

---

## ⚠️ Security — read before deploying

This service is **functionally complete and verified**, but it is **not production-ready
to expose publicly** in its current state:

- **`POST /users` is an unauthenticated development stub.** Anyone who can reach it can
  mint a valid 7-day JWT with no password, email verification, or API key. Every
  "requires JWT" endpoint is therefore only as strong as the network boundary in front
  of this service.
- **Hard deployment gate:** run this **only on an isolated private network / internal
  VPC**. Do **not** expose it to the public internet until `POST /users` is replaced
  with real authentication (enterprise IdP, Supabase Auth, or an authenticated gateway).

Also outstanding before any remote deployment:

- Set `app.set('trust proxy', …)` when running behind a reverse proxy (rate limiters
  key on client IP).
- Pin the Supabase CA certificate in `src/db/client.ts` (replace `rejectUnauthorized: false`).
- Create a dedicated PostgreSQL role scoped to the `users` and `oauth_connections` tables.
- In-memory PKCE/state store and rate-limit store are **single-instance only** — back
  them with Redis before running more than one instance.

The full threat model and the verified-controls list are tracked with the team.

---

## Local setup

1. `npm install`
2. Copy `.env.example` → `.env` and fill in the values:
   - `ENCRYPTION_KEY` — 64-hex chars: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
   - `JWT_SECRET` — any strong random string
   - `DATABASE_URL` — Supabase session-pooler connection string
   - `FRONTEND_ORIGIN` — allowed browser origin(s), comma-separated
   - `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `GOOGLE_REDIRECT_URI`
   - `SLACK_BOT_TOKEN` — optional, only when a Slack automation is built
3. Run the migration `migrations/001_create_oauth_connections.sql` in the Supabase SQL editor.
4. `npm run dev`

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/health` | — | Liveness check |
| `POST` | `/users` | — | **Dev stub** — issue a test JWT for an email |
| `GET` | `/auth/:provider/authorize` | JWT | Get the provider consent URL (`{ authUrl }`) |
| `GET` | `/auth/:provider/callback` | session | OAuth redirect target — exchanges code, stores encrypted tokens |
| `GET` | `/auth/connections` | JWT | List the user's connected providers (metadata only) |
| `POST` | `/auth/:provider/refresh` | JWT | Manual refresh trigger (returns `{ success: true }`, never a token) |
| `DELETE` | `/auth/:provider/disconnect` | JWT | Revoke upstream + delete the connection |

## For background jobs

```ts
import { getValidToken } from './auth/handlers/refresh';
import { getSlackBotToken } from './slack/token';

const googleToken = await getValidToken(userId, 'google'); // auto-refreshes near expiry
const slackToken = getSlackBotToken();                     // static workspace bot token
```

## Token security

- Access and refresh tokens are encrypted at rest with **AES-256-GCM** (fresh IV per
  value, authenticated). Plaintext tokens are never logged and never returned over HTTP.
- OAuth flow uses PKCE (S256) and a single-use, 10-minute `state` bound server-side to
  the user and provider.
