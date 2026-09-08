import { Router } from 'express';
import { validateUser } from '../middleware/validateUser';
import { callbackRateLimiter } from '../middleware/rateLimiter';
import { handleAuthorize } from './handlers/authorize';
import { handleCallback } from './handlers/callback';
import { handleRefreshRoute } from './handlers/refresh';
import { handleGetConnections, handleDisconnect } from './handlers/connections';

const router = Router();

// GET /auth/connections — returns list of active OAuth connections metadata (requires authenticated user JWT)
router.get('/connections', validateUser, handleGetConnections);

// GET /auth/:provider/authorize — returns { authUrl: string } (requires authenticated user JWT)
router.get('/:provider/authorize', validateUser, handleAuthorize);

// GET /auth/:provider/callback — handles OAuth redirect & code exchange (unauthenticated, session bound)
router.get('/:provider/callback', callbackRateLimiter, handleCallback);

// POST /auth/:provider/refresh — triggers token validation/refresh for manual testing (requires authenticated user JWT)
router.post('/:provider/refresh', validateUser, callbackRateLimiter, handleRefreshRoute);

// DELETE /auth/:provider/disconnect — revokes and deletes OAuth connection (requires authenticated user JWT)
router.delete('/:provider/disconnect', validateUser, handleDisconnect);

export default router;
