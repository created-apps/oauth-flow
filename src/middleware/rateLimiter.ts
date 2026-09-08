import rateLimit from 'express-rate-limit';

/**
 * Global rate limiter applied across all routes: max 100 requests per 15 minutes per IP.
 */
export const globalRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 100,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: {
    error: 'too_many_requests',
    message: 'Global rate limit exceeded. Max 100 requests per 15 minutes.'
  }
});

/**
 * Rate limiter for OAuth callback and refresh endpoints: max 20 requests per 15 minutes per IP.
 */
export const callbackRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 20,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: {
    error: 'too_many_requests',
    message: 'Too many requests. Please try again later.'
  }
});
