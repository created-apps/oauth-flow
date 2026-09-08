import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import { query } from '../db/client';
import { env } from '../config/env';

const router = Router();

// Rate limit: ~10 requests per hour per IP (I3) to prevent flooding the dev stub
const createUserLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: {
    error: 'too_many_requests',
    message: 'User creation rate limit exceeded. Max 10 requests per hour.'
  }
});

const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

const createUserSchema = z.object({
  email: z
    .string()
    .email('Valid email address is required')
    .regex(EMAIL_REGEX, 'Invalid email format')
    .refine((val) => val.toLowerCase().endsWith('@create-ed.in'), {
      message: 'Only @create-ed.in organization email addresses are permitted'
    })
});

interface UserRow {
  id: string;
  email: string;
  created_at: Date;
}

// POST /users — minimal dev stub for creating users / obtaining JWTs
// TODO: Replace with real auth; shorten expiry + add refresh when it lands
router.post('/', createUserLimiter, async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const parseResult = createUserSchema.safeParse(req.body);
    if (!parseResult.success) {
      res.status(400).json({
        error: 'invalid_request',
        message: parseResult.error.issues[0]?.message || 'Invalid request body'
      });
      return;
    }

    const { email } = parseResult.data;

    // Upsert on email conflict — return existing user row if already present
    const result = await query<UserRow>(
      `INSERT INTO users (email)
       VALUES ($1)
       ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
       RETURNING id, email, created_at;`,
      [email.toLowerCase().trim()]
    );

    const user = result.rows[0];

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      env.JWT_SECRET,
      {
        expiresIn: '7d',
        issuer: 'oauth-flow',
        audience: 'oauth-flow-api',
        algorithm: 'HS256'
      }
    );

    res.status(200).json({
      token,
      userId: user.id,
      email: user.email
    });
  } catch (error) {
    next(error);
  }
});

export default router;
