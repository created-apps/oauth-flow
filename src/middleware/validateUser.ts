import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { env } from '../config/env';
import { AuthUser } from '../types/express';

interface TokenPayload {
  userId: string;
  email: string;
}

export function validateUser(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'unauthorized', message: 'Missing or malformed Authorization header' });
    return;
  }

  const token = authHeader.slice(7).trim();
  if (!token) {
    res.status(401).json({ error: 'unauthorized', message: 'Token not provided' });
    return;
  }

  try {
    const decoded = jwt.verify(token, env.JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: 'oauth-flow',
      audience: 'oauth-flow-api'
    }) as TokenPayload;

    if (!decoded.userId || !decoded.email) {
      res.status(401).json({ error: 'unauthorized', message: 'Invalid token payload' });
      return;
    }

    req.user = {
      userId: decoded.userId,
      email: decoded.email
    };

    next();
  } catch (_error) {
    res.status(401).json({ error: 'unauthorized', message: 'Invalid or expired token' });
  }
}
