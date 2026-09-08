import path from 'path';
import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { env } from './config/env';
import { testDbConnection } from './db/client';
import { globalRateLimiter } from './middleware/rateLimiter';
import usersRouter from './users/routes';
import authRouter from './auth/routes';

const app = express();

// Security headers
app.use(helmet());

// CORS configuration
app.use(
  cors({
    origin: env.frontendOrigins
  })
);

// Health check route (unmetered — excluded from rate limiting for load balancers & uptime monitors)
app.get('/health', (_req: Request, res: Response) => {
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString()
  });
});

// Serve bundled static frontend (unmetered — static assets bypass global API rate limiter)
app.use(express.static(path.join(__dirname, '..', 'public')));

// Global light rate limiter (~100 req / 15 min / IP for API routes)
app.use(globalRateLimiter);

// Body parser with payload size limit
app.use(express.json({ limit: '10kb' }));

// Application routers
app.use('/users', usersRouter);
app.use('/auth', authRouter);

// Global Express error handler (Slice 10)
// Hides error internals and stack traces in production; logs full error server-side
app.use((err: unknown, _req: Request, res: Response, next: NextFunction): void => {
  console.error('Unhandled server error:', err);

  if (res.headersSent) {
    next(err);
    return;
  }

  if (env.NODE_ENV === 'production') {
    res.status(500).json({
      error: 'internal_server_error'
    });
  } else {
    const message = err instanceof Error ? err.message : 'Unknown server error';
    res.status(500).json({
      error: 'internal_server_error',
      message
    });
  }
});

async function startServer() {
  try {
    await testDbConnection();
    app.listen(env.PORT, () => {
      console.log(`Server running on port ${env.PORT} in ${env.NODE_ENV} mode`);
    });
  } catch (error) {
    console.error('Failed to start server due to database connection error:', error);
    process.exit(1);
  }
}

startServer();

export default app;
