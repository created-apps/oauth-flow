import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config();

const envSchema = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
  ENCRYPTION_KEY: z
    .string()
    .regex(/^[0-9a-fA-F]{64}$/, 'ENCRYPTION_KEY must be a 64-character hex string (32 bytes)'),
  JWT_SECRET: z.string().min(1, 'JWT_SECRET is required'),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  FRONTEND_ORIGIN: z.string().min(1, 'FRONTEND_ORIGIN is required'),
  SLACK_BOT_TOKEN: z.string().optional(),
  OAUTH_SUCCESS_REDIRECT: z.string().optional(),
  OAUTH_ERROR_REDIRECT: z.string().optional()
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  const errorDetails = parsed.error.issues
    .map((issue) => `  - ${issue.path.join('.') || 'env'}: ${issue.message}`)
    .join('\n');
  throw new Error(`Environment validation failed:\n${errorDetails}`);
}

const frontendOrigins = parsed.data.FRONTEND_ORIGIN.split(',')
  .map((origin) => origin.trim())
  .filter((origin) => origin.length > 0);

if (frontendOrigins.length === 0) {
  throw new Error('FRONTEND_ORIGIN must specify at least one valid origin');
}

if (parsed.data.NODE_ENV === 'production') {
  const hasLocalhost = frontendOrigins.some(
    (origin) => origin.toLowerCase().includes('localhost') || origin.includes('127.0.0.1')
  );
  if (hasLocalhost) {
    throw new Error(
      'Production configuration error: FRONTEND_ORIGIN cannot contain localhost in production mode.'
    );
  }

  const redirectUris = [process.env.GOOGLE_REDIRECT_URI];
  for (const uri of redirectUris) {
    if (uri && uri.startsWith('http://')) {
      throw new Error(
        `Production configuration error: Redirect URI "${uri}" must use HTTPS in production mode.`
      );
    }
  }
}

export const env = {
  ...parsed.data,
  frontendOrigins
};
