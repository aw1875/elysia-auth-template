import { createEnv } from '@t3-oss/env-core';
import { z } from 'zod';

export const env = createEnv({
  server: {
    DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
    REDIS_URL: z.string().min(1, 'REDIS_URL is required'),
    JWT_SECRET: z.string().min(1, 'JWT_SECRET is required'),
    AUTH_URL:
      process.env.NODE_ENV === 'development'
        ? z.string().optional()
        : z.string().min(1, 'AUTH_URL is required in production'),
    PORT: z.coerce.number().default(3000)
  },
  runtimeEnv: process.env,
  emptyStringAsUndefined: true
});
