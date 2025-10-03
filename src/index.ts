import Elysia from 'elysia';

import cors from '@elysiajs/cors';

import routes from '@/routes';

import { env } from '@/env';

const app = new Elysia()
  .use(
    cors({
      origin: 'http://localhost:3000',
      credentials: true
    })
  )
  .use(routes)
  .listen({ port: env.PORT || 3000 });

console.log(`🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`);
