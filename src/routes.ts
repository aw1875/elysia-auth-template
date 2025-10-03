import Elysia from 'elysia';

import openapi from '@elysiajs/openapi';

import { AuthRoutes } from '@/routes/auth';

import { z } from 'zod';

const routes = new Elysia({ prefix: '/api/v1' })
  .use(
    openapi({
      mapJsonSchema: { zod: z.toJSONSchema },
      path: '/docs',
      provider: 'scalar'
    })
  )
  .use(AuthRoutes)
  .get('/health', () => 'OK', {
    detail: {
      summary: 'Health check',
      tags: ['Health'],
      description: 'Check if the server is running',
      responses: {
        200: {
          description: 'OK',
          content: {
            'text/plain': {
              schema: { type: 'string' }
            }
          }
        }
      }
    }
  });

export default routes;
