import Bun from 'bun';

import Elysia, { t } from 'elysia';

import JWT from '@/lib/jwt';
import prisma from '@/lib/prisma';
import redis from '@/lib/redis';
import Time from '@/lib/utils';

import { env } from '@/env';

import { z } from 'zod';

export const AuthRoutes = new Elysia().group('/auth', (app) =>
  app
    .use(JWT)
    .decorate('redisClient', redis)
    .post(
      '/signup',
      async ({ body: { email, password }, status }) => {
        try {
          const hashedPassword = await Bun.password.hash(password, {
            algorithm: 'bcrypt',
            cost: 10
          });

          const user = await prisma.user.create({
            data: {
              email,
              password: hashedPassword
            },
            omit: {
              password: true
            }
          });

          return status('Created', { message: 'User created successfully', data: user });
        } catch (error) {
          if (error instanceof Error && !error.message.includes('Unique constraint failed')) {
            console.error('Error during user sign up:', error);
          }

          throw error;
        }
      },
      {
        body: t.Object({
          email: t.String({ format: 'email', errorMessage: 'Invalid email address' }),
          password: t.String({
            minLength: 6,
            errorMessage: 'Password must be at least 6 characters'
          })
        }),
        error({ code, status }) {
          if ((code as unknown) === 'P2002') {
            return status('Conflict', { message: 'Email already in use' });
          }

          switch (code) {
            case 'PARSE':
            case 'VALIDATION':
              return status('Bad Request', { message: 'Invalid request body' });

            default:
              return status('Internal Server Error', { message: 'Internal server error' });
          }
        },
        detail: {
          summary: 'User Sign Up',
          tags: ['Auth'],
          description: 'Create a new user account',
          responses: {
            201: {
              description: 'User created successfully',
              content: {
                'application/json': {
                  schema: t.Object({
                    message: t.String(),
                    data: t.Object({
                      id: t.String(),
                      email: t.String({ format: 'email' }),
                      createdAt: t.String(),
                      updatedAt: t.String()
                    })
                  }),
                  example: {
                    message: 'User created successfully',
                    data: {
                      id: 'cmg9sh2rn00005mjly6p9dzah',
                      email: 'test@mail.com',
                      createdAt: '2025-10-02T19:09:09.059Z',
                      updatedAt: '2025-10-02T19:09:09.059Z'
                    }
                  }
                }
              }
            },
            400: {
              description: 'Invalid request body',
              content: {
                'application/json': {
                  schema: t.Object({
                    message: t.String()
                  }),
                  example: {
                    message: 'Invalid request body'
                  }
                }
              }
            },
            409: {
              description: 'Email already in use',
              content: {
                'application/json': {
                  schema: t.Object({
                    message: t.String()
                  }),
                  example: {
                    message: 'Email already in use'
                  }
                }
              }
            }
          }
        }
      }
    )
    .post(
      '/signin',
      async ({
        body: { email, password },
        cookie: { accessToken, refreshToken },
        jwt,
        redisClient,
        status
      }) => {
        try {
          if (!redisClient || !redisClient.isConnected) {
            throw new Error('Redis client is not connected');
          }

          const user = await prisma.user.findUnique({
            where: { email },
            select: { id: true, email: true, password: true }
          });

          if (!user) {
            return status('Unauthorized', { message: 'Invalid email or password' });
          }

          const isPasswordValid = await Bun.password.verify(password, user.password, 'bcrypt');
          if (!isPasswordValid) {
            return status('Unauthorized', { message: 'Invalid email or password' });
          }

          const { accessToken: access, refreshToken: refresh } = await jwt.generateTokenPair(
            user.id
          );

          accessToken.set({
            domain: env.AUTH_URL || 'localhost',
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: Time.minutes(5),
            value: access
          });

          refreshToken.set({
            domain: env.AUTH_URL || 'localhost',
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: Time.days(30),
            value: refresh
          });

          if ((await redisClient.add(`refresh:${refresh}`, user.id, Time.days(30))) === false) {
            return status('Internal Server Error', { message: 'Could not store refresh token' });
          }

          return status('OK', { message: 'Signed in successfully' });
        } catch (error) {
          console.error('Error during user sign in:', error);
          throw error;
        }
      },
      {
        body: t.Object({
          email: t.String({ format: 'email', errorMessage: 'Invalid email address' }),
          password: t.String({ minLength: 6, errorMessage: 'Password must be a string' })
        }),
        cookie: t.Object({
          accessToken: t.Optional(t.String()),
          refreshToken: t.Optional(t.String())
        }),
        error({ code, status }) {
          switch (code) {
            case 'PARSE':
            case 'VALIDATION':
              return status('Bad Request', { message: 'Invalid request body' });

            default:
              return status('Internal Server Error', { message: 'Internal server error' });
          }
        },
        detail: {
          summary: 'User Sign In',
          tags: ['Auth'],
          description: 'Sign in to your user account',
          responses: {
            200: {
              description: 'Signed in successfully',
              content: {
                'application/json': {
                  schema: t.Object({
                    message: t.String()
                  }),
                  example: {
                    message: 'Signed in successfully'
                  }
                }
              }
            },
            400: {
              description: 'Invalid request body',
              content: {
                'application/json': {
                  schema: t.Object({
                    message: t.String()
                  }),
                  example: {
                    message: 'Invalid request body'
                  }
                }
              }
            },
            401: {
              description: 'Invalid email or password',
              content: {
                'application/json': {
                  schema: t.Object({
                    message: t.String()
                  }),
                  example: {
                    message: 'Invalid email or password'
                  }
                }
              }
            }
          }
        }
      }
    )
    .post(
      '/signout',
      async ({ cookie: { accessToken, refreshToken }, redisClient, status }) => {
        if (!redisClient.isConnected) {
          return status('Internal Server Error', { message: 'Redis client is not connected' });
        }

        if ((await redisClient.delete(`refresh:${refreshToken.value}`)) === false) {
          return status('Internal Server Error', { message: 'Could not delete refresh token' });
        }

        accessToken.remove();
        refreshToken.remove();

        return status('OK', { message: 'Signed out successfully' });
      },
      {
        cookie: z.object({
          accessToken: z.string().optional(),
          refreshToken: z.string().optional()
        }),
        detail: {
          summary: 'User Sign Out',
          tags: ['Auth'],
          description: 'Sign out from your user account',
          responses: {
            200: {
              description: 'Signed out successfully',
              content: {
                'application/json': {
                  schema: t.Object({
                    message: t.String()
                  }),
                  example: {
                    message: 'Signed out successfully'
                  }
                }
              }
            }
          }
        }
      }
    )
    .derive(async ({ jwt, cookie: { accessToken }, status }) => {
      if (!accessToken || !accessToken.value) {
        return status('Unauthorized', { message: 'Access token is missing' });
      }

      const decoded = await jwt.verify(accessToken.value as string);
      if (!decoded || !decoded.sub) {
        return status('Forbidden', { message: 'Invalid access token' });
      }

      const user = await prisma.user.findUnique({
        where: { id: decoded.sub },
        omit: {
          password: true
        }
      });

      if (!user) {
        return status('Forbidden', { message: 'Access token is not valid' });
      }

      return { user };
    })
    .post(
      '/refresh',
      async ({ cookie: { accessToken, refreshToken }, jwt, redisClient, status }) => {
        if (!redisClient.isConnected) {
          return status('Internal Server Error', { message: 'Redis client is not connected' });
        }

        if (!refreshToken || !refreshToken.value) {
          return status('Unauthorized', { message: 'Refresh token is missing' });
        }

        const decoded = await jwt.verify(refreshToken.value);
        if (!decoded || !decoded.sub) {
          return status('Forbidden', { message: 'Invalid refresh token' });
        }

        const user = await prisma.user.findUnique({
          where: { id: decoded.sub },
          omit: {
            password: true
          }
        });

        if (!user) {
          return status('Forbidden', { message: 'Refresh token is not valid' });
        }

        if (!(await redisClient.delete(`refresh:${refreshToken.value}`))) {
          return status('Forbidden', { message: 'Refresh token is not valid' });
        }

        const { accessToken: access, refreshToken: refresh } = await jwt.generateTokenPair(user.id);

        accessToken.set({
          domain: env.AUTH_URL || 'localhost',
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax',
          maxAge: Time.minutes(5),
          value: access
        });

        refreshToken.set({
          domain: env.AUTH_URL || 'localhost',
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax',
          maxAge: Time.days(30),
          value: refresh
        });

        if ((await redisClient.add(`refresh:${refresh}`, user.id, Time.days(30))) === false) {
          return status('Internal Server Error', { message: 'Could not store refresh token' });
        }

        return status('OK', { message: 'Token refreshed successfully' });
      },
      {
        cookie: z.object({
          accessToken: z.string().optional(),
          refreshToken: z.string()
        }),
        error({ code, status }) {
          switch (code) {
            case 'PARSE':
            case 'VALIDATION':
              return status('Bad Request', { message: 'Invalid request cookies' });

            default:
              return status('Internal Server Error', { message: 'Internal server error' });
          }
        },
        detail: {
          summary: 'Refresh Token',
          tags: ['Auth'],
          description: 'Refresh access and refresh tokens',
          responses: {
            200: {
              description: 'Token refreshed successfully',
              content: {
                'application/json': {
                  schema: t.Object({
                    message: t.String()
                  }),
                  example: {
                    message: 'Token refreshed successfully'
                  }
                }
              }
            },
            400: {
              description: 'Invalid request cookies',
              content: {
                'application/json': {
                  schema: t.Object({
                    message: t.String()
                  }),
                  example: {
                    message: 'Invalid request cookies'
                  }
                }
              }
            },
            401: {
              description: 'Refresh token is missing',
              content: {
                'application/json': {
                  schema: t.Object({
                    message: t.String()
                  }),
                  example: {
                    message: 'Refresh token is missing'
                  }
                }
              }
            },
            403: {
              description: 'Invalid or expired refresh token',
              content: {
                'application/json': {
                  schema: t.Object({
                    message: t.String()
                  }),
                  example: {
                    message: 'Invalid refresh token'
                  }
                }
              }
            }
          }
        }
      }
    )
    .get('/session', async ({ user }) => user, {
      detail: {
        summary: 'Get Current User',
        tags: ['Auth'],
        description: 'Retrieve the currently authenticated user',
        responses: {
          200: {
            description: 'Current user retrieved successfully',
            content: {
              'application/json': {
                schema: t.Object({
                  id: t.String(),
                  email: t.String({ format: 'email' }),
                  createdAt: t.String(),
                  updatedAt: t.String()
                }),
                example: {
                  id: 'cmg9sh2rn00005mjly6p9dzah',
                  email: 'test@mail.com',
                  createdAt: '2025-10-02T19:09:09.059Z',
                  updatedAt: '2025-10-02T19:09:09.059Z'
                }
              }
            }
          }
        }
      }
    })
);
