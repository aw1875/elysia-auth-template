import Elysia from 'elysia';

import jwt from '@elysiajs/jwt';

import { env } from '@/env';

const JWT = new Elysia().use(
  jwt({
    name: 'jwt',
    secret: env.JWT_SECRET
  }).decorate('jwt', {
    generateTokenPair: async (userId: string) => {
      const accessToken = await JWT.decorator.jwt.sign({
        sub: userId,
        exp: '5m'
      });

      const refreshToken = await JWT.decorator.jwt.sign({
        sub: userId,
        exp: '30d'
      });

      return { accessToken, refreshToken };
    }
  })
);

export default JWT;
