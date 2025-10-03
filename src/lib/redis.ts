import { env } from '@/env';

import { createClient } from 'redis';

class RedisClient {
  private static Instance: RedisClient;
  private redisClient: ReturnType<typeof createClient>;

  private constructor() {
    this.redisClient = createClient({ url: env.REDIS_URL });
    this.redisClient.on('error', console.error);
    this.redisClient.connect();
  }

  static get instance() {
    if (!RedisClient.Instance) RedisClient.Instance = new RedisClient();

    return RedisClient.Instance;
  }

  get isConnected() {
    return this.redisClient.isOpen;
  }

  /**
   * Set a key-value pair in Redis with an expiration time.
   *
   * @param key - The key to set.
   * @param value - The value to associate with the key.
   * @param lifetime - The expiration time in seconds.
   * @return True if the operation was successful, otherwise false.
   */
  add = async (key: string, value: string, lifetime: number) =>
    (await this.redisClient.set(key, value, { EX: lifetime })) === 'OK';

  /**
   * Delete a key from Redis.
   *
   * @param key - The key to delete.
   * @return True if the key was deleted, otherwise false.
   */
  delete = async (key: string) => (await this.redisClient.del(key)) !== 0;
}

declare global {
  var redis: RedisClient | undefined;
}

const redis = globalThis.redis ?? RedisClient.instance;
if (process.env.NODE_ENV !== 'production') globalThis.redis = redis;

export default redis;
