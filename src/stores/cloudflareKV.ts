import type { SessionStore } from "../types";

/**
 * Cloudflare KV 세션 저장소
 *
 * 사용법:
 *   import { CloudflareKVStore } from './stores/cloudflareKV.js'
 *   const store = new CloudflareKVStore(env.KV_SESSIONS)
 */
export class CloudflareKVStore implements SessionStore {
  constructor(private kv: KVNamespace) {}

  async get(key: string): Promise<string | null> {
    return this.kv.get(key);
  }

  async set(key: string, value: string, ttlSeconds: number): Promise<void> {
    await this.kv.put(key, value, { expirationTtl: ttlSeconds });
  }

  async delete(key: string): Promise<void> {
    await this.kv.delete(key);
  }
}
