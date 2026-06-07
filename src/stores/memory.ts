import type { SessionStore } from "../types";

/**
 * 메모리 세션 저장소 (개발 / 테스트 전용)
 * 프로세스 재시작 시 세션 소멸, 단일 인스턴스에서만 유효
 */
export class MemoryStore implements SessionStore {
  private store = new Map<string, { value: string; expiresAt: number }>();

  async get(key: string): Promise<string | null> {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return null;
    }
    return entry.value;
  }

  async set(key: string, value: string, ttlSeconds: number): Promise<void> {
    this.store.set(key, {
      value,
      expiresAt: Date.now() + ttlSeconds * 1000,
    });
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }
}
