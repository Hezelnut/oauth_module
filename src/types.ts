// ─── 모듈 설정 ────────────────────────────────────────────────────────────────

export interface SupabaseAuthConfig {
  supabaseUrl: string;
  anonKey: string;
  encryptionKey: string;          // 64자 hex (AES-GCM 256bit)
  allowedRedirectOrigins: string[]; // Open Redirect 화이트리스트
  store: SessionStore;            // 저장소 구현체 주입
  session?: {
    ttlSeconds?: number;          // 기본값: 900 (15분)
    maxTtlSeconds?: number;       // 절대 상한, 기본값: 86400 (24시간)
  };
}

// ─── 저장소 인터페이스 ────────────────────────────────────────────────────────

/** 세션 저장소 추상 인터페이스 — KV / Redis / Memory 모두 구현 가능 */
export interface SessionStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlSeconds: number): Promise<void>;
  delete(key: string): Promise<void>;
}

// ─── OAuth / 세션 데이터 ──────────────────────────────────────────────────────

export interface OAuthTokens {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  token_type: string;
}

export interface AuthUser {
  id: string;
  email: string;
  role: string;
  aud: string;
}

/** KV에 암호화되어 저장되는 세션 페이로드 */
export interface SessionPayload {
  user: AuthUser;
  accessToken: string;
  refreshToken?: string;
  /** 이 시각 이후 refresh token으로 갱신 시도 */
  expiresAt: number;
  createdAt: number;
}

/** PKCE state — 로그인 흐름 중 임시 저장 */
export interface PKCEState {
  codeVerifier: string;
  postLoginRedirect: string;
  createdAt: number;
}

// ─── 함수 반환 타입 ───────────────────────────────────────────────────────────

export interface CallbackResult {
  user: AuthUser;
  sessionId: string;
  /** Set-Cookie 헤더에 사용할 쿠키 문자열 */
  cookie: string;
}

export interface SessionResult {
  user: AuthUser;
  /** 세션 갱신이 발생한 경우 새 쿠키 (Set-Cookie 재발급 필요) */
  renewedCookie?: string;
}
