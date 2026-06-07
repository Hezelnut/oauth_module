/**
 * SupabaseAuth — 프레임워크 무관 순수 인증 모듈
 *
 * 책임:
 *  - OAuth2 + PKCE 로그인 URL 생성
 *  - Authorization Code → 세션 교환
 *  - 세션 검증 (15분 TTL + refresh token 자동 갱신)
 *  - 로그아웃 (저장소 세션 + Supabase 서버 토큰 동시 무효화)
 *
 * 프레임워크 의존성 없음 — 반환값을 그대로 Express / Hono / CF Worker에 적용
 */

import {
  SupabaseAuthConfig,
  OAuthTokens,
  AuthUser,
  PKCEState,
  SessionPayload,
  CallbackResult,
  SessionResult,
} from "../types";
import { generateCodeVerifier, generateCodeChallenge, generateState, generateSessionId } from "./pkce";
import { encrypt, decrypt } from "./crypto";

const ALLOWED_PROVIDERS = ["google", "github", "kakao"] as const;
type OAuthProvider = (typeof ALLOWED_PROVIDERS)[number];

const PKCE_TTL = 600;           // PKCE state 유효기간 10분 (고정)
const DEFAULT_TTL = 900;        // 세션 기본 TTL 15분
const MAX_TTL = 86400;          // 세션 절대 상한 24시간

export class SupabaseAuth {
  private url: string;
  private key: string;
  private encKey: string;
  private allowedOrigins: string[];
  private store;
  private ttl: number;
  private maxTtl: number;

  constructor(config: SupabaseAuthConfig) {
    this.url = config.supabaseUrl.replace(/\/$/, "");
    this.key = config.anonKey;
    this.encKey = config.encryptionKey;
    this.allowedOrigins = config.allowedRedirectOrigins;
    this.store = config.store;
    this.ttl = config.session?.ttlSeconds ?? DEFAULT_TTL;
    this.maxTtl = config.session?.maxTtlSeconds ?? MAX_TTL;
  }

  // ─── 1. 로그인 URL 생성 ───────────────────────────────────────────────────
  //
  // 반환된 url로 브라우저를 redirect 시키면 됩니다.
  // res.redirect(url)  /  return Response.redirect(url)  등 프레임워크에 맞게 사용

  async getLoginUrl(
    rawProvider: string,
    callbackUrl: string,         // OAuth callback을 받을 서버 URL (화이트리스트 검증)
    postLoginRedirect = "/"      // 로그인 완료 후 최종 이동 경로
  ): Promise<string> {
    const provider = this.validateProvider(rawProvider);
    this.validateOrigin(callbackUrl);

    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await generateCodeChallenge(codeVerifier);
    const state = generateState();

    // PKCE state를 저장소에 임시 보관 (10분)
    const pkceState: PKCEState = {
      codeVerifier,
      postLoginRedirect,
      createdAt: Date.now(),
    };
    await this.store.set(`pkce:${state}`, JSON.stringify(pkceState), PKCE_TTL);

    const params = new URLSearchParams({
      provider,
      redirect_to: callbackUrl,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      state,
    });

    return `${this.url}/auth/v1/authorize?${params}`;
  }

  // ─── 2. OAuth Callback 처리 ───────────────────────────────────────────────
  //
  // 반환값의 cookie를 Set-Cookie 헤더에 설정하고
  // postLoginRedirect로 브라우저를 이동시키면 됩니다.
  //
  // Express 예시:
  //   const result = await auth.handleCallback(code, state)
  //   res.setHeader('Set-Cookie', result.cookie)
  //   res.redirect(result.postLoginRedirect)

  async handleCallback(code: string, state: string): Promise<CallbackResult & { postLoginRedirect: string }> {
    if (!code || !state) throw new AuthError("missing_params");

    // PKCE state 검증 및 소비 (one-time use)
    const pkceState = await this.consumePKCEState(state);

    // code + code_verifier → token 교환
    const tokens = await this.exchangeCode(code, pkceState.codeVerifier);

    // 유저 정보 조회
    const user = await this.fetchUser(tokens.access_token);

    // 세션 생성
    const sessionId = generateSessionId();
    await this.saveSession(sessionId, user, tokens);

    return {
      user,
      sessionId,
      cookie: this.buildCookie(sessionId, this.ttl),
      postLoginRedirect: pkceState.postLoginRedirect,
    };
  }

  // ─── 3. 세션 검증 ─────────────────────────────────────────────────────────
  //
  // 매 요청마다 호출하여 유저를 확인합니다.
  // 15분 TTL 만료 시 refresh token으로 자동 갱신하고 renewedCookie를 반환합니다.
  // renewedCookie가 있으면 반드시 Set-Cookie 헤더를 재발급해야 합니다.
  //
  // Express 예시:
  //   const result = await auth.verifySession(sessionId)
  //   if (!result) return res.status(401).json({ error: 'Unauthorized' })
  //   if (result.renewedCookie) res.setHeader('Set-Cookie', result.renewedCookie)
  //   req.user = result.user

  async verifySession(sessionId: string): Promise<SessionResult | null> {
    if (!isValidSessionId(sessionId)) return null;

    const payload = await this.loadSession(sessionId);
    if (!payload) return null;

    const now = Date.now();
    const isExpired = now >= payload.expiresAt;

    // 만료 전 — 그대로 반환
    if (!isExpired) {
      return { user: payload.user };
    }

    // 만료됨 + refresh token 없음 — 세션 삭제
    if (!payload.refreshToken) {
      await this.deleteSession(sessionId);
      return null;
    }

    // 만료됨 + refresh token 있음 — 갱신 시도
    // 이 시점에 Supabase가 refresh token을 검증하므로
    // 비밀번호 변경 등으로 Supabase 세션이 무효화된 경우 여기서 감지됩니다.
    try {
      const newTokens = await this.refreshTokens(payload.refreshToken);

      // 갱신 성공 → 기존 세션 삭제 후 새 세션 ID 발급 (Session Fixation 방어)
      await this.deleteSession(sessionId);
      const newSessionId = generateSessionId();
      await this.saveSession(newSessionId, payload.user, newTokens);

      return {
        user: payload.user,
        renewedCookie: this.buildCookie(newSessionId, this.ttl),
      };
    } catch {
      // refresh 실패 = Supabase 세션 무효 (비번 변경, 계정 정지 등)
      // → 로컬 세션도 즉시 삭제
      await this.deleteSession(sessionId);
      return null;
    }
  }

  // ─── 4. 로그아웃 ──────────────────────────────────────────────────────────
  //
  // 반환된 clearCookie를 Set-Cookie 헤더에 설정하면 됩니다.
  //
  // Express 예시:
  //   const { clearCookie } = await auth.logout(sessionId)
  //   res.setHeader('Set-Cookie', clearCookie)

  async logout(sessionId: string): Promise<{ clearCookie: string }> {
    if (isValidSessionId(sessionId)) {
      // access_token을 꺼내 Supabase 서버 토큰도 무효화
      try {
        const payload = await this.loadSession(sessionId);
        if (payload?.accessToken) {
          await this.supabaseSignOut(payload.accessToken);
        }
      } catch {
        // Supabase 무효화 실패해도 로컬 세션은 반드시 삭제
      }
      await this.deleteSession(sessionId);
    }

    return { clearCookie: this.buildClearCookie() };
  }

  // ─── Private: Supabase API 호출 ───────────────────────────────────────────

  private async exchangeCode(code: string, codeVerifier: string): Promise<OAuthTokens> {
    const res = await fetch(`${this.url}/auth/v1/token?grant_type=pkce`, {
      method: "POST",
      headers: { "Content-Type": "application/json", apikey: this.key },
      body: JSON.stringify({ auth_code: code, code_verifier: codeVerifier }),
    });
    if (!res.ok) {
      const err = await res.json<{ error_description?: string }>();
      console.error("[SupabaseAuth] Token exchange failed:", err.error_description);
      throw new AuthError("token_exchange_failed");
    }
    const tokens = await res.json<OAuthTokens>();
    tokens.expires_in = Math.min(tokens.expires_in ?? 3600, this.maxTtl);
    return tokens;
  }

  private async fetchUser(accessToken: string): Promise<AuthUser> {
    const res = await fetch(`${this.url}/auth/v1/user`, {
      headers: { Authorization: `Bearer ${accessToken}`, apikey: this.key },
    });
    if (!res.ok) throw new AuthError("user_fetch_failed");
    return res.json<AuthUser>();
  }

  private async refreshTokens(refreshToken: string): Promise<OAuthTokens> {
    const res = await fetch(`${this.url}/auth/v1/token?grant_type=refresh_token`, {
      method: "POST",
      headers: { "Content-Type": "application/json", apikey: this.key },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (!res.ok) throw new AuthError("token_refresh_failed");
    const tokens = await res.json<OAuthTokens>();
    tokens.expires_in = Math.min(tokens.expires_in ?? 3600, this.maxTtl);
    return tokens;
  }

  private async supabaseSignOut(accessToken: string): Promise<void> {
    await fetch(`${this.url}/auth/v1/logout`, {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}`, apikey: this.key },
    });
  }

  // ─── Private: 세션 저장소 ─────────────────────────────────────────────────

  private async saveSession(sessionId: string, user: AuthUser, tokens: OAuthTokens): Promise<void> {
    const payload: SessionPayload = {
      user,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      expiresAt: Date.now() + this.ttl * 1000,
      createdAt: Date.now(),
    };
    const { iv, ciphertext } = await encrypt(JSON.stringify(payload), this.encKey);
    await this.store.set(`session:${sessionId}`, JSON.stringify({ iv, ciphertext }), this.ttl);
  }

  private async loadSession(sessionId: string): Promise<SessionPayload | null> {
    const raw = await this.store.get(`session:${sessionId}`);
    if (!raw) return null;
    try {
      const { iv, ciphertext } = JSON.parse(raw);
      const plaintext = await decrypt(iv, ciphertext, this.encKey);
      return JSON.parse(plaintext) as SessionPayload;
    } catch {
      // 복호화 실패 = 위변조 가능성 → 즉시 삭제
      console.error("[SupabaseAuth] Session decryption failed, deleting");
      await this.store.delete(`session:${sessionId}`);
      return null;
    }
  }

  private async deleteSession(sessionId: string): Promise<void> {
    await this.store.delete(`session:${sessionId}`);
  }

  // ─── Private: PKCE state ──────────────────────────────────────────────────

  private async consumePKCEState(state: string): Promise<PKCEState> {
    if (!state || state.length < 32) throw new AuthError("invalid_state");

    const raw = await this.store.get(`pkce:${state}`);
    if (!raw) throw new AuthError("invalid_state");

    // 사용 즉시 삭제 (재사용 방지)
    await this.store.delete(`pkce:${state}`);

    const pkceState: PKCEState = JSON.parse(raw);

    // KV TTL 외 시간 이중 검증
    if (Date.now() - pkceState.createdAt > PKCE_TTL * 1000) {
      throw new AuthError("state_expired");
    }

    return pkceState;
  }

  // ─── Private: 검증 헬퍼 ───────────────────────────────────────────────────

  private validateProvider(raw: string): OAuthProvider {
    if (!(ALLOWED_PROVIDERS as readonly string[]).includes(raw)) {
      throw new AuthError("invalid_provider");
    }
    return raw as OAuthProvider;
  }

  private validateOrigin(url: string): void {
    try {
      const origin = new URL(url).origin;
      if (!this.allowedOrigins.includes(origin)) {
        throw new AuthError("invalid_redirect");
      }
    } catch (e) {
      if (e instanceof AuthError) throw e;
      throw new AuthError("invalid_redirect");
    }
  }

  // ─── Private: 쿠키 빌더 ───────────────────────────────────────────────────

  private buildCookie(sessionId: string, maxAge: number): string {
    return [
      `__Host-session=${sessionId}`,
      "HttpOnly",
      "Secure",
      "SameSite=Lax",
      "Path=/",
      `Max-Age=${maxAge}`,
    ].join("; ");
  }

  private buildClearCookie(): string {
    return "__Host-session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";
  }
}

// ─── 커스텀 에러 ──────────────────────────────────────────────────────────────

export class AuthError extends Error {
  constructor(public readonly code: string) {
    super(code);
    this.name = "AuthError";
  }
}

function isValidSessionId(id: string): boolean {
  return /^[0-9a-f]{64}$/.test(id);
}
