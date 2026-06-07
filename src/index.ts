/**
 * 사용 예시 — Cloudflare Worker
 * (KV 바인딩 2개 필요: KV_SESSIONS, KV_RATE_LIMIT)
 */

import { SupabaseAuth, AuthError } from "./auth/index.js";
import { CloudflareKVStore } from "./stores/cloudflareKV.js";

interface Env {
  SUPABASE_URL: string;
  SUPABASE_ANON_KEY: string;
  ENCRYPTION_KEY: string;
  KV_SESSIONS: KVNamespace;
  ALLOWED_REDIRECT_ORIGINS: string; // 필요에 따라 허용할 리디렉션 도메인 추가
}


function getAuth(env: Env) {
  return new SupabaseAuth({
    supabaseUrl: env.SUPABASE_URL,
    anonKey: env.SUPABASE_ANON_KEY,
    encryptionKey: env.ENCRYPTION_KEY,
    allowedRedirectOrigins: env.ALLOWED_REDIRECT_ORIGINS.split(",").map((s) => s.trim()),
    store: new CloudflareKVStore(env.KV_SESSIONS),
    session: { ttlSeconds: 900 }, // 15분
  });
}

function getCookie(request: Request, name: string): string | null {
  const cookie = request.headers.get("Cookie") ?? "";
  const match = cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const auth = getAuth(env);

    try {
      // GET /auth/login?provider=google
      if (url.pathname === "/auth/login") {
        const provider = url.searchParams.get("provider") ?? "google";
        const postLoginRedirect = url.searchParams.get("redirect_to") ?? "/";
        const loginUrl = await auth.getLoginUrl(
          provider,
          `${url.origin}/auth/callback`,
          postLoginRedirect,
        );
        return Response.redirect(loginUrl, 302);
      }

      // GET /auth/callback?code=xxx&state=xxx
      if (url.pathname === "/auth/callback") {
        const code = url.searchParams.get("code") ?? "";
        const state = url.searchParams.get("state") ?? "";
        const result = await auth.handleCallback(code, state);

        const res = Response.redirect(
          `${url.origin}${result.postLoginRedirect}`,
          302,
        );
        res.headers.set("Set-Cookie", result.cookie);
        return res;
      }

      // POST /auth/logout
      if (url.pathname === "/auth/logout" && request.method === "POST") {
        const sessionId = getCookie(request, "__Host-session") ?? "";
        const { clearCookie } = await auth.logout(sessionId);
        const res = Response.json({ ok: true });
        res.headers.set("Set-Cookie", clearCookie);
        return res;
      }

      // GET /api/me — 인증 필요 예시
      if (url.pathname === "/api/me") {
        const sessionId = getCookie(request, "__Host-session") ?? "";
        const result = await auth.verifySession(sessionId);

        if (!result) {
          return Response.json({ error: "Unauthorized" }, { status: 401 });
        }

        const res = Response.json({ user: result.user });

        // 세션 갱신된 경우 새 쿠키 재발급
        if (result.renewedCookie) {
          res.headers.set("Set-Cookie", result.renewedCookie);
        }

        return res;
      }

      return Response.json({ error: "Not Found" }, { status: 404 });
    } catch (e) {
      if (e instanceof AuthError) {
        return Response.json({ error: e.code }, { status: 400 });
      }
      console.error("[Worker] Unhandled:", e);
      return Response.json({ error: "Internal Server Error" }, { status: 500 });
    }
  },
};
