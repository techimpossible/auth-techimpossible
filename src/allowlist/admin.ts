import type { Allowlist, Env } from "../env.js";
import { jsonError, jsonOk } from "../lib/errors.js";

function requireAdminToken(request: Request, env: Env): Response | null {
  const auth = request.headers.get("authorization") ?? "";
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match) return jsonError(401, "missing_credentials", "Bearer ADMIN_API_TOKEN required");
  const provided = match[1].trim();
  const expected = env.ADMIN_API_TOKEN ?? "";
  if (!expected || !timingSafeEqual(provided, expected)) {
    return jsonError(401, "invalid_credentials", "Bearer token invalid");
  }
  return null;
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export async function adminAllowlistHandler(
  request: Request,
  env: Env,
  aud: string
): Promise<Response> {
  const guard = requireAdminToken(request, env);
  if (guard) return guard;

  const key = `allowlist:${aud}`;

  if (request.method === "GET") {
    const value = await env.ALLOWLIST_KV.get<Allowlist>(key, "json");
    return jsonOk({ aud, allowlist: value ?? { emails: [] } });
  }

  if (request.method === "PUT") {
    const body = await safeJson(request);
    if (!body || !Array.isArray(body.emails)) {
      return jsonError(400, "invalid_body", "Body must be { emails: string[] }");
    }
    const allowlist: Allowlist = { emails: body.emails.filter((e: unknown) => typeof e === "string") };
    await env.ALLOWLIST_KV.put(key, JSON.stringify(allowlist));
    return jsonOk({ aud, allowlist });
  }

  if (request.method === "POST") {
    const body = await safeJson(request);
    if (!body || typeof body.email !== "string") {
      return jsonError(400, "invalid_body", "Body must be { email: string }");
    }
    const existing = (await env.ALLOWLIST_KV.get<Allowlist>(key, "json")) ?? { emails: [] };
    if (!existing.emails.includes(body.email)) existing.emails.push(body.email);
    await env.ALLOWLIST_KV.put(key, JSON.stringify(existing));
    return jsonOk({ aud, allowlist: existing });
  }

  if (request.method === "DELETE") {
    const body = await safeJson(request);
    if (!body || typeof body.email !== "string") {
      return jsonError(400, "invalid_body", "Body must be { email: string }");
    }
    const existing = (await env.ALLOWLIST_KV.get<Allowlist>(key, "json")) ?? { emails: [] };
    existing.emails = existing.emails.filter((e) => e !== body.email);
    await env.ALLOWLIST_KV.put(key, JSON.stringify(existing));
    return jsonOk({ aud, allowlist: existing });
  }

  return jsonError(405, "method_not_allowed", "GET/PUT/POST/DELETE supported");
}

async function safeJson(request: Request): Promise<Record<string, unknown> | null> {
  try {
    return (await request.json()) as Record<string, unknown>;
  } catch {
    return null;
  }
}
