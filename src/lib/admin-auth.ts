import type { Env } from "../env.js";
import { jsonError } from "./errors.js";

/**
 * Shared guard for the ADMIN_API_TOKEN-gated /admin/* endpoints. Extracted from
 * src/allowlist/admin.ts and src/oauth/service-clients.ts, which each carried a
 * verbatim copy: a third copy would mean a future hardening fix has to reach
 * three call sites. Behaviour is unchanged, including the fail-closed branch
 * when ADMIN_API_TOKEN is unset.
 *
 * Convention: call this BEFORE the method check, so an unauthenticated wrong
 * method request returns 401 rather than 405.
 */
export function requireAdminToken(request: Request, env: Env): Response | null {
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

/**
 * NOT constant time with respect to length: it returns early on a length
 * mismatch and therefore leaks the length of the expected token. It is constant
 * time only across equal-length inputs. Kept as-is for behavioural parity with
 * the two call sites it replaces.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export async function safeJson(request: Request): Promise<Record<string, unknown> | null> {
  try {
    return (await request.json()) as Record<string, unknown>;
  } catch {
    return null;
  }
}
