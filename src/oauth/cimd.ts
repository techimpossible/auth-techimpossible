import type { ClientRecord, Env } from "../env.js";
import { sha256Base64Url } from "../lib/crypto.js";
import { fetchJsonOutcome, type JsonFetchOutcome } from "../lib/safe-fetch.js";
import { assertSafeHttpsUrl } from "../tenants/model.js";
import { isLoopbackRedirect } from "./redirect-policy.js";

const CIMD_CACHE_PREFIX = "cimd:";
const CACHE_TTL_SECONDS = 3600;
/** A document we read and rejected. Stable, so cache the rejection. */
const REJECTED_CACHE_TTL_SECONDS = 300;
/** A document we could not read. Clears on its own, so barely cache it. */
const UNREACHABLE_CACHE_TTL_SECONDS = 20;

type CachedEntry = { ok: true; record: ClientRecord } | { ok: false };

export type CimdDeps = {
  fetchJson?: (url: string) => Promise<JsonFetchOutcome>;
};

/**
 * The client_ids for which this server will fetch a metadata document.
 *
 * CIMD resolution turns an UNAUTHENTICATED request parameter into an outbound
 * HTTPS request from Cloudflare's egress plus a KV write — on /token and
 * /authorize, which previously performed no I/O at all for an unknown client_id.
 * With no allowlist, anyone could point the Worker at any public host, and vary
 * the URL path to defeat the cache and burn OAUTH_KV's write budget (the same
 * namespace that holds authcode:, refresh: and client: records).
 *
 * So the URL must be one an operator wrote into CIMD_CLIENT_IDS. Unset means
 * CIMD is off, which is also what the discovery document then advertises.
 */
export function cimdAllowlist(env: { CIMD_CLIENT_IDS?: string }): string[] {
  return (env.CIMD_CLIENT_IDS ?? "")
    .split(/[\s,]+/)
    .map((value) => value.trim())
    .filter((value) => value.length > 0 && assertSafeHttpsUrl(value));
}

export function isCimdClientIdAllowed(env: { CIMD_CLIENT_IDS?: string }, clientId: string): boolean {
  return cimdAllowlist(env).includes(clientId);
}

/**
 * RFC 8252 §7.3 loopback (shared definition in ./redirect-policy.js: Claude Code
 * declares http://localhost/callback and http://127.0.0.1/callback, and
 * authorize.ts matches those port-agnostically), otherwise https, public host,
 * and same-origin with the vetted client_id URL. That same-origin rule is why a
 * CIMD client is exempt from the DCR redirect-host allowlist: its destinations
 * are already pinned to a URL an operator listed in CIMD_CLIENT_IDS.
 */
function redirectUriAcceptable(uri: unknown, clientIdUrl: string): boolean {
  if (typeof uri !== "string" || !uri) return false;
  if (isLoopbackRedirect(uri)) return true;
  return assertSafeHttpsUrl(uri, clientIdUrl);
}

/**
 * Client ID Metadata Document resolution: the client_id IS an https URL that
 * serves the client's own metadata document.
 *
 * Nothing resolved here is ever persisted to `client:<id>`; the synthesised
 * record lives only in a short-lived `cimd:<hash>` cache, so a CIMD client can
 * never be mistaken for an admin-created one and revoking it is a matter of the
 * document going away.
 */
export async function resolveCimdClient(
  env: Env,
  clientId: string,
  deps: CimdDeps = {}
): Promise<ClientRecord | null> {
  const fetchJson = deps.fetchJson ?? ((url: string) => fetchJsonOutcome(url));

  // Before any KV read and before any outbound request.
  if (!isCimdClientIdAllowed(env, clientId)) return null;
  if (!assertSafeHttpsUrl(clientId)) return null;

  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    return null;
  }
  // A bare origin is not a metadata document location, and query/fragment would
  // make the identity ambiguous.
  if (url.search || url.hash) return null;
  if (url.pathname === "" || url.pathname === "/") return null;

  const cacheKey = `${CIMD_CACHE_PREFIX}${await sha256Base64Url(clientId)}`;
  const cached = await env.OAUTH_KV.get<CachedEntry>(cacheKey, "json");
  if (cached) {
    return cached.ok ? cached.record : null;
  }

  const outcome = await fetchJson(clientId);
  const record = outcome.status === "ok" ? synthesiseRecord(outcome.doc, clientId) : null;

  if (!record) {
    await env.OAUTH_KV.put(cacheKey, JSON.stringify({ ok: false } satisfies CachedEntry), {
      expirationTtl:
        outcome.status === "unreachable"
          ? UNREACHABLE_CACHE_TTL_SECONDS
          : REJECTED_CACHE_TTL_SECONDS,
    });
    return null;
  }

  await env.OAUTH_KV.put(cacheKey, JSON.stringify({ ok: true, record } satisfies CachedEntry), {
    expirationTtl: CACHE_TTL_SECONDS,
  });
  return record;
}

function synthesiseRecord(doc: Record<string, unknown>, clientId: string): ClientRecord | null {
  // The document must claim exactly the URL it was fetched from, otherwise any
  // host could publish a document impersonating another client_id.
  if (doc.client_id !== clientId) return null;
  if (typeof doc.client_name !== "string" || !doc.client_name) return null;
  if (!Array.isArray(doc.redirect_uris) || doc.redirect_uris.length === 0) return null;
  for (const uri of doc.redirect_uris) {
    if (!redirectUriAcceptable(uri, clientId)) return null;
  }

  const grantTypes = Array.isArray(doc.grant_types)
    ? (doc.grant_types.filter((g): g is string => typeof g === "string") as string[])
    : ["authorization_code", "refresh_token"];
  const responseTypes = Array.isArray(doc.response_types)
    ? (doc.response_types.filter((r): r is string => typeof r === "string") as string[])
    : ["code"];

  return {
    clientId,
    clientSecretHash: null,
    redirectUris: doc.redirect_uris as string[],
    clientName: doc.client_name,
    // CIMD clients are public by definition: there is no registration step at
    // which a secret could have been exchanged.
    tokenEndpointAuthMethod: "none",
    grantTypes,
    responseTypes,
    scope: typeof doc.scope === "string" ? doc.scope : undefined,
    registrationDate: Math.floor(Date.now() / 1000),
    registrationSource: "cimd",
  };
}

/** Best-effort cache invalidation for one CIMD client_id. */
export async function clearCimdCache(env: Env, clientId: string): Promise<void> {
  await env.OAUTH_KV.delete(`${CIMD_CACHE_PREFIX}${await sha256Base64Url(clientId)}`);
}
