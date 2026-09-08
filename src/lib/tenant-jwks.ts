import {
  createRemoteJWKSet,
  jwksCache,
  type ExportedJWKSCache,
  type JWKSCacheInput,
  type JWTVerifyGetKey,
} from "jose";
import type { Env } from "../env.js";
import { sha256Base64Url } from "./crypto.js";
import { JWKS_CACHE_KEY } from "../tenants/model.js";

const MAX_ENTRIES = 128;
const CACHE_MAX_AGE_MS = 600_000;
const COOLDOWN_MS = 30_000;
const FETCH_TIMEOUT_MS = 3_000;
const KV_CACHE_TTL_SECONDS = 86400;

type Entry = { getKey: JWTVerifyGetKey };

const resolvers = new Map<string, Entry>();

function isExportedCache(value: unknown): value is ExportedJWKSCache {
  if (!value || typeof value !== "object") return false;
  const v = value as ExportedJWKSCache;
  return typeof v.uat === "number" && !!v.jwks && Array.isArray(v.jwks.keys);
}

/**
 * Resolve the key set for one tenant issuer.
 *
 * Keyed on issuer AND jwksUri: an admin who rotates a tenant's jwks_uri
 * invalidates the cached resolver immediately rather than silently continuing to
 * fetch the old endpoint for the life of the isolate.
 *
 * Workers isolates are short lived, so a module-level Map alone would refetch
 * the customer's JWKS on nearly every cold start. jose's documented [jwksCache]
 * option is the vendor-sanctioned escape hatch for exactly that: we seed it from
 * TENANT_KV and write it back only when jose reports a new `uat`. jose warns
 * that the cache must be writable only by our own code — TENANT_KV is written
 * solely by this function and by the ADMIN_API_TOKEN-gated tenant admin.
 */
export async function getTenantKeySet(
  env: Env,
  issuer: string,
  jwksUri: string
): Promise<JWTVerifyGetKey> {
  const mapKey = `${issuer} => ${jwksUri}`;
  const existing = resolvers.get(mapKey);
  if (existing) return existing.getKey;

  const url = new URL(jwksUri);
  const kvKey = JWKS_CACHE_KEY(await sha256Base64Url(jwksUri));

  const stored = await env.TENANT_KV.get<ExportedJWKSCache>(kvKey, "json");
  const cacheObject: JWKSCacheInput = isExportedCache(stored) ? stored : {};

  const remote = createRemoteJWKSet(url, {
    cacheMaxAge: CACHE_MAX_AGE_MS,
    cooldownDuration: COOLDOWN_MS,
    timeoutDuration: FETCH_TIMEOUT_MS,
    [jwksCache]: cacheObject,
  });

  const getKey: JWTVerifyGetKey = async (protectedHeader, token) => {
    const before = (cacheObject as ExportedJWKSCache).uat;
    try {
      return await remote(protectedHeader, token);
    } finally {
      const after = (cacheObject as ExportedJWKSCache).uat;
      if (after !== before) {
        await env.TENANT_KV.put(kvKey, JSON.stringify(cacheObject), {
          expirationTtl: KV_CACHE_TTL_SECONDS,
        });
      }
    }
  };

  if (resolvers.size >= MAX_ENTRIES) {
    const oldest = resolvers.keys().next();
    if (!oldest.done) resolvers.delete(oldest.value);
  }
  resolvers.set(mapKey, { getKey });
  return getKey;
}

/** Mirrors clearSigningKeyCache: the module-level Map would otherwise leak between tests. */
export function clearTenantJwksCache(): void {
  resolvers.clear();
}

/**
 * Separate "the customer's IdP is unreachable right now" from "this assertion is
 * bad". Returning invalid_grant for a network blip would make Claude treat a
 * transient outage as a permanent authentication failure.
 */
export function classifyJoseError(err: unknown): "transient" | "reject" {
  const code = (err as { code?: unknown } | null)?.code;
  if (typeof code === "string") {
    switch (code) {
      case "ERR_JWKS_TIMEOUT":
      case "ERR_JWKS_INVALID":
        return "transient";
      case "ERR_JWKS_NO_MATCHING_KEY":
      case "ERR_JWKS_MULTIPLE_MATCHING_KEYS":
      case "ERR_JWS_SIGNATURE_VERIFICATION_FAILED":
      case "ERR_JWS_INVALID":
      case "ERR_JWT_INVALID":
      case "ERR_JWT_EXPIRED":
      case "ERR_JWT_CLAIM_VALIDATION_FAILED":
      case "ERR_JOSE_ALG_NOT_ALLOWED":
      case "ERR_JWK_INVALID":
        return "reject";
      default:
        return "reject";
    }
  }
  // No jose code at all: a raw fetch/abort failure reaching us through the key
  // resolver. Treat as transient — the customer endpoint, not the assertion.
  const name = (err as { name?: unknown } | null)?.name;
  if (name === "TimeoutError" || name === "AbortError" || name === "TypeError") return "transient";
  return "reject";
}
