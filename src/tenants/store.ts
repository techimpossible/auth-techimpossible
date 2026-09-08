import type { Env, TenantRecord, TrustedIssuer } from "../env.js";
import { randomToken } from "../lib/crypto.js";
import { ISSUER_INDEX_KEY, TENANT_AUDIT_PREFIX, TENANT_KEY } from "./model.js";

const AUDIT_TTL_SECONDS = 400 * 24 * 3600;

type IssuerIndexEntry = {
  tenantId: string;
  boundAt: number;
};

function isValidTenant(record: unknown): record is TenantRecord {
  if (!record || typeof record !== "object") return false;
  const r = record as TenantRecord;
  if (typeof r.tenantId !== "string" || !r.tenantId) return false;
  if (r.status !== "active" && r.status !== "disabled") return false;
  if (!Array.isArray(r.trustedIssuers) || r.trustedIssuers.length === 0) return false;
  if (!Array.isArray(r.allowedAudiences) || r.allowedAudiences.length === 0) return false;
  if (!Array.isArray(r.allowedClientIds) || r.allowedClientIds.length === 0) return false;
  for (const ti of r.trustedIssuers) {
    if (!ti || typeof ti.issuer !== "string" || typeof ti.jwksUri !== "string") return false;
  }
  return true;
}

export async function loadTenant(env: Env, tenantId: string): Promise<TenantRecord | null> {
  const record = await env.TENANT_KV.get<TenantRecord>(TENANT_KEY(tenantId), "json");
  if (!isValidTenant(record)) return null;
  return record;
}

export async function readTenantRaw(env: Env, tenantId: string): Promise<TenantRecord | null> {
  // Deliberately skips the fail-closed shape check so the admin endpoint can
  // read back and repair a malformed or disabled record.
  return env.TENANT_KV.get<TenantRecord>(TENANT_KEY(tenantId), "json");
}

export async function lookupIssuerOwner(env: Env, normalizedIssuer: string): Promise<string | null> {
  const entry = await env.TENANT_KV.get<IssuerIndexEntry>(ISSUER_INDEX_KEY(normalizedIssuer), "json");
  if (!entry || typeof entry.tenantId !== "string" || !entry.tenantId) return null;
  return entry.tenantId;
}

/**
 * Resolve an assertion's `iss` to the tenant that owns it. Fails closed on every
 * ambiguity: a missing index entry, a missing or malformed tenant record, a
 * non-active tenant, or — the stale-index guard — an index entry that still
 * points at a tenant whose trustedIssuers no longer contains this issuer.
 *
 * That last check is what makes the admin endpoint's non-atomic multi-key write
 * safe: if a crash leaves an orphan index entry behind, this returns null.
 *
 * The jwksUri is read from the matched trustedIssuers entry, never from the
 * index entry, so the tenant record is the single source of truth for what URL
 * the Worker will fetch.
 */
export async function loadTenantByIssuer(
  env: Env,
  normalizedIssuer: string
): Promise<{ tenant: TenantRecord; trustedIssuer: TrustedIssuer } | null> {
  const tenantId = await lookupIssuerOwner(env, normalizedIssuer);
  if (!tenantId) return null;

  const tenant = await loadTenant(env, tenantId);
  if (!tenant) return null;
  if (tenant.status !== "active") return null;

  const trustedIssuer = tenant.trustedIssuers.find((ti) => ti.issuer === normalizedIssuer);
  if (!trustedIssuer) return null;

  return { tenant, trustedIssuer };
}

export async function putTenant(env: Env, record: TenantRecord): Promise<void> {
  await env.TENANT_KV.put(TENANT_KEY(record.tenantId), JSON.stringify(record));
}

export async function putIssuerIndex(
  env: Env,
  normalizedIssuer: string,
  tenantId: string
): Promise<void> {
  const entry: IssuerIndexEntry = { tenantId, boundAt: Math.floor(Date.now() / 1000) };
  await env.TENANT_KV.put(ISSUER_INDEX_KEY(normalizedIssuer), JSON.stringify(entry));
}

export async function deleteIssuerIndex(env: Env, normalizedIssuer: string): Promise<void> {
  await env.TENANT_KV.delete(ISSUER_INDEX_KEY(normalizedIssuer));
}

/**
 * Every normalized issuer currently present in the reverse index, read by
 * paginating the `issuer:` prefix.
 *
 * The key name IS the issuer, so this answers "which issuers exist" with no
 * per-issuer read; ownership is looked up separately, only for the few that
 * matter to the caller's decision. Admin writes are rare and tenants number in
 * the tens, so a scan is the cheap option — and it needs no second index, which
 * would bring a dual-write consistency problem of its own.
 *
 * Throws on a KV failure rather than returning a short list: a caller using this
 * to enforce an invariant must fail closed, not silently see an empty index.
 */
export async function listIssuerIndexKeys(env: Env): Promise<string[]> {
  const prefix = "issuer:";
  const issuers: string[] = [];
  let cursor: string | undefined;
  do {
    const listing = await env.TENANT_KV.list({ prefix, cursor });
    for (const key of listing.keys) {
      // The prefix is re-checked rather than assumed: slicing a key that does
      // not carry it would silently manufacture a bogus issuer string.
      if (!key.name.startsWith(prefix)) continue;
      issuers.push(key.name.slice(prefix.length));
    }
    cursor = listing.list_complete ? undefined : listing.cursor;
  } while (cursor);
  return issuers;
}

export async function deleteTenantIndexEntries(env: Env, record: TenantRecord): Promise<void> {
  for (const ti of record.trustedIssuers ?? []) {
    await deleteIssuerIndex(env, ti.issuer);
  }
}

export async function appendTenantAudit(
  env: Env,
  entry: { tenantId: string; action: string; issuer?: string; at?: number }
): Promise<void> {
  const at = entry.at ?? Math.floor(Date.now() / 1000);
  const key = `${TENANT_AUDIT_PREFIX}${entry.tenantId}:${at}-${randomToken(6)}`;
  await env.TENANT_KV.put(
    key,
    JSON.stringify({ tenantId: entry.tenantId, action: entry.action, issuer: entry.issuer, at }),
    { expirationTtl: AUDIT_TTL_SECONDS }
  );
}
