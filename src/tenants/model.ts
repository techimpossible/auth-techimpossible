import { SUPPORTED_AUDS } from "../oauth/audiences.js";

export { SUPPORTED_AUDS };

export const TENANT_KEY = (tenantId: string) => `tenant:${tenantId}`;
export const ISSUER_INDEX_KEY = (issuer: string) => `issuer:${issuer}`;
export const TENANT_AUDIT_PREFIX = "tenantaudit:";
export const JWKS_CACHE_KEY = (hash: string) => `jwks:${hash}`;

/**
 * Tenant ids deliberately exclude dots and colons so a tenant id can never be
 * confused with a hostname or with a KV key prefix.
 */
export const TENANT_ID_RE = /^[a-z0-9][a-z0-9_-]{1,62}$/;

const MAX_ISSUER_LENGTH = 256;
const MAX_URL_LENGTH = 512;

const BLOCKED_HOST_SUFFIXES = [
  ".local",
  ".internal",
  ".cluster.local",
  ".onion",
  ".localhost",
  ".techimpossible.com",
];

const BLOCKED_HOSTS = new Set([
  "localhost",
  "metadata.google.internal",
  "techimpossible.com",
]);

/**
 * Host-level SSRF filter for every URL the Worker will fetch on behalf of a
 * tenant admin or a client: the issuer's OIDC discovery document, its JWKS, and
 * a CIMD client_id metadata document.
 *
 * `sameOriginWith`, when supplied, additionally requires the URL to share an
 * origin with that URL (used to bind a jwks_uri to its issuer, and a CIMD
 * redirect_uri to its client_id).
 *
 * Note the *.techimpossible.com block: it stops the tenant admin being used to
 * aim the Worker's own outbound fetch at our Workers, including the issuer
 * itself (auth.techimpossible.com).
 */
export function assertSafeHttpsUrl(raw: string, sameOriginWith?: string): boolean {
  if (typeof raw !== "string") return false;
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > MAX_URL_LENGTH) return false;

  let u: URL;
  try {
    u = new URL(trimmed);
  } catch {
    return false;
  }

  if (u.protocol !== "https:") return false;
  if (u.username || u.password) return false;
  if (u.port && u.port !== "443") return false;

  const host = u.hostname.toLowerCase();
  if (!host) return false;
  // IPv6 literals arrive bracketed; IPv4 literals are all-numeric labels.
  if (host.startsWith("[") || host.endsWith("]")) return false;
  if (/^[0-9.]+$/.test(host)) return false;
  if (!host.includes(".")) return false;
  const tld = host.slice(host.lastIndexOf(".") + 1);
  if (!tld || /^[0-9]+$/.test(tld)) return false;
  if (BLOCKED_HOSTS.has(host)) return false;
  for (const suffix of BLOCKED_HOST_SUFFIXES) {
    if (host.endsWith(suffix)) return false;
  }

  if (sameOriginWith) {
    let other: URL;
    try {
      other = new URL(sameOriginWith);
    } catch {
      return false;
    }
    if (u.origin !== other.origin) return false;
  }

  return true;
}

/**
 * The path segments of a URL, empty elements dropped.
 *
 * Compared byte-exact, because issuer paths are case sensitive (Entra tenant
 * GUIDs, Okta authorization server ids — see normalizeIssuer below). Comparing
 * segment ARRAYS rather than string prefixes removes prefix confusion
 * (`/customer-a` vs `/customer-abc`) structurally instead of by appending a
 * separator, and a percent-encoded separator never splits, so it fails closed.
 */
export function pathSegments(u: URL): string[] {
  return u.pathname.split("/").filter((segment) => segment.length > 0);
}

export type JwksBinding = "subtree" | "sibling" | "origin-only" | "reject";

/**
 * Classify how a `jwks_uri` is bound to the issuer that will be verified with it.
 *
 * WHAT THIS CONTROL EXISTS TO STOP: on a shared multi-tenant IdP host, tenant A
 * nominating tenant B's key endpoint as A's key source, after which key material
 * from B's trust domain decides what is accepted as A. On such hosts the
 * customer discriminator is a PATH SEGMENT, so the real invariant is "the same
 * trust-domain segment", and same-origin alone is the wrong granularity.
 *
 * "Underneath the issuer path" was only ever a special case of that invariant,
 * and asserting it as the general rule was factually wrong. Microsoft Entra v2.0
 * publishes
 *
 *     issuer    https://login.microsoftonline.com/<tenant-guid>/v2.0
 *     jwks_uri  https://login.microsoftonline.com/<tenant-guid>/discovery/v2.0/keys
 *
 * The JWKS sits BESIDE the issuer path, not under it, while still being inside
 * the same tenant GUID. Under the old rule no Entra tenant could be registered
 * at all, through either the explicit or the discovery branch.
 *
 * The tiers, all of them after `assertSafeHttpsUrl` has already required https,
 * a public host, port 443 only, no credentials and SAME ORIGIN with the issuer:
 *
 *   subtree     the jwks path starts with the issuer's full segment list.
 *               Self-evidently inside the issuer's own namespace. Accepted with
 *               no network call (Okta custom authorization servers, Keycloak
 *               realms, PingOne).
 *   sibling     only the FIRST segment matches — the tenant discriminator on a
 *               shared host. Structurally plausible but not self-evident, so the
 *               caller must additionally require the issuer's own published
 *               metadata to designate that exact URL (Entra v2.0).
 *   origin-only the issuer carries no path at all, so it owns the whole host and
 *               there is no tighter binding available (Auth0, an Okta org
 *               server). Host exclusivity in src/tenants/admin.ts is what stops
 *               this tier being loose on a host another tenant also uses.
 *   reject      the first segments differ. That is the cross-tenant attack, and
 *               it is refused before any fetch happens.
 */
export function classifyJwksBinding(rawJwksUri: string, issuer: string): JwksBinding {
  if (!assertSafeHttpsUrl(rawJwksUri, issuer)) return "reject";

  let jwks: URL;
  let iss: URL;
  try {
    jwks = new URL(rawJwksUri.trim());
    iss = new URL(issuer);
  } catch {
    return "reject";
  }

  // Meaningless for a fetch, and it would make later href comparison ambiguous.
  if (jwks.hash) return "reject";

  const issuerSegments = pathSegments(iss);
  if (issuerSegments.length === 0) return "origin-only";

  const jwksSegments = pathSegments(jwks);
  if (
    jwksSegments.length >= issuerSegments.length &&
    issuerSegments.every((segment, i) => jwksSegments[i] === segment)
  ) {
    return "subtree";
  }
  if (jwksSegments.length > 0 && jwksSegments[0] === issuerSegments[0]) return "sibling";
  return "reject";
}

/**
 * Hosts on which every customer is one path segment of a single shared origin,
 * and on which the vendor also publishes SHARED alias endpoints that any tenant
 * of that vendor can authenticate against.
 */
const SHARED_MULTITENANT_IDP_HOSTS = new Set(["login.microsoftonline.com", "sts.windows.net"]);

const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * True when an issuer names a SHARED endpoint on a known multi-tenant IdP host
 * rather than one specific customer tenant — Entra's `/common`, `/organizations`
 * and `/consumers`, whose tokens can carry any `sub` from any Microsoft tenant.
 *
 * The 1:1 issuer index already refuses the SECOND tenant that claims such an
 * issuer, with 409 issuer_conflict. That is too late: the first tenant to claim
 * it would have been granted an issuer that can assert anybody. Refusing it at
 * registration is what the documentation already promises.
 */
export function isSharedMultiTenantIssuer(issuer: string): boolean {
  let u: URL;
  try {
    u = new URL(issuer);
  } catch {
    return false;
  }
  if (!SHARED_MULTITENANT_IDP_HOSTS.has(u.hostname.toLowerCase())) return false;
  const segments = pathSegments(u);
  return segments.length === 0 || !GUID_RE.test(segments[0]);
}

/**
 * One entry of a tenant's mandatory `email_domains` namespace binding: either a
 * wildcard domain ("*@acme.example") or one full address. Validated at write
 * time so a typo ("acme.example", "*@", "*") cannot be stored as a pattern that
 * silently matches nothing — the operator would read the record as scoping the
 * tenant while every assertion failed, or worse, believe scoping is in force
 * while reviewing a record whose only pattern is unusable.
 */
export function isEmailScopePattern(value: unknown): boolean {
  if (typeof value !== "string") return false;
  const pattern = value.trim().toLowerCase();
  if (!pattern || pattern.length > 254) return false;
  const domain = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;
  if (pattern.startsWith("*@")) return domain.test(pattern.slice(2));
  const at = pattern.indexOf("@");
  if (at <= 0) return false;
  const local = pattern.slice(0, at);
  if (local.includes("*") || /\s/.test(local)) return false;
  return domain.test(pattern.slice(at + 1));
}

/**
 * Canonicalise an issuer identifier for use as the `issuer:<iss>` reverse-index
 * key and as the value jose is told to require as `iss`. Scheme and host are
 * lowercased (URL does this); the path is left byte-exact because issuer paths
 * are case sensitive (e.g. Entra tenant GUIDs, Okta authorization server ids).
 * Exactly one trailing slash is stripped. Query and fragment are rejected.
 */
export function normalizeIssuer(raw: string): string | null {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > MAX_ISSUER_LENGTH) return null;
  if (!assertSafeHttpsUrl(trimmed)) return null;

  let u: URL;
  try {
    u = new URL(trimmed);
  } catch {
    return null;
  }
  if (u.search || u.hash) return null;

  let path = u.pathname;
  if (path.endsWith("/")) path = path.slice(0, -1);
  const normalized = `${u.protocol}//${u.host}${path}`;
  if (normalized.length > MAX_ISSUER_LENGTH) return null;
  return normalized;
}

export function clamp(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, Math.floor(value)));
}
