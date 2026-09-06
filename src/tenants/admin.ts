import type { Env, TenantRecord, TrustedIssuer } from "../env.js";
import { jsonError, jsonOk } from "../lib/errors.js";
import { requireAdminToken, safeJson } from "../lib/admin-auth.js";
import { sha256Base64Url } from "../lib/crypto.js";
import { fetchJsonOutcome } from "../lib/safe-fetch.js";
import { resolveClient } from "../oauth/clients.js";
import { JWT_BEARER_GRANT } from "../oauth/grants.js";
import {
  classifyJwksBinding,
  isEmailScopePattern,
  isSharedMultiTenantIssuer,
  JWKS_CACHE_KEY,
  normalizeIssuer,
  pathSegments,
  SUPPORTED_AUDS,
  TENANT_ID_RE,
} from "./model.js";
import {
  appendTenantAudit,
  deleteIssuerIndex,
  listIssuerIndexKeys,
  loadTenant,
  lookupIssuerOwner,
  putIssuerIndex,
  putTenant,
  readTenantRaw,
} from "./store.js";

const PUT_BODY_SHAPE =
  "Body must be { display_name?: string, status?: \"active\"|\"disabled\", " +
  "allowed_audiences: string[], default_audience?: string, allowed_client_ids: string[], " +
  "trusted_issuers: [{ issuer: string, jwks_uri?: string }], email_domains: string[], " +
  "subject_email_claim?: string, max_assertion_age_seconds?: number, " +
  "allow_legacy_typ?: boolean, issuer_claim_bindings?: Record<string,string> }";

const ISSUER_BODY_SHAPE = "Body must be { issuer: string, jwks_uri?: string }";

const MIN_ASSERTION_AGE = 30;
const MAX_ASSERTION_AGE = 3600;

function toPublic(record: TenantRecord) {
  return {
    tenant_id: record.tenantId,
    display_name: record.displayName,
    status: record.status,
    // Guarded: readTenantRaw deliberately returns malformed records so an
    // operator can inspect and repair them.
    trusted_issuers: (record.trustedIssuers ?? []).map((ti) => ({
      issuer: ti.issuer,
      jwks_uri: ti.jwksUri,
      added_at: ti.addedAt,
    })),
    allowed_audiences: record.allowedAudiences,
    default_audience: record.defaultAudience,
    allowed_client_ids: record.allowedClientIds,
    email_domains: record.emailDomains,
    subject_email_claim: record.subjectEmailClaim,
    max_assertion_age_seconds: record.maxAssertionAgeSeconds,
    allow_legacy_typ: record.allowLegacyTyp,
    issuer_claim_bindings: record.issuerClaimBindings,
    created_at: record.createdAt,
    updated_at: record.updatedAt,
  };
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((v) => typeof v === "string");
}

const JWKS_BINDING_SHAPE =
  "jwks_uri must be an https URL with a public hostname, same-origin with the issuer, and inside " +
  "the issuer's own trust domain: either underneath the issuer's path, or sharing the issuer's " +
  "first path segment (the tenant discriminator on a shared IdP host) and named by the issuer's " +
  "own discovery document";

/** Bound customer-controlled text before it is echoed into an error body. */
function quoteForError(value: string): string {
  return value.length > 200 ? `${value.slice(0, 200)}…` : value;
}

function sameUrl(a: string, b: string): boolean {
  try {
    return new URL(a).href === new URL(b).href;
  } catch {
    return false;
  }
}

/**
 * Read the issuer's own OIDC discovery document and require it to designate
 * exactly this jwks_uri.
 *
 * This is what makes the "sibling" tier safe. On its own, "shares the issuer's
 * first path segment" is only structurally plausible: on a host whose first
 * segment is a generic collection name (`/tenants/customer-a`), two different
 * customers share it. Requiring the issuer's own metadata to name the URL means
 * an attacker must control the document served at the issuer's own path AND
 * stay inside the issuer's own first segment — strictly stronger than either
 * half alone.
 */
async function confirmJwksWithDiscovery(
  issuer: string,
  jwksUri: string
): Promise<Response | null> {
  const outcome = await fetchJsonOutcome(`${issuer}/.well-known/openid-configuration`);
  if (outcome.status !== "ok") {
    return jsonError(
      400,
      "issuer_unreachable",
      `jwks_uri sits beside the issuer's path rather than underneath it, so ` +
        `${issuer}/.well-known/openid-configuration must confirm it, and that document could not ` +
        `be read. Retry, or supply a jwks_uri underneath the issuer's path.`
    );
  }
  const doc = outcome.doc;
  if (typeof doc.issuer !== "string" || normalizeIssuer(doc.issuer) !== issuer) {
    return jsonError(
      400,
      "issuer_unreachable",
      "Discovery document 'issuer' does not match the registered issuer (RFC 8414 §3.3)"
    );
  }
  if (typeof doc.jwks_uri !== "string" || !sameUrl(doc.jwks_uri, jwksUri)) {
    const published = typeof doc.jwks_uri === "string" ? quoteForError(doc.jwks_uri) : "(absent)";
    return jsonError(
      400,
      "invalid_body",
      `The issuer publishes jwks_uri '${published}', which is not the value supplied`
    );
  }
  return null;
}

/**
 * Resolve one { issuer, jwks_uri? } entry into a TrustedIssuer.
 *
 * When jwks_uri is omitted we read the issuer's OIDC discovery document and
 * require, per RFC 8414 §3.3, that its `issuer` member equals the issuer being
 * registered, and that its jwks_uri is bound to it. Doing this at write time
 * turns a silent 3am runtime failure into a loud registration failure. This is
 * also the recommended way to onboard Microsoft Entra: the URL then comes from
 * Microsoft rather than from a human paste.
 *
 * At most ONE outbound fetch happens per entry, and only where the binding is
 * not self-evident: a subtree jwks_uri is inside the issuer's own namespace by
 * construction, so adding a fetch there would buy no security and would make an
 * admin write depend on the IdP being reachable — deleting the documented
 * escape hatch for an IdP that publishes no discovery document.
 */
async function resolveTrustedIssuer(
  raw: unknown
): Promise<{ ok: true; issuer: TrustedIssuer } | { ok: false; response: Response }> {
  if (!raw || typeof raw !== "object") {
    return { ok: false, response: jsonError(400, "invalid_body", PUT_BODY_SHAPE) };
  }
  const entry = raw as { issuer?: unknown; jwks_uri?: unknown };
  if (typeof entry.issuer !== "string") {
    return { ok: false, response: jsonError(400, "invalid_body", PUT_BODY_SHAPE) };
  }

  const issuer = normalizeIssuer(entry.issuer);
  if (!issuer) {
    return {
      ok: false,
      response: jsonError(
        400,
        "invalid_body",
        "issuer must be an https URL with a public hostname, no port other than 443, no query and no fragment"
      ),
    };
  }

  // A shared alias endpoint can assert any subject from any of that vendor's
  // tenants, so it is refused at registration rather than being granted to
  // whichever tenant claims it first.
  if (isSharedMultiTenantIssuer(issuer)) {
    return {
      ok: false,
      response: jsonError(
        400,
        "invalid_body",
        `Issuer '${issuer}' is a shared multi-tenant endpoint (for example Entra's /common, ` +
          `/organizations or /consumers), which can assert any subject. Register the ` +
          `tenant-specific issuer instead, e.g. https://login.microsoftonline.com/<tenant-id>/v2.0`
      ),
    };
  }

  if (entry.jwks_uri !== undefined) {
    if (typeof entry.jwks_uri !== "string") {
      return { ok: false, response: jsonError(400, "invalid_body", JWKS_BINDING_SHAPE) };
    }
    const binding = classifyJwksBinding(entry.jwks_uri, issuer);
    if (binding === "reject") {
      return { ok: false, response: jsonError(400, "invalid_body", JWKS_BINDING_SHAPE) };
    }
    if (binding === "sibling") {
      const refusal = await confirmJwksWithDiscovery(issuer, entry.jwks_uri);
      if (refusal) return { ok: false, response: refusal };
    }
    return { ok: true, issuer: { issuer, jwksUri: entry.jwks_uri, addedAt: nowSeconds() } };
  }

  const outcome = await fetchJsonOutcome(`${issuer}/.well-known/openid-configuration`);
  if (outcome.status !== "ok") {
    return {
      ok: false,
      response: jsonError(
        400,
        "issuer_unreachable",
        outcome.status === "unreachable"
          ? `Could not read ${issuer}/.well-known/openid-configuration; retry, or supply jwks_uri explicitly`
          : `${issuer}/.well-known/openid-configuration is not a usable JSON document; supply jwks_uri explicitly`
      ),
    };
  }
  const discovery = outcome.doc;
  if (typeof discovery.issuer !== "string" || normalizeIssuer(discovery.issuer) !== issuer) {
    return {
      ok: false,
      response: jsonError(
        400,
        "issuer_unreachable",
        "Discovery document 'issuer' does not match the registered issuer (RFC 8414 §3.3)"
      ),
    };
  }
  // The discovery document is customer-controlled input, so its jwks_uri gets
  // the same trust-domain binding as an explicitly supplied one. No second
  // fetch: this document, whose `issuer` member has just been matched, IS the
  // confirmation the sibling tier asks for.
  if (
    typeof discovery.jwks_uri !== "string" ||
    classifyJwksBinding(discovery.jwks_uri, issuer) === "reject"
  ) {
    return {
      ok: false,
      response: jsonError(
        400,
        "issuer_unreachable",
        "Discovery document jwks_uri is missing, or is not same-origin with the issuer and inside " +
          "its trust domain"
      ),
    };
  }

  return { ok: true, issuer: { issuer, jwksUri: discovery.jwks_uri, addedAt: nowSeconds() } };
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

async function validateClientIds(
  env: Env,
  clientIds: string[]
): Promise<Response | null> {
  if (clientIds.length === 0) {
    return jsonError(400, "invalid_body", "allowed_client_ids must contain at least one client_id");
  }
  for (const clientId of clientIds) {
    const client = await resolveClient(env, clientId);
    if (!client) {
      return jsonError(400, "invalid_body", `Unknown client_id '${clientId}'`);
    }
    if (!client.grantTypes.includes(JWT_BEARER_GRANT)) {
      return jsonError(
        400,
        "invalid_body",
        `client_id '${clientId}' does not permit ${JWT_BEARER_GRANT}`
      );
    }
    if (client.registrationSource !== "admin" && client.registrationSource !== "cimd") {
      return jsonError(
        400,
        "invalid_body",
        `client_id '${clientId}' was self-registered (DCR); Enterprise Managed Auth requires an admin-created or CIMD client`
      );
    }
  }
  return null;
}

/**
 * Reject any issuer already bound to a different tenant. Issuer → tenant is a
 * 1:1 function: a shared issuer could mint any `sub`, so allowing two tenants to
 * claim one would make cross-tenant impersonation a data-model property rather
 * than a bug.
 */
async function assertNoIssuerConflict(
  env: Env,
  tenantId: string,
  issuers: TrustedIssuer[]
): Promise<Response | null> {
  for (const ti of issuers) {
    const owner = await lookupIssuerOwner(env, ti.issuer);
    if (owner && owner !== tenantId) {
      return jsonError(
        409,
        "issuer_conflict",
        `Issuer '${ti.issuer}' is already bound to tenant '${owner}'`
      );
    }
  }
  return null;
}

/**
 * HOST EXCLUSIVITY: a host carries EITHER one whole-host (no path) issuer, OR a
 * set of path-scoped issuers — never both across two different tenants.
 *
 * This is what makes the "origin-only" jwks binding tier as strong as the tenant
 * boundary. An issuer with no path owns its whole origin, so its key source may
 * be any path on that host; that is only safe while no OTHER tenant has a trust
 * domain there. Under this rule a bare-origin issuer can be registered only on a
 * host this tenant alone uses, so the loosest tier's blast radius stops inside
 * the tenant's own trust domain.
 *
 * Path-scoped issuers from different tenants may share a host freely (Entra,
 * PingOne): they are already bound to their own first path segment by
 * classifyJwksBinding.
 *
 * Deliberately not an availability dependency: it is a KV scan, not a fetch. It
 * fails closed if the scan fails.
 */
async function assertHostExclusivity(
  env: Env,
  tenantId: string,
  issuers: TrustedIssuer[]
): Promise<Response | null> {
  /** host -> does THIS record claim the whole host (a no-path issuer) */
  const claimedHosts = new Map<string, boolean>();
  for (const ti of issuers) {
    let u: URL;
    try {
      u = new URL(ti.issuer);
    } catch {
      return jsonError(400, "invalid_body", `Issuer '${ti.issuer}' is not a URL`);
    }
    const host = u.hostname.toLowerCase();
    const wholeHost = pathSegments(u).length === 0;
    claimedHosts.set(host, wholeHost || (claimedHosts.get(host) ?? false));
  }

  let existing: string[];
  try {
    existing = await listIssuerIndexKeys(env);
  } catch {
    return jsonError(
      503,
      "temporarily_unavailable",
      "Could not read the issuer index to verify host exclusivity. Retry shortly."
    );
  }

  const own = new Set(issuers.map((ti) => ti.issuer));
  for (const otherIssuer of existing) {
    if (own.has(otherIssuer)) continue;
    let other: URL;
    try {
      other = new URL(otherIssuer);
    } catch {
      continue;
    }
    const host = other.hostname.toLowerCase();
    if (!claimedHosts.has(host)) continue;
    const otherIsWholeHost = pathSegments(other).length === 0;
    // Two path-scoped issuers on one host are fine; each is bound to its own
    // first segment. Only a whole-host claim on either side conflicts.
    if (!claimedHosts.get(host) && !otherIsWholeHost) continue;

    const owner = await lookupIssuerOwner(env, otherIssuer);
    if (!owner || owner === tenantId) continue;
    return jsonError(
      409,
      "issuer_conflict",
      `Host '${host}' already carries issuer '${otherIssuer}', owned by tenant '${owner}'. ` +
        `A host may hold either one whole-host issuer or a set of path-scoped issuers, ` +
        `never both across different tenants`
    );
  }
  return null;
}

async function dropJwksCache(env: Env, jwksUri: string): Promise<void> {
  await env.TENANT_KV.delete(JWKS_CACHE_KEY(await sha256Base64Url(jwksUri)));
}

/**
 * Unbind an issuer ONLY if this tenant still owns it.
 *
 * The mirror image of the ownership check on the write side, and it matters for
 * the same reason: a disabled tenant keeps its issuers on its record, so another
 * tenant can legitimately have taken one over in the meantime. An unconditional
 * delete here would take that tenant off the air — no error, no audit trail,
 * and a token-time reason code pointing at the wrong thing.
 */
async function unbindOwnedIssuer(env: Env, issuer: string, tenantId: string): Promise<void> {
  const owner = await lookupIssuerOwner(env, issuer);
  if (owner === tenantId) {
    await deleteIssuerIndex(env, issuer);
  }
}

/**
 * Commit a tenant record plus its reverse index. Order matters and every crash
 * window fails closed: the tenant record lands first (an index entry without a
 * record resolves to null), new index entries next, removed index entries after
 * that (an issuer that is no longer trusted is rejected by the stale-index guard
 * in loadTenantByIssuer even before its index entry is gone).
 *
 * The index write is the AUTHORITATIVE issuer → tenant binding, and it is
 * rewritten for every issuer in the record — not only for the one an endpoint
 * happens to be changing. So ownership is re-checked here, over the whole
 * record, immediately before anything is written. Without it, adding issuer Z
 * to tenant A silently re-pointed issuer X at A even though tenant B legitimately
 * owned X, taking B off the air with a misleading reason code.
 */
async function commitTenant(
  env: Env,
  record: TenantRecord,
  previous: TenantRecord | null,
  action: string
): Promise<Response | null> {
  const conflict = await assertNoIssuerConflict(env, record.tenantId, record.trustedIssuers);
  if (conflict) return conflict;

  // Same placement and same reasoning as the check above: it covers every issuer
  // in the RESULTING record, on every write path (PUT, POST /issuers and each
  // re-index), immediately before anything is written.
  const hostConflict = await assertHostExclusivity(env, record.tenantId, record.trustedIssuers);
  if (hostConflict) return hostConflict;

  await putTenant(env, record);

  for (const ti of record.trustedIssuers) {
    await putIssuerIndex(env, ti.issuer, record.tenantId);
  }

  const keep = new Set(record.trustedIssuers.map((ti) => ti.issuer));
  const removed = (previous?.trustedIssuers ?? []).filter((ti) => !keep.has(ti.issuer));
  for (const ti of removed) {
    await unbindOwnedIssuer(env, ti.issuer, record.tenantId);
    await dropJwksCache(env, ti.jwksUri);
  }

  await appendTenantAudit(env, { tenantId: record.tenantId, action });
  return null;
}

/** GET /admin/tenants — list tenant ids. */
export async function adminTenantListHandler(request: Request, env: Env): Promise<Response> {
  const guard = requireAdminToken(request, env);
  if (guard) return guard;

  if (request.method !== "GET") {
    return jsonError(405, "method_not_allowed", "GET supported");
  }

  const listing = await env.TENANT_KV.list({ prefix: "tenant:" });
  return jsonOk({
    tenants: listing.keys.map((k) => k.name.slice("tenant:".length)),
  });
}

/** GET / PUT / DELETE /admin/tenants/<tenantId> */
export async function adminTenantHandler(
  request: Request,
  env: Env,
  tenantId: string
): Promise<Response> {
  const guard = requireAdminToken(request, env);
  if (guard) return guard;

  if (!TENANT_ID_RE.test(tenantId)) {
    return jsonError(400, "invalid_body", "tenant_id must match /^[a-z0-9][a-z0-9_-]{1,62}$/");
  }

  if (request.method === "GET") {
    const record = await readTenantRaw(env, tenantId);
    if (!record) return jsonError(404, "not_found", `No tenant '${tenantId}'`);
    return jsonOk({ tenant: toPublic(record) });
  }

  if (request.method === "PUT") {
    const body = await safeJson(request);
    if (!body) return jsonError(400, "invalid_body", PUT_BODY_SHAPE);

    if (!isStringArray(body.allowed_audiences) || body.allowed_audiences.length === 0) {
      return jsonError(400, "invalid_body", PUT_BODY_SHAPE);
    }
    for (const aud of body.allowed_audiences) {
      if (!SUPPORTED_AUDS.has(aud)) {
        return jsonError(400, "invalid_body", `Unsupported audience '${aud}'`);
      }
    }

    // Which audience a request with no RFC 8707 resource indicator gets. Some
    // IdP configurations cannot forward one, and Anthropic's EMA contract
    // requires the request to be served either way, so the admin chooses rather
    // than the request failing.
    if (body.default_audience !== undefined) {
      if (
        typeof body.default_audience !== "string" ||
        !body.allowed_audiences.includes(body.default_audience)
      ) {
        return jsonError(
          400,
          "invalid_body",
          "default_audience must be one of allowed_audiences"
        );
      }
    }

    if (!isStringArray(body.allowed_client_ids)) {
      return jsonError(400, "invalid_body", PUT_BODY_SHAPE);
    }
    const clientError = await validateClientIds(env, body.allowed_client_ids);
    if (clientError) return clientError;

    if (!Array.isArray(body.trusted_issuers) || body.trusted_issuers.length === 0) {
      return jsonError(400, "invalid_body", PUT_BODY_SHAPE);
    }

    if (body.status !== undefined && body.status !== "active" && body.status !== "disabled") {
      return jsonError(400, "invalid_body", PUT_BODY_SHAPE);
    }
    if (body.display_name !== undefined && typeof body.display_name !== "string") {
      return jsonError(400, "invalid_body", PUT_BODY_SHAPE);
    }
    if (body.subject_email_claim !== undefined) {
      // The claim name indexes straight into the assertion payload, so bound it
      // to an ordinary JWT claim name rather than accepting any string.
      if (
        typeof body.subject_email_claim !== "string" ||
        !/^[A-Za-z0-9_.:/-]{1,64}$/.test(body.subject_email_claim)
      ) {
        return jsonError(
          400,
          "invalid_body",
          "subject_email_claim must be a claim name matching /^[A-Za-z0-9_.:\\/-]{1,64}$/"
        );
      }
    }
    if (body.allow_legacy_typ !== undefined && typeof body.allow_legacy_typ !== "boolean") {
      return jsonError(400, "invalid_body", PUT_BODY_SHAPE);
    }

    // MANDATORY. email_domains is the tenant's namespace binding: it is what
    // proves this tenant's IdP may only assert identities inside its own domain.
    // An omitted list used to mean "no scoping", which let a tenant sign an
    // assertion naming a Techimpossible address. There is no legitimate tenant
    // without one, so a record cannot be created without one either.
    if (!isStringArray(body.email_domains) || body.email_domains.length === 0) {
      return jsonError(
        400,
        "invalid_body",
        "email_domains is required and must be a non-empty array of \"*@domain\" patterns or full addresses"
      );
    }
    for (const pattern of body.email_domains) {
      if (!isEmailScopePattern(pattern)) {
        return jsonError(
          400,
          "invalid_body",
          `email_domains entry '${pattern}' must be "*@domain.example" or a full address`
        );
      }
    }

    if (body.max_assertion_age_seconds !== undefined) {
      const age = body.max_assertion_age_seconds;
      if (
        typeof age !== "number" ||
        !Number.isInteger(age) ||
        age < MIN_ASSERTION_AGE ||
        age > MAX_ASSERTION_AGE
      ) {
        return jsonError(
          400,
          "invalid_body",
          `max_assertion_age_seconds must be an integer between ${MIN_ASSERTION_AGE} and ${MAX_ASSERTION_AGE}`
        );
      }
    }

    let issuerClaimBindings: Record<string, string> | undefined;
    if (body.issuer_claim_bindings !== undefined) {
      const raw = body.issuer_claim_bindings;
      if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
        return jsonError(400, "invalid_body", PUT_BODY_SHAPE);
      }
      issuerClaimBindings = {};
      for (const [claim, value] of Object.entries(raw as Record<string, unknown>)) {
        if (typeof value !== "string") {
          return jsonError(400, "invalid_body", "issuer_claim_bindings values must be strings");
        }
        issuerClaimBindings[claim] = value;
      }
    }

    const issuers: TrustedIssuer[] = [];
    const seen = new Set<string>();
    for (const raw of body.trusted_issuers) {
      const resolved = await resolveTrustedIssuer(raw);
      if (!resolved.ok) return resolved.response;
      if (seen.has(resolved.issuer.issuer)) {
        return jsonError(400, "invalid_body", `Duplicate issuer '${resolved.issuer.issuer}'`);
      }
      seen.add(resolved.issuer.issuer);
      issuers.push(resolved.issuer);
    }

    const conflict = await assertNoIssuerConflict(env, tenantId, issuers);
    if (conflict) return conflict;

    const previous = await readTenantRaw(env, tenantId);
    const record: TenantRecord = {
      tenantId,
      displayName: typeof body.display_name === "string" ? body.display_name : undefined,
      status: (body.status as "active" | "disabled" | undefined) ?? "active",
      trustedIssuers: issuers,
      allowedAudiences: body.allowed_audiences,
      defaultAudience: body.default_audience as string | undefined,
      allowedClientIds: body.allowed_client_ids,
      emailDomains: (body.email_domains as string[]).map((p) => p.trim().toLowerCase()),
      subjectEmailClaim:
        typeof body.subject_email_claim === "string" ? body.subject_email_claim : undefined,
      maxAssertionAgeSeconds: body.max_assertion_age_seconds as number | undefined,
      allowLegacyTyp: body.allow_legacy_typ as boolean | undefined,
      issuerClaimBindings,
      createdAt: previous?.createdAt ?? nowSeconds(),
      updatedAt: nowSeconds(),
    };

    const committed = await commitTenant(
      env,
      record,
      previous,
      previous ? "tenant.replace" : "tenant.create"
    );
    if (committed) return committed;

    if (record.allowLegacyTyp) {
      // Relaxing the ID-JAG media type widens what the customer's IdP can have
      // exchanged here. It is a deliberate, per-tenant choice, so it leaves a
      // trail rather than living silently in one JSON field.
      console.log(
        JSON.stringify({
          evt: "ema.tenant.allow_legacy_typ",
          tenant_id: record.tenantId,
          at: nowSeconds(),
        })
      );
      await appendTenantAudit(env, { tenantId, action: "tenant.allow_legacy_typ" });
    }
    return jsonOk({ tenant: toPublic(record) });
  }

  if (request.method === "DELETE") {
    // Non-destructive: disable the tenant and unbind every issuer, but keep the
    // record for audit. Effective immediately for new assertions; live access
    // tokens expire within their (<= 1h) TTL.
    const record = await readTenantRaw(env, tenantId);
    if (!record) return jsonError(404, "not_found", `No tenant '${tenantId}'`);

    for (const ti of record.trustedIssuers ?? []) {
      await unbindOwnedIssuer(env, ti.issuer, tenantId);
      await dropJwksCache(env, ti.jwksUri);
    }

    const disabled: TenantRecord = { ...record, status: "disabled", updatedAt: nowSeconds() };
    await putTenant(env, disabled);
    await appendTenantAudit(env, { tenantId, action: "tenant.disable" });

    return jsonOk({ tenant: toPublic(disabled) });
  }

  return jsonError(405, "method_not_allowed", "GET/PUT/DELETE supported");
}

/** POST / DELETE /admin/tenants/<tenantId>/issuers — add or remove one issuer. */
export async function adminTenantIssuersHandler(
  request: Request,
  env: Env,
  tenantId: string
): Promise<Response> {
  const guard = requireAdminToken(request, env);
  if (guard) return guard;

  if (!TENANT_ID_RE.test(tenantId)) {
    return jsonError(400, "invalid_body", "tenant_id must match /^[a-z0-9][a-z0-9_-]{1,62}$/");
  }

  if (request.method !== "POST" && request.method !== "DELETE") {
    return jsonError(405, "method_not_allowed", "POST/DELETE supported");
  }

  const existing = await loadTenant(env, tenantId);
  if (!existing) return jsonError(404, "not_found", `No tenant '${tenantId}'`);

  const body = await safeJson(request);
  if (!body || typeof body.issuer !== "string") {
    return jsonError(400, "invalid_body", ISSUER_BODY_SHAPE);
  }

  if (request.method === "DELETE") {
    const normalized = normalizeIssuer(body.issuer);
    if (!normalized) return jsonError(400, "invalid_body", ISSUER_BODY_SHAPE);

    const remaining = existing.trustedIssuers.filter((ti) => ti.issuer !== normalized);
    if (remaining.length === existing.trustedIssuers.length) {
      return jsonError(404, "not_found", `Issuer '${normalized}' is not registered for this tenant`);
    }
    if (remaining.length === 0) {
      return jsonError(
        400,
        "invalid_body",
        "A tenant must keep at least one trusted issuer; DELETE the tenant to disable it instead"
      );
    }

    const record: TenantRecord = {
      ...existing,
      trustedIssuers: remaining,
      updatedAt: nowSeconds(),
    };
    const removed = await commitTenant(env, record, existing, "issuer.remove");
    if (removed) return removed;
    return jsonOk({ tenant: toPublic(record) });
  }

  const resolved = await resolveTrustedIssuer(body);
  if (!resolved.ok) return resolved.response;

  if (existing.trustedIssuers.some((ti) => ti.issuer === resolved.issuer.issuer)) {
    return jsonError(400, "invalid_body", `Issuer '${resolved.issuer.issuer}' is already registered`);
  }

  const record: TenantRecord = {
    ...existing,
    trustedIssuers: [...existing.trustedIssuers, resolved.issuer],
    updatedAt: nowSeconds(),
  };

  // Every issuer in the RESULTING record is checked, not just the new one:
  // commitTenant re-indexes them all, and a disabled tenant can still be holding
  // an issuer that another tenant has since taken over legitimately.
  const conflict = await assertNoIssuerConflict(env, tenantId, record.trustedIssuers);
  if (conflict) return conflict;

  const added = await commitTenant(env, record, existing, "issuer.add");
  if (added) return added;
  return jsonOk({ tenant: toPublic(record) });
}
