import {
  decodeJwt,
  decodeProtectedHeader,
  jwtVerify,
  type JWTPayload,
  type JWTVerifyGetKey,
} from "jose";
import type { ClientRecord, Env, TenantRecord } from "../env.js";
import { jsonError, jsonOk } from "../lib/errors.js";
import { sha256Base64Url } from "../lib/crypto.js";
import { mintAccessToken } from "../lib/jwt.js";
import { classifyJoseError, getTenantKeySet } from "../lib/tenant-jwks.js";
import { checkStillAuthorized, isEmailAllowed } from "../allowlist/check.js";
import { clamp, normalizeIssuer, SUPPORTED_AUDS } from "../tenants/model.js";
import { loadTenantByIssuer } from "../tenants/store.js";
import { resolveClient, verifyClientSecret } from "./clients.js";
import { JWT_BEARER_GRANT } from "./grants.js";
import { extractClientCredentials } from "./client-auth.js";

export { JWT_BEARER_GRANT };

const MAX_ACCESS_TOKEN_TTL = 3600;
const MIN_ACCESS_TOKEN_TTL = 60;
const MAX_ASSERTION_BYTES = 8192;
const MAX_ASSERTION_LIFETIME = 3600;
const DEFAULT_MAX_ASSERTION_AGE = 300;
const CLOCK_TOLERANCE_SECONDS = 60;
const MAX_EMAIL_LENGTH = 254;
const ID_JAG_TYP = "oauth-id-jag+jwt";

/**
 * The media types a tenant with `allow_legacy_typ` may present, alongside a
 * header that omits `typ` entirely (RFC 7519 §5.1 makes it optional, and its
 * absence says exactly what "JWT" says: nothing about the token's purpose).
 *
 * The flag used to switch jose's `typ` check off entirely, which accepted ANY
 * token that issuer signs for our `aud` — an IdP-minted access token
 * (`at+jwt`), a security event token (`secevent+jwt`), a logout token. That put
 * the customer's IdP operator, not us, in charge of which of their token types
 * are exchangeable for our access tokens. A bounded list keeps the escape hatch
 * for IdPs that do not stamp the ID-JAG media type, while still refusing every
 * token that DECLARES itself to be something other than an authorization grant.
 */
const LEGACY_ASSERTION_TYPS = [ID_JAG_TYP, "jwt"];

/**
 * Scopes this authorization server will echo back as granted. `offline_access`
 * is deliberately absent: the EMA grant never mints a refresh token, so echoing
 * it would advertise an authorization the response does not contain.
 */
const GRANTABLE_SCOPES = new Set(["openid", "email", "profile"]);

/**
 * Signature algorithms a customer identity provider may use. Enumerating them
 * kills `alg: none` and every HS* variant (which would let an attacker sign with
 * a public JWK) before any key resolution happens.
 */
const ALLOWED_ASSERTION_ALGS = [
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
];

const REQUIRED_ASSERTION_CLAIMS = ["iss", "sub", "aud", "exp", "iat", "jti", "client_id"];

export type JwtBearerDeps = {
  resolveKeySet?: (issuer: string, jwksUri: string) => Promise<JWTVerifyGetKey>;
  now?: () => number;
};

/**
 * Uniform rejection for every assertion-validation failure from the header
 * inspection onwards. One byte-identical body closes the oracle that would
 * otherwise let an authenticated client enumerate which issuers are trusted and
 * which tenants a client belongs to. The reason survives in the structured log,
 * not in the response.
 */
function denyAssertion(context: LogContext, reasonCode: string): Response {
  logDecision(context, "deny", reasonCode);
  return jsonError(400, "invalid_grant", "assertion could not be validated");
}

/**
 * RFC 6749 §5.2: token endpoint errors are HTTP 400 unless a spec says
 * otherwise, and RFC 8707 does not say otherwise for `invalid_target`. Returning
 * 403 made client libraries that branch on status before parsing the body treat
 * a resource mismatch as a hard non-OAuth failure and hide the one detail the
 * operator needs.
 */
function denyTarget(context: LogContext, reasonCode: string, description: string): Response {
  logDecision(context, "deny", reasonCode);
  return jsonError(400, "invalid_target", description);
}

type LogContext = {
  tenantId?: string;
  issuer?: string;
  clientId?: string;
  aud?: string;
  subHash?: string;
  jtiHash?: string;
  kid?: string;
};

/**
 * One structured line per EMA decision. The uniform error surface above makes
 * production failures undiagnosable without it. Never logs the raw assertion,
 * the raw jti, the email, or the minted token.
 */
function logDecision(context: LogContext, decision: "allow" | "deny", reasonCode: string): void {
  console.log(
    JSON.stringify({
      evt: "ema.token",
      decision,
      reason_code: reasonCode,
      tenant_id: context.tenantId ?? null,
      issuer: context.issuer ?? null,
      client_id: context.clientId ?? null,
      aud: context.aud ?? null,
      sub_hash: context.subHash ?? null,
      jti_hash: context.jtiHash ?? null,
      kid: context.kid ?? null,
    })
  );
}

/**
 * RFC 7523 §2.1 JWT bearer grant, in the Enterprise Managed Auth shape described
 * at https://claude.com/docs/connectors/building/enterprise-managed-auth : the
 * client presents an ID-JAG assertion signed by the CUSTOMER's identity
 * provider, and we exchange it for one of our own RS256 access tokens.
 *
 * TWO INDEPENDENT IDENTITY CONTROLS APPLY, and both are mandatory:
 *
 *   - `tenant.emailDomains` is the NAMESPACE BINDING. It proves the tenant may
 *     only assert identities inside its own domain, so a customer IdP can never
 *     sign an assertion naming a Techimpossible address. It is required and
 *     non-empty on every tenant record, and a record that somehow lacks it
 *     fails closed here rather than skipping the check.
 *   - `allowlist:<aud>` in ALLOWLIST_KV is the PER-USER AUTHORIZATION, the same
 *     control the interactive Google path applies at src/google/callback.ts.
 *     It is what an operator revokes unilaterally (effective within the <= 1h
 *     token TTL) and it is the only control that can express "everyone at Acme
 *     except this one person". A domain pattern cannot express that.
 *
 * The step order below is itself the security control:
 *
 *   1. bound the assertion size before parsing anything
 *   2. authenticate the client, so an unauthenticated caller can never probe
 *      TENANT_KV or reach an outbound fetch
 *   3. inspect the UNVERIFIED header/payload only to learn `alg` and `iss`
 *   4. resolve `iss` against the per-tenant trusted-issuer allowlist — two KV
 *      reads, zero network — and reject on a miss BEFORE the JWKS is fetched.
 *      This is both the tenant-isolation control and the SSRF ordering.
 *   5. only then verify the signature against the tenant's registered jwks_uri
 *   6. decide identity, audience and authorization BEFORE consuming the jti, so
 *      a request we go on to reject never burns the client's assertion
 *
 * There is deliberately no refresh_token and no id_token in the response: the
 * customer's IdP holds the long-lived credential, and minting one here would
 * create a credential that outlives IdP-side revocation.
 */
export async function handleJwtBearerGrant(
  request: Request,
  env: Env,
  form: URLSearchParams,
  deps: JwtBearerDeps = {}
): Promise<Response> {
  const resolveKeySet =
    deps.resolveKeySet ?? ((issuer: string, jwksUri: string) => getTenantKeySet(env, issuer, jwksUri));
  const now = deps.now ?? (() => Math.floor(Date.now() / 1000));
  const log: LogContext = {};

  // (1) Size bound. This is the only body bound anywhere in the Worker and it
  // precedes all parsing, so a multi-megabyte "assertion" cannot be used as an
  // amplification primitive.
  const assertion = form.get("assertion");
  if (!assertion) {
    return jsonError(400, "invalid_request", "assertion is required for the jwt-bearer grant");
  }
  if (assertion.length > MAX_ASSERTION_BYTES) {
    return denyAssertion(log, "assertion_too_large");
  }

  // (2) Client authentication first.
  const creds = extractClientCredentials(request, form);
  if (!creds.clientId) {
    return jsonError(401, "invalid_client", "client_id required");
  }
  log.clientId = creds.clientId;

  const client = await resolveClient(env, creds.clientId);
  if (!client) return jsonError(401, "invalid_client", "Unknown client_id");

  const secretOk = await verifyClientSecret(client, creds.clientSecret);
  if (!secretOk) return jsonError(401, "invalid_client", "Client authentication failed");

  if (!client.grantTypes.includes(JWT_BEARER_GRANT)) {
    return jsonError(400, "unauthorized_client", "client is not permitted to use the jwt-bearer grant");
  }
  // /register is unauthenticated and passes grant_types straight through from
  // the request body, so grantTypes membership is necessary but never
  // sufficient. Anthropic states plainly that DCR is unsupported for EMA.
  if (client.registrationSource !== "admin" && client.registrationSource !== "cimd") {
    return jsonError(
      400,
      "unauthorized_client",
      "client is not permitted to use the jwt-bearer grant"
    );
  }

  // (3) Unverified inspection: alg, typ and iss only.
  let header: ReturnType<typeof decodeProtectedHeader>;
  let unverified: JWTPayload;
  try {
    header = decodeProtectedHeader(assertion);
    unverified = decodeJwt(assertion);
  } catch {
    return denyAssertion(log, "assertion_malformed");
  }

  log.kid = typeof header.kid === "string" ? header.kid : undefined;

  if (typeof header.alg !== "string" || !ALLOWED_ASSERTION_ALGS.includes(header.alg)) {
    return denyAssertion(log, "alg_not_allowed");
  }
  // Never let the assertion choose its own key source.
  if (header.jku !== undefined || header.jwk !== undefined || header.x5u !== undefined) {
    return denyAssertion(log, "header_key_injection");
  }

  const rawIss = unverified.iss;
  if (typeof rawIss !== "string" || rawIss.length === 0 || rawIss.length > 256) {
    return denyAssertion(log, "iss_missing");
  }
  const issuer = normalizeIssuer(rawIss);
  if (!issuer) {
    return denyAssertion(log, "iss_not_normalizable");
  }
  log.issuer = issuer;

  // (4) THE CONTROL. Two KV reads, no outbound request, signature untouched.
  const resolved = await loadTenantByIssuer(env, issuer);
  if (!resolved) {
    return denyAssertion(log, "issuer_not_trusted");
  }
  const { tenant, trustedIssuer } = resolved;
  log.tenantId = tenant.tenantId;

  // The admin-written tenant record, not the client's self-asserted grant_types,
  // is the authorization gate.
  if (!tenant.allowedClientIds.includes(client.clientId)) {
    return denyAssertion(log, "client_not_in_tenant");
  }

  // The namespace binding is mandatory. TENANT_KV holds untyped JSON, so a
  // record written before email_domains became required can still reach here:
  // fail closed rather than treating "absent" as "no scoping in effect", which
  // is how a customer tenant could once assert a Techimpossible address.
  if (!Array.isArray(tenant.emailDomains) || tenant.emailDomains.length === 0) {
    return denyAssertion(log, "tenant_email_domains_missing");
  }

  // Media type policy. `typ` is inside the JWS protected header, so it is
  // covered by the signature verified in step (5).
  const typ = typeof header.typ === "string" ? normalizeTyp(header.typ) : null;
  const typAllowed = tenant.allowLegacyTyp
    ? typ === null || LEGACY_ASSERTION_TYPS.includes(typ)
    : typ === ID_JAG_TYP;
  if (!typAllowed) {
    return denyAssertion(log, "typ_not_allowed");
  }

  // (5) Signature and claim verification against the tenant's registered JWKS.
  let payload: JWTPayload;
  try {
    const keySet = await resolveKeySet(trustedIssuer.issuer, trustedIssuer.jwksUri);
    const verified = await jwtVerify(assertion, keySet, {
      // `issuer` is deliberately NOT handed to jose: it compares byte-exact
      // against the raw `iss` claim, while everything else in this Worker works
      // on the normalized form, so an IdP whose issuer identifier ends in "/"
      // (Auth0's default) could be registered but could never authenticate. The
      // binding is not dropped — it is enforced immediately below on the
      // VERIFIED payload, comparing the same normalization both sides.
      //
      // Per the ID-JAG draft, `aud` is the Resource AS's issuer identifier. This
      // is the second cross-tenant control: an assertion minted for a different
      // relying party cannot be replayed here.
      audience: env.ISSUER,
      algorithms: ALLOWED_ASSERTION_ALGS,
      requiredClaims: REQUIRED_ASSERTION_CLAIMS,
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
      maxTokenAge: tenant.maxAssertionAgeSeconds ?? DEFAULT_MAX_ASSERTION_AGE,
      typ: tenant.allowLegacyTyp ? undefined : ID_JAG_TYP,
    });
    payload = verified.payload;
  } catch (err) {
    if (classifyJoseError(err) === "transient") {
      logDecision(log, "deny", "idp_unreachable");
      return temporarilyUnavailable();
    }
    return denyAssertion(log, "assertion_verification_failed");
  }

  // (6) Post-checks jose does not perform.
  //
  // The issuer binding, on the VERIFIED payload. Both sides go through
  // normalizeIssuer, so "https://acme.eu.auth0.com/" and
  // "https://acme.eu.auth0.com" are the same issuer here exactly as they are in
  // the reverse index — and an `iss` naming any other issuer is refused even if
  // the signature checks out against this tenant's key set.
  if (typeof payload.iss !== "string" || normalizeIssuer(payload.iss) !== trustedIssuer.issuer) {
    return denyAssertion(log, "iss_mismatch");
  }
  if (payload.client_id !== client.clientId) {
    return denyAssertion(log, "client_id_mismatch");
  }
  const exp = payload.exp;
  const iat = payload.iat;
  if (typeof exp !== "number" || typeof iat !== "number") {
    return denyAssertion(log, "assertion_lifetime_invalid");
  }
  if (exp - iat > MAX_ASSERTION_LIFETIME) {
    return denyAssertion(log, "assertion_lifetime_too_long");
  }
  const sub = payload.sub;
  if (typeof sub !== "string" || sub.length === 0 || sub.length > 255) {
    return denyAssertion(log, "sub_invalid");
  }
  log.subHash = await sha256Base64Url(sub);

  for (const [claim, expected] of Object.entries(tenant.issuerClaimBindings ?? {})) {
    if (payload[claim] !== expected) {
      return denyAssertion(log, "claim_binding_mismatch");
    }
  }

  const jti = payload.jti;
  if (typeof jti !== "string" || jti.length === 0 || jti.length > 255) {
    return denyAssertion(log, "jti_invalid");
  }
  const jtiHash = await sha256Base64Url(jti);
  log.jtiHash = jtiHash;

  // (7) Identity. `email` is OPTIONAL in the ID-JAG draft, but both of our
  // identity controls — the tenant namespace binding and the per-audience
  // allowlist — are keyed on an address, and every resource server downstream
  // reads `email` as the caller identity. An IdP that carries the address in a
  // different claim is configured with `subject_email_claim`; one that carries
  // no address at all cannot be authorized here. See the runbook.
  const emailClaim = tenant.subjectEmailClaim ?? "email";
  const rawEmail = payload[emailClaim];
  if (typeof rawEmail !== "string" || rawEmail.trim().length === 0) {
    return denyAssertion(log, "identity_claim_missing");
  }
  const email = rawEmail.trim().toLowerCase();
  if (email.length > MAX_EMAIL_LENGTH || !/^[^\s@,;]+@[^\s@,;]+\.[^\s@,;]+$/.test(email)) {
    return denyAssertion(log, "identity_claim_malformed");
  }
  // CONTROL 1 — namespace binding: the tenant may only assert its own domain.
  //
  // DELIBERATELY NOT checkStillAuthorized. This evaluates the TENANT's
  // `email_domains`, a different list answering a different question ("may this
  // IdP speak for this address at all?"). Routing it through the per-audience
  // record evaluator would let one audience's deny entry silently change a
  // tenant's identity-namespace binding for every audience.
  if (!isEmailAllowed(email, tenant.emailDomains)) {
    return denyAssertion(log, "email_not_in_tenant_domains");
  }

  // (8) Audience binding. The IdP-signed `resource` CLAIM outranks the
  // client-supplied RFC 8707 `resource` PARAMETER: the claim is the enterprise's
  // own policy decision, so the parameter may only agree, never widen it.
  const claimResourceRaw = payload.resource;
  if (claimResourceRaw !== undefined && typeof claimResourceRaw !== "string") {
    return denyAssertion(log, "resource_claim_invalid");
  }
  // Presence is decided once, on the trimmed value, so an empty-string claim can
  // never suppress a resource parameter the client did supply.
  const claimResource = presentValue(claimResourceRaw);

  // RFC 8707 §2 permits more than one resource indicator. We mint for exactly
  // one audience, so several indicators are honoured only when they all name the
  // same one; otherwise the request is rejected rather than silently dropping
  // every indicator after the first.
  const paramResources = form
    .getAll("resource")
    .map((value) => presentValue(value))
    .filter((value): value is string => value !== undefined);

  let paramAud: string | null = null;
  for (const value of paramResources) {
    const normalized = strictNormalizeAudience(value);
    if (!normalized) {
      return denyTarget(log, "resource_unknown", "Unknown resource");
    }
    if (paramAud && paramAud !== normalized) {
      return denyTarget(
        log,
        "resource_indicators_conflict",
        "resource indicators name more than one resource server; request one token per resource"
      );
    }
    paramAud = normalized;
  }

  let claimAud: string | null = null;
  if (claimResource !== undefined) {
    claimAud = strictNormalizeAudience(claimResource);
    if (!claimAud) {
      return denyTarget(log, "resource_claim_unknown", "Unknown resource");
    }
  }

  let aud: string;
  if (claimAud && paramAud) {
    if (claimAud !== paramAud) {
      return denyTarget(
        log,
        "resource_param_conflicts_with_claim",
        "resource parameter contradicts the assertion's resource claim"
      );
    }
    aud = claimAud;
  } else if (claimAud) {
    aud = claimAud;
  } else if (paramAud) {
    aud = paramAud;
  } else {
    // Anthropic's EMA contract requires the request to be served whether or not
    // a resource indicator is present: some IdP configurations cannot forward
    // one. The admin picks which audience that means.
    aud = defaultAudienceFor(tenant);
  }
  log.aud = aud;

  if (!isAudiencePermitted(tenant, client, aud)) {
    return denyTarget(log, "audience_not_permitted", `not permitted for audience '${aud}'`);
  }

  // (9) CONTROL 2 — per-user authorization, per audience. Identical to the
  // interactive Google path (src/google/callback.ts): ALLOWLIST_KV is the
  // control an operator revokes unilaterally, and it must gate every grant that
  // mints a user-identity token, not just the interactive one.
  const decision = await checkStillAuthorized(env, aud, email);
  if (decision.status === "unavailable") {
    // A corrupt or unreadable ALLOWLIST_KV record is an infrastructure fault,
    // not a statement about this identity. 400 invalid_grant would read as
    // permanent and deprovision the whole audience; 503 is retryable, and the
    // assertion is not consumed because the replay marker is written below.
    logDecision(log, "deny", "allowlist_unavailable");
    return temporarilyUnavailable();
  }
  if (decision.status === "denied") {
    // The response body is byte-identical for both reasons; only the structured
    // log separates "explicitly revoked" from "never authorized", so an
    // authenticated client cannot use the error to probe the allowlist.
    return denyAssertion(
      log,
      decision.reason === "deny_entry" ? "email_denied" : "email_not_allowlisted"
    );
  }

  // (10) Replay dampening. Best effort on eventually-consistent KV, not strict
  // single-use. The jti is hashed so an attacker-chosen string never becomes a
  // raw KV key. The marker is written only now, after every authorization
  // decision: a request that we go on to reject (wrong resource, revoked user)
  // must not burn an assertion the client can still legitimately retry with.
  const replayKey = `idjag:${tenant.tenantId}:${jtiHash}`;
  const seen = await env.OAUTH_KV.get(replayKey);
  if (seen) {
    return denyAssertion(log, "assertion_replayed");
  }
  await env.OAUTH_KV.put(replayKey, "1", {
    expirationTtl: clamp(exp - now() + CLOCK_TOLERANCE_SECONDS, 60, 3900),
  });

  // (11) Mint. The namespaced sub stops a customer IdP subject colliding with a
  // Google subject; the TTL clamp stops a two-minute assertion yielding a
  // sixty-minute access token.
  //
  // `email_verified` is OUR assertion, not the customer's. The ID-JAG draft does
  // not even define the claim, and relaying it would let the party being vetted
  // set a trust signal that resource servers gate on. We emit true because this
  // server has verified the address: signed by an issuer an admin bound to this
  // tenant, inside the tenant's registered email_domains, and present on
  // allowlist:<aud>. That is a stronger statement than any IdP-supplied boolean,
  // and it keeps the EMA token shape identical to every other grant's.
  let minted;
  try {
    minted = await mintAccessToken(env, {
      aud,
      sub: `ema:${tenant.tenantId}:${sub}`,
      email,
      ttlSeconds: clamp(exp - now(), MIN_ACCESS_TOKEN_TTL, MAX_ACCESS_TOKEN_TTL),
      tenantId: tenant.tenantId,
      emailVerified: true,
    });
  } catch {
    // The assertion is already consumed at this point. Say so honestly with a
    // retryable status instead of invalid_grant, which would read as "your
    // assertion is bad" when the fault is ours.
    logDecision(log, "deny", "mint_failed");
    return temporarilyUnavailable();
  }

  logDecision(log, "allow", "ok");

  const grantedScope = resolveGrantedScope(form.get("scope"), payload.scope);
  return jsonOk({
    access_token: minted.token,
    token_type: "Bearer",
    expires_in: minted.expiresIn,
    // RFC 6749 §5.1: the response `scope` describes the scope of the ISSUED
    // token. Echoing the request parameter verbatim asserted authorizations
    // this server never validated and the assertion never granted, so the value
    // is bounded by what we support and by the IdP-signed `scope` claim.
    ...(grantedScope ? { scope: grantedScope } : {}),
  });
}

/**
 * A customer IdP that is unreachable, or our own signing path failing, is not
 * "your assertion is invalid". RFC 6749 §5.2 defaults token errors to HTTP 400
 * "unless specified otherwise"; a 5xx is the honest status for an upstream
 * dependency being down, and every OAuth client already treats 503 as retryable
 * whereas 400 invalid_grant reads as permanent.
 */
function temporarilyUnavailable(): Response {
  const response = jsonError(
    503,
    "temporarily_unavailable",
    "Could not complete the exchange right now. Retry shortly."
  );
  response.headers.set("Retry-After", "5");
  return response;
}

/** Trim, and treat an empty or whitespace-only value as absent. */
function presentValue(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/**
 * RFC 7515 §4.1.9 lets a `typ` omit the "application/" prefix, so the two forms
 * are the same media type and must compare equal.
 */
function normalizeTyp(raw: string): string {
  const trimmed = raw.trim().toLowerCase();
  return trimmed.startsWith("application/") ? trimmed.slice("application/".length) : trimmed;
}

/**
 * Which audience an assertion with no resource indicator is minted for. The
 * admin's explicit choice wins; otherwise the first entry of allowed_audiences,
 * which is the order the admin wrote.
 */
function defaultAudienceFor(tenant: TenantRecord): string {
  if (tenant.defaultAudience && tenant.allowedAudiences.includes(tenant.defaultAudience)) {
    return tenant.defaultAudience;
  }
  return tenant.allowedAudiences[0];
}

/**
 * The granted scope: what the client asked for, intersected with what this
 * server grants and with the IdP-signed `scope` claim when the assertion
 * carries one. Never the raw request parameter.
 */
function resolveGrantedScope(requested: string | null, assertionScope: unknown): string | undefined {
  const split = (value: unknown): string[] =>
    typeof value === "string" ? value.split(/\s+/).filter(Boolean) : [];

  const idpScopes = split(assertionScope);
  const asked = split(requested);
  const candidates = asked.length > 0 ? asked : idpScopes;

  const granted = candidates.filter(
    (scope) => GRANTABLE_SCOPES.has(scope) && (idpScopes.length === 0 || idpScopes.includes(scope))
  );

  const unique = [...new Set(granted)];
  return unique.length > 0 ? unique.join(" ") : undefined;
}

function isAudiencePermitted(tenant: TenantRecord, client: ClientRecord, aud: string): boolean {
  if (!tenant.allowedAudiences.includes(aud)) return false;
  // A client record may carry its own bound: intersect when it does.
  if (client.allowedAudiences && client.allowedAudiences.length > 0) {
    if (!client.allowedAudiences.includes(aud)) return false;
  }
  return true;
}

/**
 * Strict audience resolution for the EMA grant.
 *
 * Deliberately NOT token.ts's normalizeAudience, whose leftmost-hostname-label
 * fallback turns resource=https://evil.example/x into aud "evil". Here an
 * unrecognised resource resolves to null and the request is rejected.
 */
function strictNormalizeAudience(resource: string): string | null {
  const trimmed = resource.trim();
  if (!trimmed) return null;

  if (SUPPORTED_AUDS.has(trimmed)) return trimmed;

  let u: URL;
  try {
    u = new URL(trimmed);
  } catch {
    return null;
  }
  if (u.protocol !== "https:") return null;
  if (u.hash) return null;
  if (u.port && u.port !== "443") return null;

  const path = u.pathname.endsWith("/") ? u.pathname.slice(0, -1) : u.pathname;
  if (path !== "" && path !== "/mcp") return null;

  switch (u.hostname.toLowerCase()) {
    case "compliance-mcp.techimpossible.com":
      return "compliance-mcp";
    case "basecamp-mcp.techimpossible.com":
      return "basecamp-mcp";
    default:
      return null;
  }
}
