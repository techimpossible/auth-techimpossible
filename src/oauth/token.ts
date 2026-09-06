import type { AuthCodeRecord, Env } from "../env.js";
import { jsonError, jsonOk } from "../lib/errors.js";
import { randomToken, sha256Base64Url } from "../lib/crypto.js";
import { mintAccessToken, mintIdToken } from "../lib/jwt.js";
import { checkStillAuthorized } from "../allowlist/check.js";
import { SUPPORTED_AUDS } from "./audiences.js";
import { resolveClient, verifyClientSecret } from "./clients.js";
import { JWT_BEARER_GRANT } from "./grants.js";
import { handleJwtBearerGrant } from "./jwt-bearer.js";
import { extractClientCredentials } from "./client-auth.js";

export { extractClientCredentials };

const ACCESS_TOKEN_TTL = 3600;

/**
 * IDLE window: how long an UNUSED refresh token stays redeemable, and the ONLY
 * bound on a refresh chain's life. Rotation writes it afresh on every use, so a
 * chain that is exercised regularly does not age out. That is deliberate.
 *
 * An absolute 90-day chain cap was tried here and removed. It was never part of
 * the revocation fix, and it scheduled an outage: completing `/authorize` needs
 * a human at a browser, so a headless integration (Hermes -> compliance-mcp)
 * cannot re-authenticate itself when its chain expires. What it bought was
 * re-proof of the states ALLOWLIST_KV cannot see — a Google account suspended,
 * deleted or password-reset while the address is still on the list. Those are
 * covered on demand by removing the identity from `allowlist:<aud>`, which is
 * re-decided on EVERY use below and is effective within ~1 h with no
 * client-side action. A timer that expires a live integration by default is not
 * an acceptable price for a control the operator can already exercise directly.
 */
const REFRESH_IDLE_TTL = 30 * 24 * 3600;

export async function tokenHandler(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") {
    return jsonError(405, "method_not_allowed", "POST required");
  }

  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.includes("application/x-www-form-urlencoded")) {
    return jsonError(400, "invalid_request", "Content-Type must be application/x-www-form-urlencoded");
  }

  const bodyText = await request.text();
  const form = new URLSearchParams(bodyText);

  const grantType = form.get("grant_type");
  if (grantType === "refresh_token") {
    return handleRefreshGrant(request, env, form);
  }
  if (grantType === "client_credentials") {
    return handleClientCredentialsGrant(request, env, form);
  }
  if (grantType === JWT_BEARER_GRANT) {
    return handleJwtBearerGrant(request, env, form);
  }
  if (grantType !== "authorization_code") {
    return jsonError(400, "unsupported_grant_type", `Unsupported grant_type: ${grantType ?? ""}`);
  }

  const code = form.get("code");
  const redirectUri = form.get("redirect_uri");
  const codeVerifier = form.get("code_verifier");

  if (!code || !redirectUri) {
    return jsonError(400, "invalid_request", "code and redirect_uri are required");
  }

  const clientCreds = extractClientCredentials(request, form);
  if (!clientCreds.clientId) {
    return jsonError(401, "invalid_client", "client_id required");
  }

  const client = await resolveClient(env, clientCreds.clientId);
  if (!client) return jsonError(401, "invalid_client", "Unknown client_id");

  const ok = await verifyClientSecret(client, clientCreds.clientSecret);
  if (!ok) return jsonError(401, "invalid_client", "Client authentication failed");

  const codeKey = `authcode:${code}`;
  const codeRecord = await env.OAUTH_KV.get<AuthCodeRecord>(codeKey, "json");
  if (!codeRecord) {
    return jsonError(400, "invalid_grant", "Authorization code expired or unknown");
  }
  await env.OAUTH_KV.delete(codeKey);

  if (codeRecord.clientId !== client.clientId) {
    return jsonError(400, "invalid_grant", "Authorization code was issued to a different client");
  }
  if (codeRecord.redirectUri !== redirectUri) {
    return jsonError(400, "invalid_grant", "redirect_uri mismatch");
  }

  if (codeRecord.codeChallenge) {
    if (!codeVerifier) {
      return jsonError(400, "invalid_grant", "PKCE code_verifier required");
    }
    if (codeRecord.codeChallengeMethod !== "S256") {
      return jsonError(400, "invalid_grant", "Only PKCE S256 supported");
    }
    const challenge = await sha256Base64Url(codeVerifier);
    if (challenge !== codeRecord.codeChallenge) {
      return jsonError(400, "invalid_grant", "PKCE code_verifier does not match challenge");
    }
  }

  const minted = await mintAccessToken(env, {
    aud: codeRecord.aud,
    sub: codeRecord.props.sub,
    email: codeRecord.props.email,
    ttlSeconds: ACCESS_TOKEN_TTL,
  });

  // Mint a refresh token if offline_access was requested. We persist a record
  // keyed by the opaque token; handleRefreshGrant below exchanges it for a new
  // access_token, re-running the authorization decision from this record's own
  // `aud` and `email` every time.
  let refreshToken: string | undefined;
  const scopes = (codeRecord.scope ?? "").split(/\s+/).filter(Boolean);
  const offlineRequested = scopes.includes("offline_access");
  if (offlineRequested) {
    const issuedAt = Math.floor(Date.now() / 1000);
    refreshToken = randomToken(32);
    const refreshRecord: RefreshTokenRecord = {
      clientId: codeRecord.clientId,
      userId: codeRecord.userId,
      aud: codeRecord.aud,
      sub: codeRecord.props.sub,
      email: codeRecord.props.email,
      scope: codeRecord.scope,
      createdAt: issuedAt,
    };
    await env.OAUTH_KV.put(`refresh:${refreshToken}`, JSON.stringify(refreshRecord), {
      expirationTtl: REFRESH_IDLE_TTL,
    });
  }

  // Mint an ID token if openid scope was requested (OIDC Core §3.1.3.3)
  let idToken: string | undefined;
  if (scopes.includes("openid")) {
    idToken = await mintIdToken(env, {
      audClientId: codeRecord.clientId,
      sub: codeRecord.props.sub,
      email: codeRecord.props.email,
      ttlSeconds: ACCESS_TOKEN_TTL,
    });
  }

  const response: Record<string, unknown> = {
    access_token: minted.token,
    token_type: "Bearer",
    expires_in: minted.expiresIn,
    scope: codeRecord.scope,
  };
  if (refreshToken) response.refresh_token = refreshToken;
  if (idToken) response.id_token = idToken;

  return jsonOk(response);
}

interface RefreshTokenRecord {
  clientId: string;
  userId: string;
  aud: string;
  sub: string;
  email: string;
  scope?: string;
  createdAt: number;
}

type RefreshLogContext = {
  clientId: string | null;
  aud: string | null;
  subHash: string | null;
};

/**
 * One structured line per refresh decision, in the same shape as the EMA
 * grant's `evt: "ema.token"` (src/oauth/jwt-bearer.ts). The refresh grant used
 * to log nothing at all, which made "did that revocation actually take effect?"
 * unanswerable. Never the email, never the token, never the raw subject.
 */
function logRefreshDecision(
  context: RefreshLogContext,
  decision: "allow" | "deny",
  reasonCode: string
): void {
  console.log(
    JSON.stringify({
      evt: "refresh.token",
      decision,
      reason_code: reasonCode,
      aud: context.aud,
      client_id: context.clientId,
      sub_hash: context.subHash,
    })
  );
}

/**
 * An ALLOWLIST_KV read that failed is not "your refresh token is invalid".
 * Mirrors src/oauth/jwt-bearer.ts's handling of an unreachable customer IdP:
 * every OAuth client treats 503 as retryable, whereas 400 invalid_grant reads
 * as permanent and makes a client throw a still-valid credential away.
 */
function temporarilyUnavailable(): Response {
  const response = jsonError(
    503,
    "temporarily_unavailable",
    "Could not verify authorization right now. Retry shortly."
  );
  response.headers.set("Retry-After", "5");
  return response;
}

/**
 * OAuth 2.0 refresh_token grant (RFC 6749 §6).
 *
 * THE STEP ORDER IS THE CONTROL. A refresh token is a long-lived credential, so
 * this grant re-decides authorization on every single use rather than trusting
 * the decision made when the chain started:
 *
 *   1. client authentication first, so an unauthenticated caller never probes
 *      OAUTH_KV with a guessed token
 *   2. the record must exist and belong to that client
 *   3. the record must be able to name an identity and a known audience — a
 *      check that cannot run must not be treated as a check that passed
 *   4. THE CONTROL: `allowlist:<aud>` must still contain the identity. This is
 *      the same ALLOWLIST_KV check the interactive path runs at
 *      src/google/callback.ts and the EMA grant runs at
 *      src/oauth/jwt-bearer.ts. Without it here, DELETE /admin/allowlist/<aud>
 *      stopped new logins but not anyone already holding a refresh token, so
 *      the documented "revocation effective within ~1 h" was false.
 *
 * NO DENIAL CONSUMES THE RECORD. On `unavailable` that is essential: a KV blip
 * must not convert into a mandatory interactive re-authentication for a client
 * that may have no human available. On a genuine denial it costs nothing,
 * because the credential is powerless for as long as the identity is off the
 * list — every use re-checks — and it means an address removed by mistake and
 * re-added resumes working with no re-auth.
 */
async function handleRefreshGrant(
  request: Request,
  env: Env,
  form: URLSearchParams
): Promise<Response> {
  const refreshToken = form.get("refresh_token");
  if (!refreshToken) {
    return jsonError(400, "invalid_request", "refresh_token is required");
  }

  const clientCreds = extractClientCredentials(request, form);
  if (!clientCreds.clientId) {
    return jsonError(401, "invalid_client", "client_id required");
  }

  const client = await resolveClient(env, clientCreds.clientId);
  if (!client) return jsonError(401, "invalid_client", "Unknown client_id");

  const ok = await verifyClientSecret(client, clientCreds.clientSecret);
  if (!ok) return jsonError(401, "invalid_client", "Client authentication failed");

  const log: RefreshLogContext = { clientId: client.clientId, aud: null, subHash: null };

  const recordKey = `refresh:${refreshToken}`;
  const record = await env.OAUTH_KV.get<RefreshTokenRecord>(recordKey, "json");
  if (!record) {
    logRefreshDecision(log, "deny", "record_unknown");
    return jsonError(400, "invalid_grant", "refresh_token expired or unknown");
  }
  log.aud = typeof record.aud === "string" ? record.aud : null;
  if (typeof record.sub === "string" && record.sub.length > 0) {
    log.subHash = await sha256Base64Url(record.sub);
  }

  if (record.clientId !== client.clientId) {
    logRefreshDecision(log, "deny", "client_mismatch");
    return jsonError(400, "invalid_grant", "refresh_token was issued to a different client");
  }

  // KV holds untyped JSON, so the declared type is not a runtime guarantee. A
  // record that cannot name an identity, or names an audience this server does
  // not mint for, cannot be authorized — and must not be able to route around
  // the allowlist check by making that check impossible to run.
  const email = typeof record.email === "string" ? record.email.trim() : "";
  const hasSubject = typeof record.sub === "string" && record.sub.length > 0;
  if (email.length === 0 || !hasSubject || !SUPPORTED_AUDS.has(record.aud)) {
    logRefreshDecision(log, "deny", "record_incomplete");
    return jsonError(400, "invalid_grant", "refresh_token record is incomplete; re-authorize");
  }

  const decision = await checkStillAuthorized(env, record.aud, email);
  if (decision.status === "unavailable") {
    logRefreshDecision(log, "deny", "allowlist_unavailable");
    return temporarilyUnavailable();
  }
  if (decision.status === "denied") {
    // `email_denied` means a `denied` entry on the record revoked this identity
    // explicitly; `not_allowlisted` means nothing covers it. The response body
    // is identical for both — only the log separates them, so a client cannot
    // use the error to probe the list. Same discipline as the EMA grant.
    logRefreshDecision(
      log,
      "deny",
      decision.reason === "deny_entry" ? "email_denied" : "not_allowlisted"
    );
    return jsonError(
      400,
      "invalid_grant",
      "the authenticated identity is no longer authorized for this resource"
    );
  }

  // Mint a fresh access token with the same claims as the original.
  const minted = await mintAccessToken(env, {
    aud: record.aud,
    sub: record.sub,
    email: record.email,
    ttlSeconds: ACCESS_TOKEN_TTL,
  });

  // Rotate the refresh token: write a new record, invalidate the old one.
  // Single-use rotation is OAuth 2.0 Security BCP §4.14 and is what makes theft
  // detectable, so it stays. The rotated record gets the full idle window again:
  // a chain in continuous use stays alive for as long as its identity stays on
  // `allowlist:<aud>`, and stops within ~1 h of leaving it.
  //
  // The spread copies the stored record as it is. A record issued before the
  // absolute cap was removed may still carry a `chainStartedAt` number; nothing
  // reads it any more, so it is inert data that ages out with the record.
  const now = Math.floor(Date.now() / 1000);
  const newRefreshToken = randomToken(32);
  const rotated: RefreshTokenRecord = { ...record, createdAt: now };
  await env.OAUTH_KV.put(`refresh:${newRefreshToken}`, JSON.stringify(rotated), {
    expirationTtl: REFRESH_IDLE_TTL,
  });
  await env.OAUTH_KV.delete(recordKey);

  logRefreshDecision(log, "allow", "ok");

  const response: Record<string, unknown> = {
    access_token: minted.token,
    token_type: "Bearer",
    expires_in: minted.expiresIn,
    refresh_token: newRefreshToken,
  };
  if (record.scope) response.scope = record.scope;

  return jsonOk(response);
}

/**
 * OAuth 2.0 client_credentials grant (RFC 6749 §4.4) for machine-to-machine
 * callers such as the vendor-review Managed Agent's Worker. There is no user and
 * no Google login: the client_secret is the entire security boundary. The service
 * client record carries the `email` to mint (serviceEmail) and the audiences it is
 * allowed to request (allowedAudiences). The minted token is identical in shape to
 * a user token (email_verified: true, sub, aud), so resource servers verify it the
 * same way. Resource servers do not re-check the email allowlist, so scoping lives
 * entirely on the client record here.
 */
async function handleClientCredentialsGrant(
  request: Request,
  env: Env,
  form: URLSearchParams
): Promise<Response> {
  const clientCreds = extractClientCredentials(request, form);
  if (!clientCreds.clientId) {
    return jsonError(401, "invalid_client", "client_id required");
  }

  const client = await resolveClient(env, clientCreds.clientId);
  if (!client) return jsonError(401, "invalid_client", "Unknown client_id");

  const ok = await verifyClientSecret(client, clientCreds.clientSecret);
  if (!ok) return jsonError(401, "invalid_client", "Client authentication failed");

  if (!client.grantTypes.includes("client_credentials")) {
    return jsonError(400, "unauthorized_client", "client is not permitted to use client_credentials");
  }
  if (!client.serviceEmail || !client.allowedAudiences || client.allowedAudiences.length === 0) {
    return jsonError(400, "invalid_client", "service client missing serviceEmail / allowedAudiences");
  }

  // Determine the target audience. RFC 8707 resource= (a URL) or a bare audience=.
  const requested = form.get("resource") ?? form.get("audience");
  let aud: string;
  if (requested) {
    aud = normalizeAudience(requested);
    if (!client.allowedAudiences.includes(aud)) {
      return jsonError(403, "invalid_target", `client not permitted for audience '${aud}'`);
    }
  } else if (client.allowedAudiences.length === 1) {
    aud = client.allowedAudiences[0];
  } else {
    return jsonError(400, "invalid_request", "resource or audience is required (client permits multiple audiences)");
  }

  const minted = await mintAccessToken(env, {
    aud,
    sub: client.clientId, // stable service subject
    email: client.serviceEmail,
    ttlSeconds: ACCESS_TOKEN_TTL,
  });

  // No refresh token: client_credentials clients re-authenticate with the secret.
  return jsonOk({
    access_token: minted.token,
    token_type: "Bearer",
    expires_in: minted.expiresIn,
    scope: form.get("scope") ?? undefined,
  });
}

/**
 * Accept either a bare audience string ("compliance-mcp") or an RFC 8707 resource
 * URL and reduce it to the canonical aud string the resource server expects.
 */
function normalizeAudience(resource: string): string {
  try {
    const u = new URL(resource);
    if (u.hostname === "compliance-mcp.techimpossible.com") return "compliance-mcp";
    if (u.hostname === "basecamp-mcp.techimpossible.com") return "basecamp-mcp";
    if (u.hostname === "finance-mcp.techimpossible.com") return "finance-mcp";
    // Unknown URL: fall back to the hostname's leftmost label.
    return u.hostname.split(".")[0];
  } catch {
    // Not a URL: treat as a bare audience string.
    return resource;
  }
}
