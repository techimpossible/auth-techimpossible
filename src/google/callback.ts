import type { AuthCodeRecord, AuthStateRecord, Env } from "../env.js";
import { jsonError } from "../lib/errors.js";
import { randomToken, sha256Base64Url } from "../lib/crypto.js";
import { checkStillAuthorized } from "../allowlist/check.js";
import { renderForbiddenPage } from "../pages/forbidden.js";
import { renderTemporarilyUnavailablePage } from "../pages/unavailable.js";
import { exchangeGoogleAuthCode } from "./exchange.js";
import { verifyGoogleIdToken } from "./verify.js";

const AUTH_CODE_TTL_SECONDS = 60;

export async function googleCallbackHandler(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const params = url.searchParams;

  const googleError = params.get("error");
  if (googleError) {
    const desc = params.get("error_description") ?? googleError;
    return jsonError(400, "google_oauth_error", desc);
  }

  const code = params.get("code");
  const state = params.get("state");
  if (!code || !state) {
    return jsonError(400, "invalid_request", "Missing code or state");
  }

  const stateKey = `authstate:${state}`;
  const stateJson = await env.OAUTH_KV.get<AuthStateRecord>(stateKey, "json");
  if (!stateJson) {
    return jsonError(400, "invalid_state", "State expired or unknown — restart authorization");
  }
  await env.OAUTH_KV.delete(stateKey);

  const googleTokens = await exchangeGoogleAuthCode({
    code,
    clientId: env.GOOGLE_OIDC_CLIENT_ID,
    clientSecret: env.GOOGLE_OIDC_CLIENT_SECRET,
    redirectUri: `${env.ISSUER}/oauth/callback`,
  });

  const idToken = googleTokens.id_token;
  if (!idToken) {
    return jsonError(502, "google_token_response_invalid", "Google did not return an id_token");
  }

  let verified;
  try {
    verified = await verifyGoogleIdToken(idToken, env.GOOGLE_OIDC_CLIENT_ID);
  } catch (e) {
    return jsonError(401, "google_id_token_invalid", e instanceof Error ? e.message : String(e));
  }

  // THE PER-AUDIENCE AUTHORIZATION DECISION, through the one function every
  // grant uses (src/allowlist/check.ts). It used to be an inline
  // loadAllowlist + isEmailAllowed here, which meant a control added to the
  // decision — the deny list — would have been enforced on refresh and skipped
  // on interactive login, and a revoked user could simply log in again for a
  // fresh chain.
  const decision = await checkStillAuthorized(env, stateJson.aud, verified.email);
  if (decision.status !== "allowed") {
    logCallbackRefusal(stateJson.aud, decision.status, decision.reason, await sha256Base64Url(verified.sub));
  }
  if (decision.status === "unavailable") {
    // NOT the 403 page. Nothing was decided about this account: one corrupt
    // ALLOWLIST_KV value or one failed read must not tell a legitimate user
    // they have been deprovisioned.
    return renderTemporarilyUnavailablePage({ aud: stateJson.aud });
  }
  if (decision.status === "denied") {
    // The page is byte-identical whether the address was never authorized or
    // was explicitly revoked. Rendering that difference would let anyone with a
    // Google account probe whether a given address is provisioned for an
    // audience; the reason is in the log line above instead. Same
    // oracle-closing discipline as denyAssertion in src/oauth/jwt-bearer.ts.
    return renderForbiddenPage({ email: verified.email, aud: stateJson.aud });
  }

  const authCode = randomToken(32);
  const authCodeRecord: AuthCodeRecord = {
    clientId: stateJson.clientId,
    userId: verified.email,
    redirectUri: stateJson.redirectUri,
    scope: stateJson.scope,
    codeChallenge: stateJson.codeChallenge,
    codeChallengeMethod: stateJson.codeChallengeMethod,
    props: {
      email: verified.email,
      sub: verified.sub,
      tenant_id: null,
      roles: [],
    },
    aud: stateJson.aud,
    createdAt: Math.floor(Date.now() / 1000),
  };
  await env.OAUTH_KV.put(`authcode:${authCode}`, JSON.stringify(authCodeRecord), {
    expirationTtl: AUTH_CODE_TTL_SECONDS,
  });

  const redirect = new URL(stateJson.redirectUri);
  redirect.searchParams.set("code", authCode);
  if (stateJson.state) redirect.searchParams.set("state", stateJson.state);

  return Response.redirect(redirect.toString(), 302);
}

/**
 * One structured line per REFUSED interactive sign-in, in the shape of
 * `evt: "refresh.token"` (src/oauth/token.ts) and `evt: "ema.token"`
 * (src/oauth/jwt-bearer.ts). Refusals only: this is the record that answers
 * "did that revocation take effect?" and "was that a decision or an outage?".
 * Never the email, never the raw Google subject.
 */
function logCallbackRefusal(
  aud: string,
  decision: "denied" | "unavailable",
  reasonCode: string,
  subHash: string
): void {
  console.log(
    JSON.stringify({
      evt: "google.callback",
      decision: decision === "denied" ? "deny" : "unavailable",
      reason_code: reasonCode,
      aud,
      sub_hash: subHash,
    })
  );
}
