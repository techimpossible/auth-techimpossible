import type { AuthCodeRecord, AuthStateRecord, Env } from "../env.js";
import { jsonError } from "../lib/errors.js";
import { randomToken } from "../lib/crypto.js";
import { isEmailAllowed, loadAllowlist } from "../allowlist/check.js";
import { renderForbiddenPage } from "../pages/forbidden.js";
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

  const allowlist = await loadAllowlist(env, stateJson.aud);
  if (!allowlist || !isEmailAllowed(verified.email, allowlist.emails)) {
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
