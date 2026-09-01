import type { AuthStateRecord, Env } from "../env.js";
import { jsonError } from "../lib/errors.js";
import { randomToken } from "../lib/crypto.js";
import { lookupClient } from "./clients.js";
import { resolveAuthorizeAudience } from "./audience.js";

const STATE_TTL_SECONDS = 600;

// RFC 8252 §7.3: native/CLI apps (MCP clients, Claude Desktop, etc.) use a
// loopback redirect with a runtime-assigned port. Treat 127.0.0.1 / ::1 /
// localhost over http as loopback.
function isLoopbackRedirect(uriStr: string): boolean {
  try {
    const u = new URL(uriStr);
    return (
      u.protocol === "http:" &&
      (u.hostname === "127.0.0.1" || u.hostname === "::1" || u.hostname === "localhost")
    );
  } catch {
    return false;
  }
}

// Exact match, OR — for loopback clients — any loopback redirect (any port/path).
// Safe: a loopback redirect can only ever deliver the code to the user's own machine.
function redirectAllowed(redirectUris: string[], redirectUri: string): boolean {
  if (redirectUris.includes(redirectUri)) return true;
  if (isLoopbackRedirect(redirectUri) && redirectUris.some(isLoopbackRedirect)) return true;
  return false;
}

export async function authorizeHandler(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const params = url.searchParams;

  const responseType = params.get("response_type");
  const clientId = params.get("client_id");
  const redirectUri = params.get("redirect_uri");
  const scope = params.get("scope") ?? "openid email";
  const state = params.get("state");
  const codeChallenge = params.get("code_challenge");
  const codeChallengeMethod = params.get("code_challenge_method");
  const resource = params.get("resource") ?? params.get("audience");
  const resourceMetadata = params.get("resource_metadata");

  if (responseType !== "code") {
    return jsonError(400, "unsupported_response_type", "Only response_type=code is supported");
  }
  if (!clientId) return jsonError(400, "invalid_request", "client_id is required");
  if (!redirectUri) return jsonError(400, "invalid_request", "redirect_uri is required");

  const client = await lookupClient(env, clientId);
  if (!client) return jsonError(400, "invalid_client", "Unknown client_id");

  if (!redirectAllowed(client.redirectUris, redirectUri)) {
    return jsonError(400, "invalid_redirect_uri", "redirect_uri not registered for this client");
  }

  if (codeChallenge && codeChallengeMethod && codeChallengeMethod !== "S256") {
    return jsonError(400, "invalid_request", "code_challenge_method must be S256");
  }

  const aud = resolveAuthorizeAudience(resource, client, resourceMetadata);
  if (!aud) {
    return jsonError(
      400,
      "invalid_request",
      "Could not determine target audience. Provide resource= pointing to a known MCP."
    );
  }

  const nonce = randomToken(24);
  const record: AuthStateRecord = {
    responseType,
    clientId,
    redirectUri,
    scope,
    state,
    codeChallenge,
    codeChallengeMethod,
    aud,
    createdAt: Math.floor(Date.now() / 1000),
  };
  await env.OAUTH_KV.put(`authstate:${nonce}`, JSON.stringify(record), {
    expirationTtl: STATE_TTL_SECONDS,
  });

  const googleAuth = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  googleAuth.searchParams.set("client_id", env.GOOGLE_OIDC_CLIENT_ID);
  googleAuth.searchParams.set("redirect_uri", `${env.ISSUER}/oauth/callback`);
  googleAuth.searchParams.set("response_type", "code");
  googleAuth.searchParams.set("scope", "openid email");
  googleAuth.searchParams.set("state", nonce);
  googleAuth.searchParams.set("prompt", "select_account");
  googleAuth.searchParams.set("access_type", "online");

  return Response.redirect(googleAuth.toString(), 302);
}
