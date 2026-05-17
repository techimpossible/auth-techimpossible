import type { AuthStateRecord, Env } from "../env.js";
import { jsonError } from "../lib/errors.js";
import { randomToken } from "../lib/crypto.js";
import { lookupClient } from "./clients.js";

const STATE_TTL_SECONDS = 600;

const SUPPORTED_AUDS = new Set(["compliance-mcp", "basecamp-mcp"]);

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

  if (responseType !== "code") {
    return jsonError(400, "unsupported_response_type", "Only response_type=code is supported");
  }
  if (!clientId) return jsonError(400, "invalid_request", "client_id is required");
  if (!redirectUri) return jsonError(400, "invalid_request", "redirect_uri is required");

  const client = await lookupClient(env, clientId);
  if (!client) return jsonError(400, "invalid_client", "Unknown client_id");

  if (!client.redirectUris.includes(redirectUri)) {
    return jsonError(400, "invalid_redirect_uri", "redirect_uri not registered for this client");
  }

  if (codeChallenge && codeChallengeMethod && codeChallengeMethod !== "S256") {
    return jsonError(400, "invalid_request", "code_challenge_method must be S256");
  }

  const aud = inferAudience(resource);
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

function inferAudience(resource: string | null): string | null {
  // No resource= → default to compliance-mcp (the most common paid audience).
  // RFC 8707 makes resource optional; Claude.ai sends it when present in resource metadata.
  if (!resource) return "compliance-mcp";
  try {
    const u = new URL(resource);
    if (u.hostname === "compliance-mcp.techimpossible.com") return "compliance-mcp";
    if (u.hostname === "basecamp-mcp.techimpossible.com") return "basecamp-mcp";
    // mcp.techimpossible.com is the public Worker with no auth — clients
    // shouldn't OAuth against it. Reject explicitly instead of silently
    // minting a token that won't be honored anywhere.
    if (u.hostname === "mcp.techimpossible.com") return null;
  } catch {
    // resource might be a bare aud string
  }
  if (SUPPORTED_AUDS.has(resource)) return resource;
  return null;
}
