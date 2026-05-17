import type { AuthCodeRecord, Env } from "../env.js";
import { jsonError, jsonOk } from "../lib/errors.js";
import { sha256Base64Url } from "../lib/crypto.js";
import { mintAccessToken } from "../lib/jwt.js";
import { lookupClient, verifyClientSecret } from "./clients.js";

const ACCESS_TOKEN_TTL = 3600;

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

  const client = await lookupClient(env, clientCreds.clientId);
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

  return jsonOk({
    access_token: minted.token,
    token_type: "Bearer",
    expires_in: minted.expiresIn,
    scope: codeRecord.scope,
  });
}

function extractClientCredentials(
  request: Request,
  form: URLSearchParams
): { clientId: string | null; clientSecret: string | null } {
  const basic = request.headers.get("authorization");
  if (basic && /^basic\s+/i.test(basic)) {
    try {
      const decoded = atob(basic.replace(/^basic\s+/i, ""));
      const idx = decoded.indexOf(":");
      if (idx >= 0) {
        return {
          clientId: decodeURIComponent(decoded.slice(0, idx)),
          clientSecret: decodeURIComponent(decoded.slice(idx + 1)),
        };
      }
    } catch {
      // fall through
    }
  }
  return {
    clientId: form.get("client_id"),
    clientSecret: form.get("client_secret"),
  };
}
