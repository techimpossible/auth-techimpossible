import type { AuthCodeRecord, Env } from "../env.js";
import { jsonError, jsonOk } from "../lib/errors.js";
import { randomToken, sha256Base64Url } from "../lib/crypto.js";
import { mintAccessToken, mintIdToken } from "../lib/jwt.js";
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
  if (grantType === "refresh_token") {
    return handleRefreshGrant(request, env, form);
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

  // Mint a refresh token if offline_access was requested. We persist a record
  // keyed by the opaque token; the refresh_token grant exchanges it for a new
  // access_token (TODO once a /token refresh_token grant handler lands).
  let refreshToken: string | undefined;
  const scopes = (codeRecord.scope ?? "").split(/\s+/).filter(Boolean);
  const offlineRequested = scopes.includes("offline_access");
  if (offlineRequested) {
    refreshToken = randomToken(32);
    await env.OAUTH_KV.put(`refresh:${refreshToken}`, JSON.stringify({
      clientId: codeRecord.clientId,
      userId: codeRecord.userId,
      aud: codeRecord.aud,
      sub: codeRecord.props.sub,
      email: codeRecord.props.email,
      scope: codeRecord.scope,
      createdAt: Math.floor(Date.now() / 1000),
    }), { expirationTtl: 30 * 24 * 3600 }); // 30 days
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

interface RefreshTokenRecord {
  clientId: string;
  userId: string;
  aud: string;
  sub: string;
  email: string;
  scope?: string;
  createdAt: number;
}

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

  const client = await lookupClient(env, clientCreds.clientId);
  if (!client) return jsonError(401, "invalid_client", "Unknown client_id");

  const ok = await verifyClientSecret(client, clientCreds.clientSecret);
  if (!ok) return jsonError(401, "invalid_client", "Client authentication failed");

  const recordKey = `refresh:${refreshToken}`;
  const record = await env.OAUTH_KV.get<RefreshTokenRecord>(recordKey, "json");
  if (!record) {
    return jsonError(400, "invalid_grant", "refresh_token expired or unknown");
  }

  if (record.clientId !== client.clientId) {
    return jsonError(400, "invalid_grant", "refresh_token was issued to a different client");
  }

  // Mint a fresh access token with the same claims as the original.
  const minted = await mintAccessToken(env, {
    aud: record.aud,
    sub: record.sub,
    email: record.email,
    ttlSeconds: ACCESS_TOKEN_TTL,
  });

  // Rotate the refresh token: write a new record, invalidate the old one.
  // This is the recommended pattern (RFC 6749 §10.4 + OAuth 2.0 BCP).
  const newRefreshToken = randomToken(32);
  await env.OAUTH_KV.put(`refresh:${newRefreshToken}`, JSON.stringify({
    ...record,
    createdAt: Math.floor(Date.now() / 1000),
  }), { expirationTtl: 30 * 24 * 3600 });
  await env.OAUTH_KV.delete(recordKey);

  const response: Record<string, unknown> = {
    access_token: minted.token,
    token_type: "Bearer",
    expires_in: minted.expiresIn,
    refresh_token: newRefreshToken,
  };
  if (record.scope) response.scope = record.scope;

  return jsonOk(response);
}
