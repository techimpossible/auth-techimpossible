import type { Env } from "../env.js";
import { jsonError, jsonOk } from "../lib/errors.js";
import { createClient } from "./clients.js";
import {
  logRedirectRefused,
  MAX_REDIRECT_URI_LENGTH,
  redirectDestinationPermitted,
  redirectOrigin,
} from "./redirect-policy.js";

/**
 * Bounds on an UNAUTHENTICATED registration. /register writes to OAUTH_KV with
 * no TTL — the same namespace that holds authcode:, refresh: and client: records
 * — so the request body is bounded here for the same reason src/oauth/cimd.ts
 * bounds what an unauthenticated caller can make this Worker do.
 */
const MAX_REDIRECT_URIS = 5;
const MAX_CLIENT_NAME_LENGTH = 128;

const DESTINATION_RULE =
  "redirect_uris must be either an RFC 8252 loopback URI (http://127.0.0.1, http://[::1] or " +
  "http://localhost, any port) or an https URI on a redirect host this server permits. A client " +
  "registered here is not vetted by anyone, so it may not have an authorization code delivered to " +
  "an arbitrary host.";

export async function registerHandler(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") {
    return jsonError(405, "method_not_allowed", "Use POST for client registration");
  }

  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return jsonError(400, "invalid_client_metadata", "Body must be JSON");
  }

  const redirectUris = body.redirect_uris;
  if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
    return jsonError(400, "invalid_redirect_uri", "redirect_uris must be a non-empty array");
  }
  if (redirectUris.length > MAX_REDIRECT_URIS) {
    return jsonError(
      400,
      "invalid_redirect_uri",
      `redirect_uris must contain at most ${MAX_REDIRECT_URIS} entries`
    );
  }

  for (const uri of redirectUris) {
    if (typeof uri !== "string") {
      return jsonError(400, "invalid_redirect_uri", "redirect_uris must be strings");
    }
    if (uri.length > MAX_REDIRECT_URI_LENGTH) {
      return jsonError(
        400,
        "invalid_redirect_uri",
        `Each redirect_uri must be at most ${MAX_REDIRECT_URI_LENGTH} characters`
      );
    }
    try {
      new URL(uri);
    } catch {
      return jsonError(400, "invalid_redirect_uri", `Malformed URI: ${uri}`);
    }
    // THE CONTROL. Registration is unauthenticated, so a client registered here
    // may only nominate a destination the registrant cannot read: the user's own
    // loopback interface, or an https host an operator vetted.
    if (!redirectDestinationPermitted(env, uri)) {
      logRedirectRefused("dcr.redirect_refused", {
        clientId: null,
        origin: redirectOrigin(uri),
        aud: null,
      });
      return jsonError(400, "invalid_redirect_uri", DESTINATION_RULE);
    }
  }

  if (typeof body.client_name === "string" && body.client_name.length > MAX_CLIENT_NAME_LENGTH) {
    return jsonError(
      400,
      "invalid_client_metadata",
      `client_name must be at most ${MAX_CLIENT_NAME_LENGTH} characters`
    );
  }

  const { record, clientSecret } = await createClient(env, {
    redirect_uris: redirectUris as string[],
    client_name: typeof body.client_name === "string" ? body.client_name : undefined,
    token_endpoint_auth_method:
      typeof body.token_endpoint_auth_method === "string"
        ? body.token_endpoint_auth_method
        : undefined,
    grant_types: Array.isArray(body.grant_types)
      ? (body.grant_types.filter((g) => typeof g === "string") as string[])
      : undefined,
    response_types: Array.isArray(body.response_types)
      ? (body.response_types.filter((r) => typeof r === "string") as string[])
      : undefined,
    scope: typeof body.scope === "string" ? body.scope : undefined,
    allowed_audiences: Array.isArray(body.allowed_audiences)
      ? (body.allowed_audiences.filter((a) => typeof a === "string") as string[])
      : undefined,
  });

  const response = {
    client_id: record.clientId,
    ...(clientSecret ? { client_secret: clientSecret } : {}),
    redirect_uris: record.redirectUris,
    client_name: record.clientName,
    token_endpoint_auth_method: record.tokenEndpointAuthMethod,
    grant_types: record.grantTypes,
    response_types: record.responseTypes,
    scope: record.scope,
    ...(record.allowedAudiences ? { allowed_audiences: record.allowedAudiences } : {}),
    client_id_issued_at: record.registrationDate,
  };

  return jsonOk(response, 201);
}
