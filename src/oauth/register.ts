import type { Env } from "../env.js";
import { jsonError, jsonOk } from "../lib/errors.js";
import { createClient } from "./clients.js";

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

  for (const uri of redirectUris) {
    if (typeof uri !== "string") {
      return jsonError(400, "invalid_redirect_uri", "redirect_uris must be strings");
    }
    try {
      new URL(uri);
    } catch {
      return jsonError(400, "invalid_redirect_uri", `Malformed URI: ${uri}`);
    }
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
    client_id_issued_at: record.registrationDate,
  };

  return jsonOk(response, 201);
}
