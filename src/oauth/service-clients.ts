import type { Env } from "../env.js";
import { jsonError, jsonOk } from "../lib/errors.js";
import { createClient } from "./clients.js";

/**
 * Admin endpoint to register a machine-to-machine (client_credentials) service
 * client. Mirrors the allowlist admin: Bearer ADMIN_API_TOKEN gated. Returns the
 * client_id and the plaintext client_secret ONCE; the secret is not recoverable
 * afterward (only its hash is stored).
 *
 * POST /admin/service-clients
 *   { "client_name": "vendor-review-agent",
 *     "service_email": "vendor-review-agent@techimpossible.com",
 *     "allowed_audiences": ["compliance-mcp"] }
 */
export async function adminServiceClientHandler(request: Request, env: Env): Promise<Response> {
  const guard = requireAdminToken(request, env);
  if (guard) return guard;

  if (request.method !== "POST") {
    return jsonError(405, "method_not_allowed", "POST supported");
  }

  const body = await safeJson(request);
  if (!body || typeof body.service_email !== "string" || !Array.isArray(body.allowed_audiences)) {
    return jsonError(
      400,
      "invalid_body",
      "Body must be { client_name?, service_email: string, allowed_audiences: string[] }"
    );
  }
  const audiences = body.allowed_audiences.filter((a): a is string => typeof a === "string");
  if (audiences.length === 0) {
    return jsonError(400, "invalid_body", "allowed_audiences must contain at least one audience");
  }

  const { record, clientSecret } = await createClient(env, {
    redirect_uris: [], // service clients never redirect
    client_name: typeof body.client_name === "string" ? body.client_name : "service-client",
    token_endpoint_auth_method: "client_secret_post",
    grant_types: ["client_credentials"],
    response_types: [],
    service_email: body.service_email,
    allowed_audiences: audiences,
  });

  return jsonOk({
    client_id: record.clientId,
    client_secret: clientSecret, // shown once
    service_email: record.serviceEmail,
    allowed_audiences: record.allowedAudiences,
    grant_types: record.grantTypes,
    token_endpoint: `${env.ISSUER}/token`,
    note: "Store client_secret now. It is not recoverable. Mint tokens with grant_type=client_credentials.",
  });
}

function requireAdminToken(request: Request, env: Env): Response | null {
  const auth = request.headers.get("authorization") ?? "";
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match) return jsonError(401, "missing_credentials", "Bearer ADMIN_API_TOKEN required");
  const provided = match[1].trim();
  const expected = env.ADMIN_API_TOKEN ?? "";
  if (!expected || !timingSafeEqual(provided, expected)) {
    return jsonError(401, "invalid_credentials", "Bearer token invalid");
  }
  return null;
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function safeJson(request: Request): Promise<Record<string, unknown> | null> {
  try {
    return (await request.json()) as Record<string, unknown>;
  } catch {
    return null;
  }
}
