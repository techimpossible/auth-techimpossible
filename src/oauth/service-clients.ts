import type { Env } from "../env.js";
import { jsonError, jsonOk } from "../lib/errors.js";
import { requireAdminToken, safeJson } from "../lib/admin-auth.js";
import { createClient } from "./clients.js";
import { SUPPORTED_AUDS } from "./audiences.js";
import { JWT_BEARER_GRANT } from "./grants.js";

const ADMIN_GRANT_TYPES = new Set(["client_credentials", JWT_BEARER_GRANT]);
const ADMIN_AUTH_METHODS = new Set(["client_secret_post", "client_secret_basic", "none"]);

const BODY_SHAPE =
  "Body must be { client_name?: string, service_email?: string, allowed_audiences?: string[], " +
  `grant_types?: ["client_credentials" | "${JWT_BEARER_GRANT}"], ` +
  'token_endpoint_auth_method?: "client_secret_post"|"client_secret_basic"|"none" }. ' +
  "service_email and allowed_audiences are required when grant_types includes client_credentials.";

const EMAIL_RE = /^[^\s@,;]+@[^\s@,;]+\.[^\s@,;]+$/;

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
 *
 * Optionally takes grant_types and token_endpoint_auth_method so the same
 * endpoint can mint an Enterprise Managed Auth client — one that carries
 * urn:ietf:params:oauth:grant-type:jwt-bearer. Clients minted here are stamped
 * registrationSource "admin", which is what /admin/tenants requires: a DCR-born
 * client can never be an EMA client because /register is unauthenticated and
 * echoes back whatever grant_types the caller asked for.
 *
 * Two rules the caller cannot talk this endpoint out of:
 *
 *   - `token_endpoint_auth_method: "none"` is REFUSED together with
 *     client_credentials. RFC 6749 §4.4 requires a confidential client, and for
 *     that grant the client_secret is the entire security boundary: a public
 *     client_credentials client can be driven by anyone who has seen one of its
 *     tokens, because the client_id it needs is that token's `sub`. A public
 *     client is accepted only for the jwt-bearer grant, where the signed,
 *     audience-bound, short-lived assertion is itself the credential
 *     (RFC 7523 §3.1).
 *   - service_email / allowed_audiences are required ONLY for
 *     client_credentials, which mints them into the token. A jwt-bearer-only
 *     client takes its identity from the assertion and its audiences from the
 *     tenant record, so demanding a service identity there would invent one
 *     that nothing uses.
 */
export async function adminServiceClientHandler(request: Request, env: Env): Promise<Response> {
  const guard = requireAdminToken(request, env);
  if (guard) return guard;

  if (request.method !== "POST") {
    return jsonError(405, "method_not_allowed", "POST supported");
  }

  const body = await safeJson(request);
  if (!body) {
    return jsonError(400, "invalid_body", BODY_SHAPE);
  }

  let grantTypes = ["client_credentials"];
  if (body.grant_types !== undefined) {
    if (
      !Array.isArray(body.grant_types) ||
      body.grant_types.length === 0 ||
      !body.grant_types.every((g) => typeof g === "string" && ADMIN_GRANT_TYPES.has(g))
    ) {
      return jsonError(
        400,
        "invalid_body",
        `grant_types must be a non-empty subset of ["client_credentials", "${JWT_BEARER_GRANT}"]`
      );
    }
    grantTypes = [...new Set(body.grant_types as string[])];
  }
  const mintsServiceTokens = grantTypes.includes("client_credentials");

  let authMethod = "client_secret_post";
  if (body.token_endpoint_auth_method !== undefined) {
    if (
      typeof body.token_endpoint_auth_method !== "string" ||
      !ADMIN_AUTH_METHODS.has(body.token_endpoint_auth_method)
    ) {
      return jsonError(
        400,
        "invalid_body",
        'token_endpoint_auth_method must be one of "client_secret_post", "client_secret_basic", "none"'
      );
    }
    authMethod = body.token_endpoint_auth_method;
  }

  if (authMethod === "none" && mintsServiceTokens) {
    return jsonError(
      400,
      "invalid_body",
      'token_endpoint_auth_method "none" cannot be combined with the client_credentials grant: ' +
        "that client would mint tokens for any caller who knows its client_id, which is not a " +
        `secret. Use a confidential auth method, or grant only "${JWT_BEARER_GRANT}".`
    );
  }

  // Required for client_credentials (they become the token's `email` and its
  // audience bound); optional for a jwt-bearer-only client.
  let serviceEmail: string | undefined;
  if (body.service_email !== undefined || mintsServiceTokens) {
    if (typeof body.service_email !== "string" || !EMAIL_RE.test(body.service_email.trim())) {
      return jsonError(
        400,
        "invalid_body",
        mintsServiceTokens
          ? "service_email is required for the client_credentials grant and must be an email address"
          : "service_email, when supplied, must be an email address"
      );
    }
    serviceEmail = body.service_email.trim().toLowerCase();
  }

  let audiences: string[] | undefined;
  if (body.allowed_audiences !== undefined || mintsServiceTokens) {
    if (!Array.isArray(body.allowed_audiences)) {
      return jsonError(400, "invalid_body", BODY_SHAPE);
    }
    audiences = [...new Set(body.allowed_audiences.filter((a): a is string => typeof a === "string"))];
    if (audiences.length === 0) {
      return jsonError(400, "invalid_body", "allowed_audiences must contain at least one audience");
    }
    for (const aud of audiences) {
      if (!SUPPORTED_AUDS.has(aud)) {
        return jsonError(400, "invalid_body", `Unsupported audience '${aud}'`);
      }
    }
  }

  const { record, clientSecret } = await createClient(env, {
    redirect_uris: [], // service clients never redirect
    client_name: typeof body.client_name === "string" ? body.client_name : "service-client",
    token_endpoint_auth_method: authMethod,
    grant_types: grantTypes,
    response_types: [],
    service_email: serviceEmail,
    allowed_audiences: audiences,
    registration_source: "admin",
  });

  return jsonOk({
    client_id: record.clientId,
    client_secret: clientSecret, // shown once
    service_email: record.serviceEmail,
    allowed_audiences: record.allowedAudiences,
    grant_types: record.grantTypes,
    token_endpoint_auth_method: record.tokenEndpointAuthMethod,
    token_endpoint: `${env.ISSUER}/token`,
    note: clientSecret
      ? "Store client_secret now. It is not recoverable."
      : "Public client (token_endpoint_auth_method=none): no client_secret is issued.",
  });
}
