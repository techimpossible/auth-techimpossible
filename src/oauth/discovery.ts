import { jsonOk } from "../lib/errors.js";

export function discoveryHandler(env: { ISSUER: string }): Response {
  const issuer = env.ISSUER;
  const doc = {
    issuer: issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    registration_endpoint: `${issuer}/register`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic", "none"],
    scopes_supported: ["openid", "email", "offline_access"],
    id_token_signing_alg_values_supported: ["RS256"],
    subject_types_supported: ["public"],
  };
  return jsonOk(doc);
}
