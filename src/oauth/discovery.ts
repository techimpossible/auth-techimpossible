import { jsonOk } from "../lib/errors.js";
import { cimdAllowlist } from "./cimd.js";

export function discoveryHandler(env: { ISSUER: string; CIMD_CLIENT_IDS?: string }): Response {
  const issuer = env.ISSUER;
  // Only claim CIMD support when at least one client_id is actually resolvable.
  // Advertising it while every document fetch is refused would send Claude down
  // a path that cannot complete; and advertising it at all is what makes Claude
  // switch to a URL client_id, so it stays an explicit operator decision.
  const cimdSupported = cimdAllowlist(env).length > 0;
  const doc = {
    issuer: issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    registration_endpoint: `${issuer}/register`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    response_types_supported: ["code"],
    grant_types_supported: [
      "authorization_code",
      "refresh_token",
      "client_credentials",
      // RFC 7523 §2.1, used by the Enterprise Managed Auth flow.
      "urn:ietf:params:oauth:grant-type:jwt-bearer",
    ],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic", "none"],
    // Claude selects CIMD when this and "none" are both advertised, and then
    // uses a URL client_id on the interactive flow too — including on refresh,
    // where a client_id change invalidates existing refresh tokens. So it is
    // advertised only once an operator has listed the exact metadata document
    // URL in CIMD_CLIENT_IDS and verified it resolves.
    client_id_metadata_document_supported: cimdSupported,
    scopes_supported: ["openid", "email", "offline_access"],
    id_token_signing_alg_values_supported: ["RS256"],
    subject_types_supported: ["public"],
  };
  return jsonOk(doc);
}
