import { describe, expect, it } from "vitest";
import { discoveryHandler } from "../src/oauth/discovery.js";
import { JWT_BEARER_GRANT } from "../src/oauth/grants.js";

const ISSUER = "https://auth.example.test";

async function metadata(env: { CIMD_CLIENT_IDS?: string } = {}) {
  const res = discoveryHandler({ ISSUER, ...env });
  expect(res.status).toBe(200);
  expect(res.headers.get("content-type")).toContain("application/json");
  return (await res.json()) as Record<string, any>;
}

describe("authorization server metadata", () => {
  it("advertises the jwt-bearer grant used by Enterprise Managed Auth", async () => {
    const doc = await metadata();
    expect(doc.grant_types_supported).toContain(JWT_BEARER_GRANT);
    expect(doc.grant_types_supported).toContain("urn:ietf:params:oauth:grant-type:jwt-bearer");
  });

  it("does not advertise Client ID Metadata Document support until one is configured", async () => {
    // Advertising it is what makes Claude switch to a URL client_id, and every
    // CIMD document fetch is refused unless an operator listed that URL. So the
    // default document must not claim a capability nothing can use.
    const doc = await metadata();
    expect(doc.client_id_metadata_document_supported).toBe(false);
    // Claude only selects CIMD when "none" is also offered.
    expect(doc.token_endpoint_auth_methods_supported).toContain("none");
  });

  it("advertises Client ID Metadata Document support once a client_id is allowlisted", async () => {
    const doc = await metadata({
      CIMD_CLIENT_IDS: "https://client.example/metadata.json",
    });
    expect(doc.client_id_metadata_document_supported).toBe(true);
  });

  it("ignores a CIMD entry that is not a safe https URL", async () => {
    const doc = await metadata({ CIMD_CLIENT_IDS: "http://client.example/metadata.json" });
    expect(doc.client_id_metadata_document_supported).toBe(false);
  });

  it("keeps every previously advertised grant (no regression for existing clients)", async () => {
    const doc = await metadata();
    for (const grant of ["authorization_code", "refresh_token", "client_credentials"]) {
      expect(doc.grant_types_supported).toContain(grant);
    }
  });

  it("keeps the rest of the document stable", async () => {
    const doc = await metadata();
    expect(doc.issuer).toBe(ISSUER);
    expect(doc.authorization_endpoint).toBe(`${ISSUER}/authorize`);
    expect(doc.token_endpoint).toBe(`${ISSUER}/token`);
    expect(doc.registration_endpoint).toBe(`${ISSUER}/register`);
    expect(doc.jwks_uri).toBe(`${ISSUER}/.well-known/jwks.json`);
    expect(doc.response_types_supported).toEqual(["code"]);
    expect(doc.code_challenge_methods_supported).toEqual(["S256"]);
    expect(doc.token_endpoint_auth_methods_supported).toEqual([
      "client_secret_post",
      "client_secret_basic",
      "none",
    ]);
    expect(doc.id_token_signing_alg_values_supported).toEqual(["RS256"]);
    expect(doc.subject_types_supported).toEqual(["public"]);
    expect(doc.scopes_supported).toEqual(["openid", "email", "offline_access"]);
  });

  it("does not advertise any grant the token endpoint cannot service", async () => {
    const doc = await metadata();
    expect(new Set(doc.grant_types_supported)).toEqual(
      new Set(["authorization_code", "refresh_token", "client_credentials", JWT_BEARER_GRANT])
    );
  });
});
