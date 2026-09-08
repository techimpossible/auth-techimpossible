import { describe, expect, it } from "vitest";
import { adminServiceClientHandler } from "../src/oauth/service-clients.js";
import { tokenHandler } from "../src/oauth/token.js";
import { JWT_BEARER_GRANT } from "../src/oauth/grants.js";
import { clearSigningKeyCache } from "../src/lib/crypto.js";

const ISSUER = "https://auth.example.test";
const ADMIN_TOKEN = "synthetic-admin-token";

function inMemoryKV(): KVNamespace {
  const map = new Map<string, string>();
  return {
    async get(key: string, opts?: any) {
      const v = map.get(key);
      if (v === undefined) return null;
      if (opts === "json" || (opts && opts.type === "json")) return JSON.parse(v);
      return v;
    },
    async put(key: string, value: string) {
      map.set(key, value);
    },
    async delete(key: string) {
      map.delete(key);
    },
    async list() {
      return { keys: [...map.keys()].map((name) => ({ name })), list_complete: true, cursor: "" };
    },
  } as unknown as KVNamespace;
}

function env() {
  return {
    OAUTH_KV: inMemoryKV(),
    ALLOWLIST_KV: inMemoryKV(),
    TENANT_KV: inMemoryKV(),
    ISSUER,
    ADMIN_API_TOKEN: ADMIN_TOKEN,
  } as any;
}

function adminRequest(body: unknown): Request {
  return new Request(`${ISSUER}/admin/service-clients`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${ADMIN_TOKEN}` },
    body: JSON.stringify(body),
  });
}

function tokenRequest(params: Record<string, string>): Request {
  return new Request(`${ISSUER}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params).toString(),
  });
}

describe("POST /admin/service-clients — auth method and grant cross-check", () => {
  it('refuses "none" together with the default client_credentials grant', async () => {
    // The regression that mattered: omit grant_types, pass auth method "none",
    // and the endpoint minted a client_credentials client with no secret at all.
    // Its client_id is not secret — it is the `sub` of every token it mints — so
    // anyone who saw one token could mint unlimited ones.
    const testEnv = env();
    const res = await adminServiceClientHandler(
      adminRequest({
        client_name: "ema-client",
        service_email: "ema@techimpossible.com",
        allowed_audiences: ["compliance-mcp"],
        token_endpoint_auth_method: "none",
      }),
      testEnv
    );
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error_description).toContain("client_credentials");

    const listing = await testEnv.OAUTH_KV.list();
    expect(listing.keys.filter((k: any) => k.name.startsWith("client:"))).toHaveLength(0);
  });

  it('refuses "none" with an explicit client_credentials + jwt-bearer pair', async () => {
    const res = await adminServiceClientHandler(
      adminRequest({
        client_name: "ema-client",
        service_email: "ema@techimpossible.com",
        allowed_audiences: ["compliance-mcp"],
        grant_types: ["client_credentials", JWT_BEARER_GRANT],
        token_endpoint_auth_method: "none",
      }),
      env()
    );
    expect(res.status).toBe(400);
  });

  it("no unauthenticated caller can mint a service token, because no such client exists", async () => {
    clearSigningKeyCache();
    const testEnv = env();
    const refused = await adminServiceClientHandler(
      adminRequest({
        service_email: "ema@techimpossible.com",
        allowed_audiences: ["compliance-mcp"],
        token_endpoint_auth_method: "none",
      }),
      testEnv
    );
    expect(refused.status).toBe(400);

    // A confidential client is what the operator gets instead, and it still
    // needs its secret.
    const created = await adminServiceClientHandler(
      adminRequest({
        service_email: "ema@techimpossible.com",
        allowed_audiences: ["compliance-mcp"],
      }),
      testEnv
    );
    expect(created.status).toBe(200);
    const body = (await created.json()) as any;
    expect(body.client_secret).toBeTruthy();

    const withoutSecret = await tokenHandler(
      tokenRequest({
        grant_type: "client_credentials",
        client_id: body.client_id,
        audience: "compliance-mcp",
      }),
      testEnv
    );
    expect(withoutSecret.status).toBe(401);

    const withSecret = await tokenHandler(
      tokenRequest({
        grant_type: "client_credentials",
        client_id: body.client_id,
        client_secret: body.client_secret,
        audience: "compliance-mcp",
      }),
      testEnv
    );
    expect(withSecret.status).toBe(200);
  });

  it("mints a public jwt-bearer-only client without demanding a service identity", async () => {
    // A jwt-bearer client takes its identity from the assertion and its
    // audiences from the tenant record, so requiring a service_email there would
    // invent an identity nothing uses — and RFC 7523 §3.1 lets the signed
    // assertion be the client credential.
    const res = await adminServiceClientHandler(
      adminRequest({
        client_name: "acme-ema",
        grant_types: [JWT_BEARER_GRANT],
        token_endpoint_auth_method: "none",
      }),
      env()
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.client_secret).toBeNull();
    expect(body.grant_types).toEqual([JWT_BEARER_GRANT]);
    expect(body.service_email).toBeUndefined();
  });

  it("rejects an audience this server does not mint for", async () => {
    const res = await adminServiceClientHandler(
      adminRequest({
        service_email: "ema@techimpossible.com",
        allowed_audiences: ["compliance-mcp", "some-other-mcp"],
      }),
      env()
    );
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error_description).toContain("some-other-mcp");
  });

  it("rejects a service_email that is not an address", async () => {
    const res = await adminServiceClientHandler(
      adminRequest({ service_email: "not-an-address", allowed_audiences: ["compliance-mcp"] }),
      env()
    );
    expect(res.status).toBe(400);
  });
});
