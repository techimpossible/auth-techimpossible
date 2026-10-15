import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  SignJWT,
  type JWK,
  type JWTVerifyGetKey,
} from "jose";
import { adminTenantHandler, adminTenantIssuersHandler } from "../src/tenants/admin.js";
import { createClient } from "../src/oauth/clients.js";
import { handleJwtBearerGrant, JWT_BEARER_GRANT } from "../src/oauth/jwt-bearer.js";
import { clearSigningKeyCache } from "../src/lib/crypto.js";
import { clearTenantJwksCache } from "../src/lib/tenant-jwks.js";
import { lookupIssuerOwner, putIssuerIndex } from "../src/tenants/store.js";

/**
 * Issue #15, finding 2: a tenant disabled through PUT (or any path that leaves
 * `status: "disabled"` on the record) must not keep its issuers in the
 * issuer → tenant index. A disabled tenant must neither authenticate nor squat
 * on issuers another tenant needs, and re-enabling it must go back through the
 * conflict checks instead of silently restoring its old bindings.
 */

beforeEach(() => {
  vi.spyOn(console, "log").mockImplementation(() => {});
  clearSigningKeyCache();
  clearTenantJwksCache();
});

afterEach(() => {
  vi.restoreAllMocks();
});

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
    async list(opts?: { prefix?: string }) {
      const names = [...map.keys()].filter((name) => !opts?.prefix || name.startsWith(opts.prefix));
      return { keys: names.map((name) => ({ name })), list_complete: true, cursor: "" };
    },
  } as unknown as KVNamespace;
}

const AUTH_ISSUER = "https://auth.example.test";
const ADMIN_TOKEN = "synthetic-admin-token";
const IDP_ISSUER = "https://idp.customer.example";
const IDP_JWKS = "https://idp.customer.example/jwks";
const SECOND_ISSUER = "https://idp2.customer.example";
const SECOND_JWKS = "https://idp2.customer.example/keys";
const PATH_ISSUER = "https://idp.customer.example/tenant-b";
const PATH_JWKS = "https://idp.customer.example/tenant-b/jwks";
const IDP_KID = "synthetic-idp-key-1";

function env() {
  return {
    OAUTH_KV: inMemoryKV(),
    ALLOWLIST_KV: inMemoryKV(),
    TENANT_KV: inMemoryKV(),
    ISSUER: AUTH_ISSUER,
    ADMIN_API_TOKEN: ADMIN_TOKEN,
  } as any;
}

function adminRequest(path: string, method: string, body?: unknown): Request {
  return new Request(`${AUTH_ISSUER}${path}`, {
    method,
    headers: { "content-type": "application/json", authorization: `Bearer ${ADMIN_TOKEN}` },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function emaClient(testEnv: any, clientName: string) {
  const { record } = await createClient(testEnv, {
    redirect_uris: [],
    client_name: clientName,
    token_endpoint_auth_method: "none",
    grant_types: [JWT_BEARER_GRANT],
    response_types: [],
    registration_source: "admin",
  });
  return record;
}

function tenantBody(clientId: string, overrides: Record<string, unknown> = {}) {
  return {
    display_name: "Acme Corp",
    allowed_audiences: ["compliance-mcp"],
    allowed_client_ids: [clientId],
    trusted_issuers: [{ issuer: IDP_ISSUER, jwks_uri: IDP_JWKS }],
    email_domains: ["*@customer.example"],
    ...overrides,
  };
}

async function putTenant(testEnv: any, tenantId: string, body: unknown): Promise<Response> {
  return adminTenantHandler(adminRequest(`/admin/tenants/${tenantId}`, "PUT", body), testEnv, tenantId);
}

async function installAllowlist(testEnv: any): Promise<void> {
  await testEnv.ALLOWLIST_KV.put(
    "allowlist:compliance-mcp",
    JSON.stringify({ emails: ["*@customer.example"] })
  );
}

let sharedPair: ReturnType<typeof generateKeyPair> | null = null;

async function makeIdp() {
  if (!sharedPair) sharedPair = generateKeyPair("RS256", { extractable: true });
  const { privateKey, publicKey } = await sharedPair;
  const jwk = (await exportJWK(publicKey)) as JWK;
  jwk.kid = IDP_KID;
  jwk.alg = "RS256";
  jwk.use = "sig";
  return { privateKey, keySet: createLocalJWKSet({ keys: [jwk] }) as JWTVerifyGetKey };
}

async function exchange(testEnv: any, clientId: string): Promise<Response> {
  const idp = await makeIdp();
  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({
    iss: IDP_ISSUER,
    aud: AUTH_ISSUER,
    sub: "idp-subject-0001",
    jti: `jti-${Math.random().toString(36).slice(2)}`,
    client_id: clientId,
    email: "worker@customer.example",
    email_verified: true,
    iat: now,
    exp: now + 300,
  })
    .setProtectedHeader({ alg: "RS256", kid: IDP_KID, typ: "oauth-id-jag+jwt" })
    .sign(idp.privateKey);
  const form = new URLSearchParams({ grant_type: JWT_BEARER_GRANT, client_id: clientId, assertion });
  const request = new Request(`${AUTH_ISSUER}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });
  return handleJwtBearerGrant(request, testEnv, form, { resolveKeySet: async () => idp.keySet });
}

describe("tenant admin — disabling a tenant withdraws its issuer claims", () => {
  it("PUT status=disabled removes every issuer from the index and stops authentication", async () => {
    const testEnv = env();
    await installAllowlist(testEnv);
    const client = await emaClient(testEnv, "acme-ema");

    const created = await putTenant(
      testEnv,
      "acme",
      tenantBody(client.clientId, {
        trusted_issuers: [
          { issuer: IDP_ISSUER, jwks_uri: IDP_JWKS },
          { issuer: SECOND_ISSUER, jwks_uri: SECOND_JWKS },
        ],
      })
    );
    expect(created.status).toBe(200);
    expect((await exchange(testEnv, client.clientId)).status).toBe(200);

    const disabled = await putTenant(
      testEnv,
      "acme",
      tenantBody(client.clientId, {
        status: "disabled",
        trusted_issuers: [
          { issuer: IDP_ISSUER, jwks_uri: IDP_JWKS },
          { issuer: SECOND_ISSUER, jwks_uri: SECOND_JWKS },
        ],
      })
    );
    expect(disabled.status).toBe(200);
    const pub = ((await disabled.json()) as any).tenant;
    expect(pub.status).toBe("disabled");
    // The record keeps its issuers for audit and a later re-enable…
    expect(pub.trusted_issuers.map((ti: any) => ti.issuer)).toEqual([IDP_ISSUER, SECOND_ISSUER]);
    // …but none of them is bound in the index any more.
    expect(await lookupIssuerOwner(testEnv, IDP_ISSUER)).toBeNull();
    expect(await lookupIssuerOwner(testEnv, SECOND_ISSUER)).toBeNull();

    const refused = await exchange(testEnv, client.clientId);
    expect(refused.status).toBe(400);
    expect(((await refused.json()) as any).error).toBe("invalid_grant");
  });

  it("creating a tenant as disabled indexes nothing", async () => {
    const testEnv = env();
    const client = await emaClient(testEnv, "acme-ema");
    const res = await putTenant(testEnv, "acme", tenantBody(client.clientId, { status: "disabled" }));
    expect(res.status).toBe(200);
    expect(await lookupIssuerOwner(testEnv, IDP_ISSUER)).toBeNull();
  });

  it("a tenant disabled by PUT no longer blocks another tenant from claiming its issuer", async () => {
    const testEnv = env();
    const acme = await emaClient(testEnv, "acme-ema");
    const beta = await emaClient(testEnv, "beta-ema");

    expect((await putTenant(testEnv, "acme", tenantBody(acme.clientId))).status).toBe(200);
    expect(
      (await putTenant(testEnv, "acme", tenantBody(acme.clientId, { status: "disabled" }))).status
    ).toBe(200);

    const claimed = await putTenant(testEnv, "beta", tenantBody(beta.clientId));
    expect(claimed.status).toBe(200);
    expect(await lookupIssuerOwner(testEnv, IDP_ISSUER)).toBe("beta");
  });

  it("a disabled tenant's whole-host issuer no longer blocks a path-scoped issuer on that host", async () => {
    const testEnv = env();
    const acme = await emaClient(testEnv, "acme-ema");
    const beta = await emaClient(testEnv, "beta-ema");

    expect((await putTenant(testEnv, "acme", tenantBody(acme.clientId))).status).toBe(200);
    const pathScoped = tenantBody(beta.clientId, {
      trusted_issuers: [{ issuer: PATH_ISSUER, jwks_uri: PATH_JWKS }],
    });
    // While acme is active, its whole-host issuer owns the host.
    expect((await putTenant(testEnv, "beta", pathScoped)).status).toBe(409);

    expect(
      (await putTenant(testEnv, "acme", tenantBody(acme.clientId, { status: "disabled" }))).status
    ).toBe(200);
    expect((await putTenant(testEnv, "beta", pathScoped)).status).toBe(200);
    expect(await lookupIssuerOwner(testEnv, PATH_ISSUER)).toBe("beta");
  });

  it("re-enabling re-runs the conflict check instead of silently restoring the index", async () => {
    const testEnv = env();
    await installAllowlist(testEnv);
    const acme = await emaClient(testEnv, "acme-ema");
    const beta = await emaClient(testEnv, "beta-ema");

    await putTenant(testEnv, "acme", tenantBody(acme.clientId));
    await putTenant(testEnv, "acme", tenantBody(acme.clientId, { status: "disabled" }));
    expect((await putTenant(testEnv, "beta", tenantBody(beta.clientId))).status).toBe(200);

    const reEnabled = await putTenant(testEnv, "acme", tenantBody(acme.clientId, { status: "active" }));
    expect(reEnabled.status).toBe(409);
    expect(((await reEnabled.json()) as any).error).toBe("issuer_conflict");
    expect(await lookupIssuerOwner(testEnv, IDP_ISSUER)).toBe("beta");
    expect((await exchange(testEnv, acme.clientId)).status).toBe(400);
  });

  it("re-enabling with no conflict re-binds the issuers and authentication resumes", async () => {
    const testEnv = env();
    await installAllowlist(testEnv);
    const acme = await emaClient(testEnv, "acme-ema");

    await putTenant(testEnv, "acme", tenantBody(acme.clientId));
    await putTenant(testEnv, "acme", tenantBody(acme.clientId, { status: "disabled" }));
    expect(await lookupIssuerOwner(testEnv, IDP_ISSUER)).toBeNull();

    expect((await putTenant(testEnv, "acme", tenantBody(acme.clientId))).status).toBe(200);
    expect(await lookupIssuerOwner(testEnv, IDP_ISSUER)).toBe("acme");
    expect((await exchange(testEnv, acme.clientId)).status).toBe(200);
  });

  it("adding an issuer to a disabled tenant does not index any of its issuers", async () => {
    const testEnv = env();
    const acme = await emaClient(testEnv, "acme-ema");

    await putTenant(testEnv, "acme", tenantBody(acme.clientId));
    await adminTenantHandler(adminRequest("/admin/tenants/acme", "DELETE"), testEnv, "acme");

    const added = await adminTenantIssuersHandler(
      adminRequest("/admin/tenants/acme/issuers", "POST", { issuer: SECOND_ISSUER, jwks_uri: SECOND_JWKS }),
      testEnv,
      "acme"
    );
    expect(added.status).toBe(200);
    expect(((await added.json()) as any).tenant.status).toBe("disabled");
    expect(await lookupIssuerOwner(testEnv, IDP_ISSUER)).toBeNull();
    expect(await lookupIssuerOwner(testEnv, SECOND_ISSUER)).toBeNull();
  });

  it("removing an issuer from a disabled tenant does not re-index the rest", async () => {
    const testEnv = env();
    const acme = await emaClient(testEnv, "acme-ema");

    await putTenant(
      testEnv,
      "acme",
      tenantBody(acme.clientId, {
        trusted_issuers: [
          { issuer: IDP_ISSUER, jwks_uri: IDP_JWKS },
          { issuer: SECOND_ISSUER, jwks_uri: SECOND_JWKS },
        ],
      })
    );
    await adminTenantHandler(adminRequest("/admin/tenants/acme", "DELETE"), testEnv, "acme");

    const removed = await adminTenantIssuersHandler(
      adminRequest("/admin/tenants/acme/issuers", "DELETE", { issuer: SECOND_ISSUER }),
      testEnv,
      "acme"
    );
    expect(removed.status).toBe(200);
    expect(await lookupIssuerOwner(testEnv, IDP_ISSUER)).toBeNull();
    expect(await lookupIssuerOwner(testEnv, SECOND_ISSUER)).toBeNull();
  });

  it("a stale index entry left by a disabled tenant does not count as a conflict", async () => {
    // A crash between writing the disabled record and unbinding its issuers, or
    // an entry written before this fix, leaves the index pointing at a disabled
    // tenant. That entry cannot authenticate, so it must not block anyone either.
    const testEnv = env();
    const acme = await emaClient(testEnv, "acme-ema");
    const beta = await emaClient(testEnv, "beta-ema");

    await putTenant(testEnv, "acme", tenantBody(acme.clientId, { status: "disabled" }));
    await putIssuerIndex(testEnv, IDP_ISSUER, "acme");

    expect((await putTenant(testEnv, "beta", tenantBody(beta.clientId))).status).toBe(200);
    expect(await lookupIssuerOwner(testEnv, IDP_ISSUER)).toBe("beta");
  });
});
