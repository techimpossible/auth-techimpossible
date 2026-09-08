import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
  SignJWT,
  type JWK,
  type JWTPayload,
  type JWTVerifyGetKey,
} from "jose";
import type { TenantRecord } from "../src/env.js";
import { handleJwtBearerGrant, JWT_BEARER_GRANT } from "../src/oauth/jwt-bearer.js";
import { tokenHandler } from "../src/oauth/token.js";
import { createClient } from "../src/oauth/clients.js";
import { clearSigningKeyCache, getSigningKey } from "../src/lib/crypto.js";
import { clearTenantJwksCache } from "../src/lib/tenant-jwks.js";
import { putIssuerIndex, putTenant } from "../src/tenants/store.js";

/**
 * Every EMA decision writes one structured line to stdout. Capture it instead of
 * letting it flood the test output — one test below asserts on its contents.
 */
const logLines: string[] = [];

beforeEach(() => {
  logLines.length = 0;
  vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    logLines.push(args.map((arg) => String(arg)).join(" "));
  });
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
    async list() {
      return { keys: [...map.keys()].map((name) => ({ name })), list_complete: true, cursor: "" };
    },
  } as unknown as KVNamespace;
}

const AUTH_ISSUER = "https://auth.example.test";
const IDP_ISSUER = "https://idp.customer.example";
const IDP_JWKS = "https://idp.customer.example/jwks";
const OTHER_IDP_ISSUER = "https://idp.other.example";
const IDP_KID = "synthetic-idp-key-1";

function env() {
  return {
    OAUTH_KV: inMemoryKV(),
    ALLOWLIST_KV: inMemoryKV(),
    TENANT_KV: inMemoryKV(),
    ISSUER: AUTH_ISSUER,
    ADMIN_API_TOKEN: "synthetic-admin-token",
  } as any;
}

/**
 * RSA keygen is the slowest thing in this file, so the well-behaved IdP reuses
 * one ephemeral pair. `fresh` mints a genuinely different pair, which is what
 * the bad-signature test needs (same kid, different key).
 */
let sharedPair: ReturnType<typeof generateKeyPair> | null = null;

function keyPair(fresh: boolean) {
  if (fresh) return generateKeyPair("RS256", { extractable: true });
  if (!sharedPair) sharedPair = generateKeyPair("RS256", { extractable: true });
  return sharedPair;
}

/**
 * A synthetic customer identity provider: an ephemeral RS256 key pair plus the
 * local key set that stands in for the remote JWKS fetch. No key material here
 * is real, and none of it is ever written to disk.
 */
async function makeIdp(kid = IDP_KID, fresh = false) {
  const { privateKey, publicKey } = await keyPair(fresh);
  const jwk = (await exportJWK(publicKey)) as JWK;
  jwk.kid = kid;
  jwk.alg = "RS256";
  jwk.use = "sig";
  const jwks = { keys: [jwk] };
  return { privateKey, kid, jwks, keySet: createLocalJWKSet(jwks) as JWTVerifyGetKey };
}

type Idp = Awaited<ReturnType<typeof makeIdp>>;

/** A resolveKeySet dep that always returns this IdP's key set, and records calls. */
function keySetDep(idp: Idp) {
  const calls: Array<{ issuer: string; jwksUri: string }> = [];
  const resolveKeySet = async (issuer: string, jwksUri: string) => {
    calls.push({ issuer, jwksUri });
    return idp.keySet;
  };
  return { resolveKeySet, calls };
}

type AssertionOptions = {
  iss?: string;
  aud?: string | string[] | null;
  sub?: string | null;
  jti?: string | null;
  clientId?: string | null;
  email?: string | null;
  iat?: number;
  exp?: number;
  typ?: string | null;
  extraClaims?: Record<string, unknown>;
  extraHeader?: Record<string, unknown>;
};

/**
 * Build an ID-JAG shaped assertion. Every claim is individually removable so a
 * test can express exactly one defect at a time.
 */
async function signAssertion(idp: Idp, clientId: string, opts: AssertionOptions = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload: JWTPayload = {
    iss: opts.iss ?? IDP_ISSUER,
    iat: opts.iat ?? now,
    exp: opts.exp ?? now + 300,
    email_verified: true,
    ...(opts.extraClaims ?? {}),
  };
  if (opts.aud !== null) payload.aud = opts.aud ?? AUTH_ISSUER;
  if (opts.sub !== null) payload.sub = opts.sub ?? "idp-subject-0001";
  if (opts.jti !== null) payload.jti = opts.jti ?? `jti-${Math.random().toString(36).slice(2)}`;
  if (opts.clientId !== null) payload.client_id = opts.clientId ?? clientId;
  if (opts.email !== null) payload.email = opts.email ?? "worker@customer.example";

  const header: Record<string, unknown> = { alg: "RS256", kid: idp.kid, ...(opts.extraHeader ?? {}) };
  if (opts.typ !== null) header.typ = opts.typ ?? "oauth-id-jag+jwt";

  return new SignJWT(payload).setProtectedHeader(header as any).sign(idp.privateKey);
}

function tenantRecord(overrides: Partial<TenantRecord> = {}): TenantRecord {
  const now = Math.floor(Date.now() / 1000);
  return {
    tenantId: "acme",
    displayName: "Acme Corp",
    status: "active",
    trustedIssuers: [{ issuer: IDP_ISSUER, jwksUri: IDP_JWKS, addedAt: now }],
    allowedAudiences: ["compliance-mcp"],
    allowedClientIds: [],
    // Mandatory namespace binding: this tenant may only assert its own domain.
    emailDomains: ["*@customer.example"],
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

/** Register the tenant record AND the issuer -> tenant reverse index. */
async function installTenant(testEnv: any, record: TenantRecord): Promise<void> {
  await putTenant(testEnv, record);
  for (const ti of record.trustedIssuers) {
    await putIssuerIndex(testEnv, ti.issuer, record.tenantId);
  }
}

/**
 * The per-audience ALLOWLIST_KV control. Every grant that mints a user identity
 * passes it, EMA included, and it is what an operator revokes unilaterally.
 */
async function installAllowlist(
  testEnv: any,
  emails: string[] = ["*@customer.example"]
): Promise<void> {
  for (const aud of ["compliance-mcp", "basecamp-mcp"]) {
    await testEnv.ALLOWLIST_KV.put(`allowlist:${aud}`, JSON.stringify({ emails }));
  }
}

/** An admin-created public EMA client (registrationSource "admin", auth method "none"). */
async function emaClient(testEnv: any, clientName = "claude-ema") {
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

function bearerForm(params: Record<string, string>): URLSearchParams {
  return new URLSearchParams({ grant_type: JWT_BEARER_GRANT, ...params });
}

/** The reason codes of every ema.token decision logged so far in this test. */
function reasonCodes(): string[] {
  return logLines
    .map((line) => {
      try {
        return JSON.parse(line) as { evt?: string; reason_code?: string };
      } catch {
        return {};
      }
    })
    .filter((entry) => entry.evt === "ema.token")
    .map((entry) => entry.reason_code ?? "");
}

function tokenRequest(form: URLSearchParams): Request {
  return new Request(`${AUTH_ISSUER}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });
}

/** Full EMA fixture: env, admin client, active tenant, synthetic IdP. */
async function fixture(tenantOverrides: Partial<TenantRecord> = {}) {
  clearSigningKeyCache();
  clearTenantJwksCache();
  const testEnv = env();
  const client = await emaClient(testEnv);
  const idp = await makeIdp();
  const record = tenantRecord({ allowedClientIds: [client.clientId], ...tenantOverrides });
  await installTenant(testEnv, record);
  await installAllowlist(testEnv);
  return { env: testEnv, client, idp, tenant: record };
}

async function verifyMinted(testEnv: any, accessToken: string, audience: string) {
  const material = await getSigningKey(testEnv.OAUTH_KV);
  const publicKey = await importJWK(material.publicJwk, "RS256");
  const { payload } = await jwtVerify(accessToken, publicKey, {
    issuer: AUTH_ISSUER,
    audience,
    algorithms: ["RS256"],
  });
  return payload;
}

describe("jwt-bearer grant — happy path", () => {
  it("mints an access token for a valid assertion from an allowlisted issuer", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const dep = keySetDep(idp);

    const form = bearerForm({ client_id: client.clientId, scope: "openid email" });
    form.set("assertion", await signAssertion(idp, client.clientId));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, dep);
    expect(res.status).toBe(200);

    const body = (await res.json()) as any;
    expect(body.token_type).toBe("Bearer");
    expect(body.scope).toBe("openid email");
    // The customer's IdP holds the long-lived credential: we never mint one.
    expect(body.refresh_token).toBeUndefined();
    expect(body.id_token).toBeUndefined();

    const payload = await verifyMinted(testEnv, body.access_token, "compliance-mcp");
    expect(payload.iss).toBe(AUTH_ISSUER);
    expect(payload.aud).toBe("compliance-mcp");
    // Namespaced so a customer IdP subject can never collide with a Google one.
    expect(payload.sub).toBe("ema:acme:idp-subject-0001");
    expect(payload.email).toBe("worker@customer.example");
    expect(payload.email_verified).toBe(true);
    expect(payload.tenant_id).toBe("acme");
    expect(payload.roles).toEqual([]);

    // The JWKS was resolved from the tenant record, not from the assertion.
    expect(dep.calls).toEqual([{ issuer: IDP_ISSUER, jwksUri: IDP_JWKS }]);
  });

  it("asserts email_verified from server policy, not from the assertion", async () => {
    // The party being vetted must not get to set a trust signal that resource
    // servers gate on. We verified the address ourselves: signed by a bound
    // issuer, inside the tenant's email_domains, present on allowlist:<aud>.
    const { env: testEnv, client, idp } = await fixture();
    const form = bearerForm({ client_id: client.clientId });
    form.set(
      "assertion",
      await signAssertion(idp, client.clientId, { extraClaims: { email_verified: false } })
    );

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(200);
    const payload = await verifyMinted(testEnv, ((await res.json()) as any).access_token, "compliance-mcp");
    expect(payload.email_verified).toBe(true);
  });

  it("reads the email from a tenant-configured subject_email_claim", async () => {
    const { env: testEnv, client, idp } = await fixture({ subjectEmailClaim: "upn" });
    const form = bearerForm({ client_id: client.clientId });
    form.set(
      "assertion",
      await signAssertion(idp, client.clientId, {
        email: null,
        extraClaims: { upn: "person@customer.example" },
      })
    );

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(200);
    const payload = await verifyMinted(testEnv, ((await res.json()) as any).access_token, "compliance-mcp");
    expect(payload.email).toBe("person@customer.example");
  });

  it("clamps the access token TTL to the assertion lifetime, floor 60 and ceiling 3600", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const now = Math.floor(Date.now() / 1000);

    const shortForm = bearerForm({ client_id: client.clientId });
    shortForm.set("assertion", await signAssertion(idp, client.clientId, { exp: now + 30 }));
    const shortRes = await handleJwtBearerGrant(
      tokenRequest(shortForm),
      testEnv,
      shortForm,
      keySetDep(idp)
    );
    expect(shortRes.status).toBe(200);
    expect(((await shortRes.json()) as any).expires_in).toBe(60);

    const longForm = bearerForm({ client_id: client.clientId });
    longForm.set("assertion", await signAssertion(idp, client.clientId, { exp: now + 3600 }));
    const longRes = await handleJwtBearerGrant(
      tokenRequest(longForm),
      testEnv,
      longForm,
      keySetDep(idp)
    );
    expect(longRes.status).toBe(200);
    const longExpiry = ((await longRes.json()) as any).expires_in;
    expect(longExpiry).toBeLessThanOrEqual(3600);
    expect(longExpiry).toBeGreaterThan(3590);
  });

  it("is reachable through tokenHandler's grant dispatch", async () => {
    // tokenHandler does not take deps, so this exercises the real dispatch path
    // and stops at the pre-network trusted-issuer check.
    const { env: testEnv, client, idp } = await fixture();
    const form = bearerForm({ client_id: client.clientId });
    form.set("assertion", await signAssertion(idp, client.clientId, { iss: OTHER_IDP_ISSUER }));

    const res = await tokenHandler(tokenRequest(form), testEnv);
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
  });
});

describe("jwt-bearer grant — trusted issuer allowlist (the core control)", () => {
  it("rejects an assertion whose iss is not allowlisted for the tenant, despite a valid signature", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const dep = keySetDep(idp);

    // Same key, same client, same tenant — only the issuer differs.
    const form = bearerForm({ client_id: client.clientId });
    form.set("assertion", await signAssertion(idp, client.clientId, { iss: OTHER_IDP_ISSUER }));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, dep);
    expect(res.status).toBe(400);
    const body = (await res.json()) as any;
    expect(body.error).toBe("invalid_grant");
    // The rejection happens before any key resolution: no SSRF primitive, and no
    // oracle telling the caller which issuers exist.
    expect(dep.calls).toEqual([]);
    expect(body.error_description).toBe("assertion could not be validated");
  });

  it("proves that rejected assertion was otherwise valid: allowlisting its issuer accepts it", async () => {
    const { env: testEnv, client, idp, tenant } = await fixture();
    const assertion = await signAssertion(idp, client.clientId, { iss: OTHER_IDP_ISSUER });

    const before = bearerForm({ client_id: client.clientId });
    before.set("assertion", assertion);
    const rejected = await handleJwtBearerGrant(
      tokenRequest(before),
      testEnv,
      before,
      keySetDep(idp)
    );
    expect(rejected.status).toBe(400);

    await installTenant(testEnv, {
      ...tenant,
      trustedIssuers: [
        ...tenant.trustedIssuers,
        { issuer: OTHER_IDP_ISSUER, jwksUri: `${OTHER_IDP_ISSUER}/jwks`, addedAt: 0 },
      ],
    });

    const after = bearerForm({ client_id: client.clientId });
    after.set("assertion", assertion);
    const accepted = await handleJwtBearerGrant(
      tokenRequest(after),
      testEnv,
      after,
      keySetDep(idp)
    );
    expect(accepted.status).toBe(200);
  });

  it("rejects a client that is not in the tenant's allowed_client_ids", async () => {
    const { env: testEnv, idp } = await fixture();
    // Second admin client, valid in its own right, but bound to no tenant.
    const stranger = await emaClient(testEnv, "stranger");
    const dep = keySetDep(idp);

    const form = bearerForm({ client_id: stranger.clientId });
    form.set("assertion", await signAssertion(idp, stranger.clientId));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, dep);
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
    expect(dep.calls).toEqual([]);
  });

  it("rejects an assertion for a disabled tenant", async () => {
    const { env: testEnv, client, idp, tenant } = await fixture();
    await putTenant(testEnv, { ...tenant, status: "disabled" });

    const form = bearerForm({ client_id: client.clientId });
    form.set("assertion", await signAssertion(idp, client.clientId));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
  });

  it("rejects a stale index entry pointing at a tenant that no longer trusts the issuer", async () => {
    const { env: testEnv, client, idp, tenant } = await fixture();
    // Simulate a crash between the tenant write and the index cleanup.
    await putTenant(testEnv, {
      ...tenant,
      trustedIssuers: [{ issuer: OTHER_IDP_ISSUER, jwksUri: `${OTHER_IDP_ISSUER}/jwks`, addedAt: 0 }],
    });

    const form = bearerForm({ client_id: client.clientId });
    form.set("assertion", await signAssertion(idp, client.clientId));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
  });

  it("accepts a trailing-slash iss, normalizing both sides of the comparison", async () => {
    // Auth0 and every OIDC issuer that publishes a trailing slash emits it at
    // token time. The lookup normalizes, so the verification must normalize too
    // — otherwise such a tenant registers successfully and can never
    // authenticate.
    const { env: testEnv, client, idp } = await fixture();
    const dep = keySetDep(idp);
    const form = bearerForm({ client_id: client.clientId });
    form.set("assertion", await signAssertion(idp, client.clientId, { iss: `${IDP_ISSUER}/` }));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, dep);
    expect(res.status).toBe(200);
    expect(dep.calls).toEqual([{ issuer: IDP_ISSUER, jwksUri: IDP_JWKS }]);
    const payload = await verifyMinted(testEnv, ((await res.json()) as any).access_token, "compliance-mcp");
    expect(payload.sub).toBe("ema:acme:idp-subject-0001");
  });

  it("still refuses an iss that normalizes to a different issuer", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const form = bearerForm({ client_id: client.clientId });
    form.set(
      "assertion",
      await signAssertion(idp, client.clientId, { iss: `${IDP_ISSUER}/tenant-two` })
    );

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
  });
});

describe("jwt-bearer grant — assertion validation", () => {
  it("rejects a bad signature", async () => {
    const { env: testEnv, client, idp } = await fixture();
    // Different private key, same kid, so jose reaches signature verification.
    const attacker = await makeIdp(IDP_KID, true);

    const form = bearerForm({ client_id: client.clientId });
    form.set("assertion", await signAssertion(attacker, client.clientId));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
  });

  it("rejects an expired assertion", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const now = Math.floor(Date.now() / 1000);

    const form = bearerForm({ client_id: client.clientId });
    // Past the 60s clock tolerance, and iat still inside the 300s max age.
    form.set("assertion", await signAssertion(idp, client.clientId, { iat: now - 200, exp: now - 120 }));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
  });

  it("rejects an assertion older than the tenant's max assertion age", async () => {
    const { env: testEnv, client, idp } = await fixture({ maxAssertionAgeSeconds: 60 });
    const now = Math.floor(Date.now() / 1000);

    const form = bearerForm({ client_id: client.clientId });
    form.set("assertion", await signAssertion(idp, client.clientId, { iat: now - 600, exp: now + 600 }));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
  });

  it("rejects an assertion with no sub", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const form = bearerForm({ client_id: client.clientId });
    form.set("assertion", await signAssertion(idp, client.clientId, { sub: null }));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
  });

  it("rejects an assertion minted for a different relying party (wrong aud)", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const form = bearerForm({ client_id: client.clientId });
    form.set("assertion", await signAssertion(idp, client.clientId, { aud: "https://someone-else.example" }));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
  });

  it("rejects an assertion with no aud at all", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const form = bearerForm({ client_id: client.clientId });
    form.set("assertion", await signAssertion(idp, client.clientId, { aud: null }));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
  });

  it("rejects an assertion with no jti", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const form = bearerForm({ client_id: client.clientId });
    form.set("assertion", await signAssertion(idp, client.clientId, { jti: null }));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
  });

  it("rejects an assertion whose client_id claim names a different client", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const form = bearerForm({ client_id: client.clientId });
    form.set("assertion", await signAssertion(idp, client.clientId, { clientId: "ti-someone-else" }));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
  });

  it("rejects an assertion whose lifetime exceeds one hour", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const now = Math.floor(Date.now() / 1000);
    const form = bearerForm({ client_id: client.clientId });
    form.set("assertion", await signAssertion(idp, client.clientId, { iat: now, exp: now + 7200 }));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
  });

  it("rejects a symmetric algorithm before any key is resolved", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const dep = keySetDep(idp);
    const now = Math.floor(Date.now() / 1000);

    const hs256 = await new SignJWT({
      iss: IDP_ISSUER,
      aud: AUTH_ISSUER,
      sub: "idp-subject-0001",
      jti: "jti-hs256",
      client_id: client.clientId,
      email: "worker@customer.example",
      iat: now,
      exp: now + 300,
    })
      .setProtectedHeader({ alg: "HS256", typ: "oauth-id-jag+jwt" })
      .sign(new Uint8Array(32).fill(7));

    const form = bearerForm({ client_id: client.clientId });
    form.set("assertion", hs256);

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, dep);
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
    expect(dep.calls).toEqual([]);
  });

  it("rejects a header that supplies its own key source (jku / jwk / x5u)", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const dep = keySetDep(idp);

    for (const header of [
      { jku: "https://evil.example/jwks" },
      { jwk: idp.jwks.keys[0] },
      { x5u: "https://evil.example/chain.pem" },
    ]) {
      const form = bearerForm({ client_id: client.clientId });
      form.set("assertion", await signAssertion(idp, client.clientId, { extraHeader: header }));
      const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, dep);
      expect(res.status).toBe(400);
      expect(((await res.json()) as any).error).toBe("invalid_grant");
    }
    expect(dep.calls).toEqual([]);
  });

  it("rejects a legacy typ unless the tenant opts in", async () => {
    const strict = await fixture();
    const strictForm = bearerForm({ client_id: strict.client.clientId });
    strictForm.set("assertion", await signAssertion(strict.idp, strict.client.clientId, { typ: "JWT" }));
    const rejected = await handleJwtBearerGrant(
      tokenRequest(strictForm),
      strict.env,
      strictForm,
      keySetDep(strict.idp)
    );
    expect(rejected.status).toBe(400);

    const lenient = await fixture({ allowLegacyTyp: true });
    const lenientForm = bearerForm({ client_id: lenient.client.clientId });
    lenientForm.set("assertion", await signAssertion(lenient.idp, lenient.client.clientId, { typ: "JWT" }));
    const accepted = await handleJwtBearerGrant(
      tokenRequest(lenientForm),
      lenient.env,
      lenientForm,
      keySetDep(lenient.idp)
    );
    expect(accepted.status).toBe(200);
  });

  it("rejects a malformed assertion", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const form = bearerForm({ client_id: client.clientId });
    form.set("assertion", "not.a.jwt");

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
  });

  it("requires an assertion and bounds its size before parsing", async () => {
    const { env: testEnv, client, idp } = await fixture();

    const missing = bearerForm({ client_id: client.clientId });
    const missingRes = await handleJwtBearerGrant(
      tokenRequest(missing),
      testEnv,
      missing,
      keySetDep(idp)
    );
    expect(missingRes.status).toBe(400);
    expect(((await missingRes.json()) as any).error).toBe("invalid_request");

    const huge = bearerForm({ client_id: client.clientId });
    huge.set("assertion", "a".repeat(9000));
    const hugeRes = await handleJwtBearerGrant(tokenRequest(huge), testEnv, huge, keySetDep(idp));
    expect(hugeRes.status).toBe(400);
    expect(((await hugeRes.json()) as any).error).toBe("invalid_grant");
  });

  it("dampens replay of the same jti", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const assertion = await signAssertion(idp, client.clientId, { jti: "jti-replayed-once" });

    const first = bearerForm({ client_id: client.clientId });
    first.set("assertion", assertion);
    const firstRes = await handleJwtBearerGrant(
      tokenRequest(first),
      testEnv,
      first,
      keySetDep(idp)
    );
    expect(firstRes.status).toBe(200);

    const second = bearerForm({ client_id: client.clientId });
    second.set("assertion", assertion);
    const secondRes = await handleJwtBearerGrant(
      tokenRequest(second),
      testEnv,
      second,
      keySetDep(idp)
    );
    expect(secondRes.status).toBe(400);
    expect(((await secondRes.json()) as any).error).toBe("invalid_grant");
  });

  it("returns 503 rather than invalid_grant when the customer IdP is unreachable", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const form = bearerForm({ client_id: client.clientId });
    form.set("assertion", await signAssertion(idp, client.clientId));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, {
      resolveKeySet: async () => {
        const err = new Error("jwks timed out") as Error & { code?: string };
        err.code = "ERR_JWKS_TIMEOUT";
        throw err;
      },
    });
    expect(res.status).toBe(503);
    expect(res.headers.get("retry-after")).toBe("5");
    expect(((await res.json()) as any).error).toBe("temporarily_unavailable");
  });
});

describe("jwt-bearer grant — client authentication and authorization", () => {
  it("rejects an unknown client_id", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const form = bearerForm({ client_id: "ti-does-not-exist" });
    form.set("assertion", await signAssertion(idp, client.clientId));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(401);
    expect(((await res.json()) as any).error).toBe("invalid_client");
  });

  it("requires a client_id", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const form = new URLSearchParams({ grant_type: JWT_BEARER_GRANT });
    form.set("assertion", await signAssertion(idp, client.clientId));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(401);
    expect(((await res.json()) as any).error).toBe("invalid_client");
  });

  it("rejects a wrong client_secret on a confidential EMA client", async () => {
    clearSigningKeyCache();
    const testEnv = env();
    const idp = await makeIdp();
    const { record } = await createClient(testEnv, {
      redirect_uris: [],
      client_name: "confidential-ema",
      grant_types: [JWT_BEARER_GRANT],
      registration_source: "admin",
    });
    await installTenant(testEnv, tenantRecord({ allowedClientIds: [record.clientId] }));

    const form = bearerForm({ client_id: record.clientId, client_secret: "wrong" });
    form.set("assertion", await signAssertion(idp, record.clientId));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(401);
    expect(((await res.json()) as any).error).toBe("invalid_client");
  });

  it("rejects a client that does not carry the jwt-bearer grant", async () => {
    clearSigningKeyCache();
    const testEnv = env();
    const idp = await makeIdp();
    const { record } = await createClient(testEnv, {
      redirect_uris: [],
      client_name: "code-only",
      token_endpoint_auth_method: "none",
      registration_source: "admin",
    });
    await installTenant(testEnv, tenantRecord({ allowedClientIds: [record.clientId] }));

    const form = bearerForm({ client_id: record.clientId });
    form.set("assertion", await signAssertion(idp, record.clientId));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("unauthorized_client");
  });

  it("rejects a self-registered (DCR) client even when it asks for the jwt-bearer grant", async () => {
    clearSigningKeyCache();
    const testEnv = env();
    const idp = await makeIdp();
    // /register is unauthenticated and echoes grant_types back, so provenance —
    // not the client's own claim — is the gate.
    const { record } = await createClient(testEnv, {
      redirect_uris: [],
      client_name: "self-registered",
      token_endpoint_auth_method: "none",
      grant_types: [JWT_BEARER_GRANT],
    });
    expect(record.registrationSource).toBe("dcr");
    await installTenant(testEnv, tenantRecord({ allowedClientIds: [record.clientId] }));

    const form = bearerForm({ client_id: record.clientId });
    form.set("assertion", await signAssertion(idp, record.clientId));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("unauthorized_client");
  });
});

describe("jwt-bearer grant — audience binding (RFC 8707 resource)", () => {
  it("mints for the tenant's only audience when resource is absent", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const form = bearerForm({ client_id: client.clientId });
    form.set("assertion", await signAssertion(idp, client.clientId));
    expect(form.get("resource")).toBeNull();

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(200);
    const payload = await verifyMinted(testEnv, ((await res.json()) as any).access_token, "compliance-mcp");
    expect(payload.aud).toBe("compliance-mcp");
  });

  it("serves a request with no resource indicator on a multi-audience tenant", async () => {
    // Some IdP configurations cannot forward a resource indicator at all, and
    // the EMA contract requires the request to be served either way. The admin
    // decides which audience that means; the first allowed audience by default.
    const { env: testEnv, client, idp } = await fixture({
      allowedAudiences: ["compliance-mcp", "basecamp-mcp"],
    });
    const form = bearerForm({ client_id: client.clientId });
    form.set("assertion", await signAssertion(idp, client.clientId));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(200);
    const payload = await verifyMinted(testEnv, ((await res.json()) as any).access_token, "compliance-mcp");
    expect(payload.aud).toBe("compliance-mcp");
  });

  it("honours the tenant's default_audience when no resource indicator is present", async () => {
    const { env: testEnv, client, idp } = await fixture({
      allowedAudiences: ["compliance-mcp", "basecamp-mcp"],
      defaultAudience: "basecamp-mcp",
    });
    const form = bearerForm({ client_id: client.clientId });
    form.set("assertion", await signAssertion(idp, client.clientId));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(200);
    const payload = await verifyMinted(testEnv, ((await res.json()) as any).access_token, "basecamp-mcp");
    expect(payload.aud).toBe("basecamp-mcp");
  });

  it("binds the audience from a resource parameter when present", async () => {
    const { env: testEnv, client, idp } = await fixture({
      allowedAudiences: ["compliance-mcp", "basecamp-mcp"],
    });
    const form = bearerForm({
      client_id: client.clientId,
      resource: "https://basecamp-mcp.techimpossible.com/mcp",
    });
    form.set("assertion", await signAssertion(idp, client.clientId));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(200);
    const payload = await verifyMinted(testEnv, ((await res.json()) as any).access_token, "basecamp-mcp");
    expect(payload.aud).toBe("basecamp-mcp");
  });

  it("accepts a bare audience string as the resource value", async () => {
    const { env: testEnv, client, idp } = await fixture({
      allowedAudiences: ["compliance-mcp", "basecamp-mcp"],
    });
    const form = bearerForm({ client_id: client.clientId, resource: "basecamp-mcp" });
    form.set("assertion", await signAssertion(idp, client.clientId));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(200);
    const payload = await verifyMinted(testEnv, ((await res.json()) as any).access_token, "basecamp-mcp");
    expect(payload.aud).toBe("basecamp-mcp");
  });

  it("rejects a resource the tenant is not allowed to reach", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const form = bearerForm({
      client_id: client.clientId,
      resource: "https://basecamp-mcp.techimpossible.com/mcp",
    });
    form.set("assertion", await signAssertion(idp, client.clientId));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    // RFC 6749 §5.2: token endpoint errors are HTTP 400 unless a spec says
    // otherwise, and RFC 8707 does not for invalid_target.
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_target");
  });

  it("rejects an unrecognised resource URL instead of inventing an audience from its hostname", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const form = bearerForm({ client_id: client.clientId, resource: "https://evil.example/mcp" });
    form.set("assertion", await signAssertion(idp, client.clientId));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_target");
  });

  it("lets the IdP-signed resource claim bind the audience on its own", async () => {
    const { env: testEnv, client, idp } = await fixture({
      allowedAudiences: ["compliance-mcp", "basecamp-mcp"],
    });
    const form = bearerForm({ client_id: client.clientId });
    form.set(
      "assertion",
      await signAssertion(idp, client.clientId, {
        extraClaims: { resource: "https://basecamp-mcp.techimpossible.com/mcp" },
      })
    );

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(200);
    const payload = await verifyMinted(testEnv, ((await res.json()) as any).access_token, "basecamp-mcp");
    expect(payload.aud).toBe("basecamp-mcp");
  });

  it("accepts a resource parameter that agrees with the resource claim", async () => {
    const { env: testEnv, client, idp } = await fixture({
      allowedAudiences: ["compliance-mcp", "basecamp-mcp"],
    });
    const form = bearerForm({
      client_id: client.clientId,
      resource: "https://basecamp-mcp.techimpossible.com/mcp",
    });
    form.set(
      "assertion",
      await signAssertion(idp, client.clientId, {
        extraClaims: { resource: "basecamp-mcp" },
      })
    );

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(200);
  });

  it("rejects a resource parameter that contradicts the resource claim", async () => {
    const { env: testEnv, client, idp } = await fixture({
      allowedAudiences: ["compliance-mcp", "basecamp-mcp"],
    });
    const form = bearerForm({
      client_id: client.clientId,
      resource: "https://compliance-mcp.techimpossible.com/mcp",
    });
    form.set(
      "assertion",
      await signAssertion(idp, client.clientId, {
        extraClaims: { resource: "https://basecamp-mcp.techimpossible.com/mcp" },
      })
    );

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_target");
  });

  it("intersects the tenant's audiences with the client's own bound", async () => {
    clearSigningKeyCache();
    const testEnv = env();
    const idp = await makeIdp();
    const { record } = await createClient(testEnv, {
      redirect_uris: [],
      client_name: "compliance-only-ema",
      token_endpoint_auth_method: "none",
      grant_types: [JWT_BEARER_GRANT],
      allowed_audiences: ["compliance-mcp"],
      registration_source: "admin",
    });
    await installTenant(
      testEnv,
      tenantRecord({
        allowedClientIds: [record.clientId],
        allowedAudiences: ["compliance-mcp", "basecamp-mcp"],
      })
    );

    const form = bearerForm({
      client_id: record.clientId,
      resource: "https://basecamp-mcp.techimpossible.com/mcp",
    });
    form.set("assertion", await signAssertion(idp, record.clientId));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_target");
  });
});

describe("jwt-bearer grant — tenant scoping claims", () => {
  it("enforces the tenant's email domain scoping", async () => {
    const { env: testEnv, client, idp } = await fixture({ emailDomains: ["*@customer.example"] });

    const inside = bearerForm({ client_id: client.clientId });
    inside.set("assertion", await signAssertion(idp, client.clientId));
    const allowed = await handleJwtBearerGrant(
      tokenRequest(inside),
      testEnv,
      inside,
      keySetDep(idp)
    );
    expect(allowed.status).toBe(200);

    const outside = bearerForm({ client_id: client.clientId });
    outside.set(
      "assertion",
      await signAssertion(idp, client.clientId, { email: "intruder@elsewhere.example" })
    );
    const denied = await handleJwtBearerGrant(
      tokenRequest(outside),
      testEnv,
      outside,
      keySetDep(idp)
    );
    expect(denied.status).toBe(400);
    expect(((await denied.json()) as any).error).toBe("invalid_grant");
  });

  it("rejects an assertion carrying no email claim", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const form = bearerForm({ client_id: client.clientId });
    form.set("assertion", await signAssertion(idp, client.clientId, { email: null }));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
  });

  it("enforces issuer_claim_bindings", async () => {
    const { env: testEnv, client, idp } = await fixture({
      issuerClaimBindings: { tid: "customer-directory-id" },
    });

    const matching = bearerForm({ client_id: client.clientId });
    matching.set(
      "assertion",
      await signAssertion(idp, client.clientId, { extraClaims: { tid: "customer-directory-id" } })
    );
    const allowed = await handleJwtBearerGrant(
      tokenRequest(matching),
      testEnv,
      matching,
      keySetDep(idp)
    );
    expect(allowed.status).toBe(200);

    const wrong = bearerForm({ client_id: client.clientId });
    wrong.set(
      "assertion",
      await signAssertion(idp, client.clientId, { extraClaims: { tid: "some-other-directory" } })
    );
    const denied = await handleJwtBearerGrant(tokenRequest(wrong), testEnv, wrong, keySetDep(idp));
    expect(denied.status).toBe(400);
  });
});

describe("jwt-bearer grant — identity controls (namespace binding + allowlist)", () => {
  it("refuses a customer tenant asserting a Techimpossible identity", async () => {
    // The headline bypass: without a namespace binding a customer IdP could
    // sign `email: peter.skaronis@techimpossible.com` and mint a token that
    // impersonates internal staff against another organisation's data.
    const { env: testEnv, client, idp } = await fixture();
    await installAllowlist(testEnv, ["*@customer.example", "*@techimpossible.com"]);

    const form = bearerForm({ client_id: client.clientId });
    form.set(
      "assertion",
      await signAssertion(idp, client.clientId, { email: "peter.skaronis@techimpossible.com" })
    );

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
    expect(reasonCodes()).toContain("email_not_in_tenant_domains");
  });

  it("fails closed when the tenant record carries no email_domains at all", async () => {
    // A record written before email_domains became mandatory must not be read
    // as "no scoping in effect".
    const { env: testEnv, client, idp, tenant } = await fixture();
    const legacy = { ...tenant } as Record<string, unknown>;
    delete legacy.emailDomains;
    await putTenant(testEnv, legacy as unknown as TenantRecord);

    const form = bearerForm({ client_id: client.clientId });
    form.set("assertion", await signAssertion(idp, client.clientId));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(reasonCodes()).toContain("tenant_email_domains_missing");
  });

  it("requires the identity to be on allowlist:<aud>, the operator's revocation control", async () => {
    const { env: testEnv, client, idp } = await fixture();

    const before = bearerForm({ client_id: client.clientId });
    before.set("assertion", await signAssertion(idp, client.clientId));
    expect(
      (await handleJwtBearerGrant(tokenRequest(before), testEnv, before, keySetDep(idp))).status
    ).toBe(200);

    // Peter revokes one person without touching the tenant record.
    await installAllowlist(testEnv, ["someone.else@customer.example"]);

    const after = bearerForm({ client_id: client.clientId });
    after.set("assertion", await signAssertion(idp, client.clientId));
    const res = await handleJwtBearerGrant(tokenRequest(after), testEnv, after, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
    expect(reasonCodes()).toContain("email_not_allowlisted");
  });

  it("refuses when the audience has no allowlist at all", async () => {
    const { env: testEnv, client, idp } = await fixture();
    await testEnv.ALLOWLIST_KV.delete("allowlist:compliance-mcp");

    const form = bearerForm({ client_id: client.clientId });
    form.set("assertion", await signAssertion(idp, client.clientId));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(reasonCodes()).toContain("email_not_allowlisted");
  });

  it("applies the allowlist of the audience actually requested", async () => {
    const { env: testEnv, client, idp } = await fixture({
      allowedAudiences: ["compliance-mcp", "basecamp-mcp"],
    });
    await testEnv.ALLOWLIST_KV.put(
      "allowlist:basecamp-mcp",
      JSON.stringify({ emails: ["nobody@customer.example"] })
    );

    const compliance = bearerForm({ client_id: client.clientId, resource: "compliance-mcp" });
    compliance.set("assertion", await signAssertion(idp, client.clientId));
    expect(
      (await handleJwtBearerGrant(tokenRequest(compliance), testEnv, compliance, keySetDep(idp)))
        .status
    ).toBe(200);

    const basecamp = bearerForm({ client_id: client.clientId, resource: "basecamp-mcp" });
    basecamp.set("assertion", await signAssertion(idp, client.clientId));
    const res = await handleJwtBearerGrant(tokenRequest(basecamp), testEnv, basecamp, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(reasonCodes()).toContain("email_not_allowlisted");
  });

  it("normalizes the minted email and refuses a malformed identity claim", async () => {
    const { env: testEnv, client, idp } = await fixture();

    const mixed = bearerForm({ client_id: client.clientId });
    mixed.set(
      "assertion",
      await signAssertion(idp, client.clientId, { email: "  Worker@Customer.Example " })
    );
    const ok = await handleJwtBearerGrant(tokenRequest(mixed), testEnv, mixed, keySetDep(idp));
    expect(ok.status).toBe(200);
    const payload = await verifyMinted(testEnv, ((await ok.json()) as any).access_token, "compliance-mcp");
    expect(payload.email).toBe("worker@customer.example");

    const junk = bearerForm({ client_id: client.clientId });
    junk.set(
      "assertion",
      await signAssertion(idp, client.clientId, {
        email: "worker@customer.example, peter.skaronis@techimpossible.com",
      })
    );
    const res = await handleJwtBearerGrant(tokenRequest(junk), testEnv, junk, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(reasonCodes()).toContain("identity_claim_malformed");
  });
});

describe("jwt-bearer grant — assertion is not burned by a rejected request", () => {
  it("keeps the jti usable after an invalid_target rejection", async () => {
    const { env: testEnv, client, idp } = await fixture({
      allowedAudiences: ["compliance-mcp", "basecamp-mcp"],
    });
    const assertion = await signAssertion(idp, client.clientId, { jti: "jti-not-burned" });

    const wrong = bearerForm({ client_id: client.clientId, resource: "https://evil.example/mcp" });
    wrong.set("assertion", assertion);
    const rejected = await handleJwtBearerGrant(tokenRequest(wrong), testEnv, wrong, keySetDep(idp));
    expect(rejected.status).toBe(400);
    expect(((await rejected.json()) as any).error).toBe("invalid_target");

    // Same assertion, corrected resource: the client must not need a new one.
    const corrected = bearerForm({ client_id: client.clientId, resource: "basecamp-mcp" });
    corrected.set("assertion", assertion);
    const res = await handleJwtBearerGrant(
      tokenRequest(corrected),
      testEnv,
      corrected,
      keySetDep(idp)
    );
    expect(res.status).toBe(200);
  });

  it("keeps the jti usable after an allowlist rejection", async () => {
    const { env: testEnv, client, idp } = await fixture();
    await installAllowlist(testEnv, ["someone.else@customer.example"]);
    const assertion = await signAssertion(idp, client.clientId, { jti: "jti-still-good" });

    const denied = bearerForm({ client_id: client.clientId });
    denied.set("assertion", assertion);
    expect(
      (await handleJwtBearerGrant(tokenRequest(denied), testEnv, denied, keySetDep(idp))).status
    ).toBe(400);

    await installAllowlist(testEnv);
    const retry = bearerForm({ client_id: client.clientId });
    retry.set("assertion", assertion);
    expect(
      (await handleJwtBearerGrant(tokenRequest(retry), testEnv, retry, keySetDep(idp))).status
    ).toBe(200);
  });
});

describe("jwt-bearer grant — RFC 8707 resource indicator handling", () => {
  it("does not let an empty resource claim suppress the resource parameter", async () => {
    const { env: testEnv, client, idp } = await fixture({
      allowedAudiences: ["compliance-mcp", "basecamp-mcp"],
    });
    const form = bearerForm({ client_id: client.clientId, resource: "basecamp-mcp" });
    form.set(
      "assertion",
      await signAssertion(idp, client.clientId, { extraClaims: { resource: "" } })
    );

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(200);
    const payload = await verifyMinted(testEnv, ((await res.json()) as any).access_token, "basecamp-mcp");
    expect(payload.aud).toBe("basecamp-mcp");
  });

  it("rejects two resource indicators naming different resource servers", async () => {
    const { env: testEnv, client, idp } = await fixture({
      allowedAudiences: ["compliance-mcp", "basecamp-mcp"],
    });
    const form = bearerForm({ client_id: client.clientId });
    form.append("resource", "https://compliance-mcp.techimpossible.com/mcp");
    form.append("resource", "https://basecamp-mcp.techimpossible.com/mcp");
    form.set("assertion", await signAssertion(idp, client.clientId));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_target");
  });

  it("accepts repeated resource indicators that name the same resource server", async () => {
    const { env: testEnv, client, idp } = await fixture({
      allowedAudiences: ["compliance-mcp", "basecamp-mcp"],
    });
    const form = bearerForm({ client_id: client.clientId });
    form.append("resource", "https://basecamp-mcp.techimpossible.com/mcp");
    form.append("resource", "basecamp-mcp");
    form.set("assertion", await signAssertion(idp, client.clientId));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(200);
    const payload = await verifyMinted(testEnv, ((await res.json()) as any).access_token, "basecamp-mcp");
    expect(payload.aud).toBe("basecamp-mcp");
  });
});

describe("jwt-bearer grant — response scope and media type", () => {
  it("echoes only scopes this server grants, never the raw request parameter", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const form = bearerForm({
      client_id: client.clientId,
      scope: "openid admin:everything offline_access",
    });
    form.set("assertion", await signAssertion(idp, client.clientId));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    // No refresh token is ever minted here, so offline_access is never granted.
    expect(body.scope).toBe("openid");
    expect(body.refresh_token).toBeUndefined();
  });

  it("bounds the granted scope by the IdP-signed scope claim", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const form = bearerForm({ client_id: client.clientId, scope: "openid email" });
    form.set(
      "assertion",
      await signAssertion(idp, client.clientId, { extraClaims: { scope: "openid" } })
    );

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(200);
    expect(((await res.json()) as any).scope).toBe("openid");
  });

  it("omits scope entirely when nothing is granted", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const form = bearerForm({ client_id: client.clientId, scope: "admin:everything" });
    form.set("assertion", await signAssertion(idp, client.clientId));

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(200);
    expect(((await res.json()) as any).scope).toBeUndefined();
  });

  it("allow_legacy_typ accepts a plain JWT but still refuses other token types", async () => {
    const lenient = await fixture({ allowLegacyTyp: true });

    const plain = bearerForm({ client_id: lenient.client.clientId });
    plain.set(
      "assertion",
      await signAssertion(lenient.idp, lenient.client.clientId, { typ: "JWT" })
    );
    expect(
      (await handleJwtBearerGrant(tokenRequest(plain), lenient.env, plain, keySetDep(lenient.idp)))
        .status
    ).toBe(200);

    // An IdP that stamps no typ at all says nothing about the token's purpose,
    // exactly as "JWT" does, so the same relaxation covers it.
    const noTyp = bearerForm({ client_id: lenient.client.clientId });
    noTyp.set(
      "assertion",
      await signAssertion(lenient.idp, lenient.client.clientId, { typ: null })
    );
    expect(
      (await handleJwtBearerGrant(tokenRequest(noTyp), lenient.env, noTyp, keySetDep(lenient.idp)))
        .status
    ).toBe(200);

    // A token that DECLARES itself an IdP access token (RFC 9068) is not an
    // authorization grant, and stays refused.
    const accessToken = bearerForm({ client_id: lenient.client.clientId });
    accessToken.set(
      "assertion",
      await signAssertion(lenient.idp, lenient.client.clientId, { typ: "at+jwt" })
    );
    const res = await handleJwtBearerGrant(
      tokenRequest(accessToken),
      lenient.env,
      accessToken,
      keySetDep(lenient.idp)
    );
    expect(res.status).toBe(400);
    expect(reasonCodes()).toContain("typ_not_allowed");
  });
});

describe("jwt-bearer grant — failure surface and logging", () => {
  it("returns one byte-identical body for every assertion-level rejection", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const now = Math.floor(Date.now() / 1000);

    const cases: AssertionOptions[] = [
      { iss: OTHER_IDP_ISSUER },
      { sub: null },
      { aud: "https://someone-else.example" },
      { iat: now - 200, exp: now - 120 },
    ];

    const bodies: string[] = [];
    for (const opts of cases) {
      const form = bearerForm({ client_id: client.clientId });
      form.set("assertion", await signAssertion(idp, client.clientId, opts));
      const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
      expect(res.status).toBe(400);
      bodies.push(await res.text());
    }

    expect(new Set(bodies).size).toBe(1);
  });

  it("logs a structured decision without the assertion, the raw sub, the raw jti or the email", async () => {
    const { env: testEnv, client, idp } = await fixture();
    const assertion = await signAssertion(idp, client.clientId, { jti: "jti-not-in-logs" });
    const form = bearerForm({ client_id: client.clientId });
    form.set("assertion", assertion);

    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
    expect(res.status).toBe(200);

    const decision = logLines
      .map((line) => JSON.parse(line))
      .find((entry) => entry.evt === "ema.token");
    expect(decision).toBeDefined();
    expect(decision.decision).toBe("allow");
    expect(decision.tenant_id).toBe("acme");
    expect(decision.issuer).toBe(IDP_ISSUER);
    expect(decision.aud).toBe("compliance-mcp");
    expect(decision.sub_hash).not.toBe("idp-subject-0001");
    expect(decision.jti_hash).not.toBe("jti-not-in-logs");

    const joined = logLines.join("\n");
    expect(joined).not.toContain(assertion);
    expect(joined).not.toContain("worker@customer.example");
    expect(joined).not.toContain("jti-not-in-logs");
    expect(joined).not.toContain("idp-subject-0001");
  });
});
