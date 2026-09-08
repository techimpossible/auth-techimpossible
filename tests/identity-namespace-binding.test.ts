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
import { adminTenantHandler, adminTenantIssuersHandler } from "../src/tenants/admin.js";
import { createClient } from "../src/oauth/clients.js";
import { clearSigningKeyCache, getSigningKey } from "../src/lib/crypto.js";
import { clearTenantJwksCache } from "../src/lib/tenant-jwks.js";
import { putIssuerIndex, putTenant } from "../src/tenants/store.js";
import { TENANT_KEY } from "../src/tenants/model.js";

/**
 * IDENTITY-NAMESPACE BINDING — the control the first pass did not have.
 *
 * The first pass shipped green with an authentication bypass because the suite
 * tested AUDIENCE isolation ("can tenant A reach compliance-mcp?") and never
 * IDENTITY isolation ("which identities may tenant A assert?"). Those are
 * different questions, and only the second one stops a customer tenant minting
 * a token that says `email: peter.skaronis@techimpossible.com`.
 *
 * Two independent controls answer it, and the tests below hold BOTH:
 *
 *   1. `tenant.emailDomains` — the namespace binding. Required and non-empty on
 *      every tenant record, fail-closed when a record somehow lacks it.
 *   2. `allowlist:<aud>` — per-user authorization, the control an operator
 *      revokes with. A domain pattern cannot express "everyone at Acme except
 *      this one person"; the allowlist can.
 *
 * Deliberate redundancy: several tests here fail independently under the exact
 * first-pass defect. One test guarding a HIGH-severity bypass is one deletion
 * away from the bypass coming back.
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
    async list(opts?: any) {
      const prefix = opts?.prefix ?? "";
      return {
        keys: [...map.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name })),
        list_complete: true,
        cursor: "",
      };
    },
  } as unknown as KVNamespace;
}

const AUTH_ISSUER = "https://auth.example.test";
const ACME_ISSUER = "https://idp.acme.example";
const ACME_JWKS = "https://idp.acme.example/jwks";
const GLOBEX_ISSUER = "https://idp.globex.example";
const GLOBEX_JWKS = "https://idp.globex.example/jwks";
const IDP_KID = "synthetic-idp-key-1";

/** The identity the bypass forged. Never a real credential — just an address. */
const STAFF_EMAIL = "peter.skaronis@techimpossible.com";
const ACME_WORKER = "worker@acme.example";
const GLOBEX_WORKER = "worker@globex.example";

function env() {
  return {
    OAUTH_KV: inMemoryKV(),
    ALLOWLIST_KV: inMemoryKV(),
    TENANT_KV: inMemoryKV(),
    ISSUER: AUTH_ISSUER,
    ADMIN_API_TOKEN: "synthetic-admin-token",
  } as any;
}

/** RSA keygen is the slow part: one ephemeral pair serves the whole file. */
let sharedPair: ReturnType<typeof generateKeyPair> | null = null;

function keyPair() {
  if (!sharedPair) sharedPair = generateKeyPair("RS256", { extractable: true });
  return sharedPair;
}

/**
 * A synthetic customer identity provider. No key material here is real, and
 * none of it is ever written to disk.
 */
async function makeIdp(kid = IDP_KID) {
  const { privateKey, publicKey } = await keyPair();
  const jwk = (await exportJWK(publicKey)) as JWK;
  jwk.kid = kid;
  jwk.alg = "RS256";
  jwk.use = "sig";
  const jwks = { keys: [jwk] };
  return { privateKey, kid, jwks, keySet: createLocalJWKSet(jwks) as JWTVerifyGetKey };
}

type Idp = Awaited<ReturnType<typeof makeIdp>>;

function keySetDep(idp: Idp) {
  return { resolveKeySet: async () => idp.keySet };
}

type AssertionOptions = {
  iss?: string;
  sub?: string;
  email?: string | null;
  jti?: string;
  extraClaims?: Record<string, unknown>;
};

async function signAssertion(
  idp: Idp,
  clientId: string,
  opts: AssertionOptions = {}
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload: JWTPayload = {
    iss: opts.iss ?? ACME_ISSUER,
    iat: now,
    exp: now + 300,
    email_verified: true,
    ...(opts.extraClaims ?? {}),
  };
  payload.aud = AUTH_ISSUER;
  payload.sub = opts.sub ?? "idp-subject-0001";
  payload.jti = opts.jti ?? `jti-${Math.random().toString(36).slice(2)}`;
  payload.client_id = clientId;
  if (opts.email !== null) payload.email = opts.email ?? ACME_WORKER;

  return new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", kid: idp.kid, typ: "oauth-id-jag+jwt" })
    .sign(idp.privateKey);
}

function tenantRecord(overrides: Partial<TenantRecord> = {}): TenantRecord {
  const now = Math.floor(Date.now() / 1000);
  return {
    tenantId: "acme",
    displayName: "Acme Corp",
    status: "active",
    trustedIssuers: [{ issuer: ACME_ISSUER, jwksUri: ACME_JWKS, addedAt: now }],
    allowedAudiences: ["compliance-mcp"],
    allowedClientIds: [],
    emailDomains: ["*@acme.example"],
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

async function installTenant(testEnv: any, record: TenantRecord): Promise<void> {
  await putTenant(testEnv, record);
  for (const ti of record.trustedIssuers) {
    await putIssuerIndex(testEnv, ti.issuer, record.tenantId);
  }
}

/**
 * Write a tenant row into KV as RAW JSON, bypassing putTenant and the
 * TenantRecord type altogether.
 *
 * This is the honest simulation of a row that predates a schema change: KV
 * holds untyped JSON, so a record written before `email_domains` was mandatory
 * is still sitting there, and nothing in the type system will stop it reaching
 * the token endpoint.
 */
async function installRawTenant(testEnv: any, raw: Record<string, unknown>): Promise<void> {
  await testEnv.TENANT_KV.put(TENANT_KEY(raw.tenantId as string), JSON.stringify(raw));
  for (const ti of (raw.trustedIssuers ?? []) as Array<{ issuer: string }>) {
    await putIssuerIndex(testEnv, ti.issuer, raw.tenantId as string);
  }
}

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

async function installAllowlist(
  testEnv: any,
  emails: string[] = ["*@acme.example", "*@globex.example"]
): Promise<void> {
  for (const aud of ["compliance-mcp", "basecamp-mcp"]) {
    await testEnv.ALLOWLIST_KV.put(`allowlist:${aud}`, JSON.stringify({ emails }));
  }
}

function bearerForm(params: Record<string, string>): URLSearchParams {
  return new URLSearchParams({ grant_type: JWT_BEARER_GRANT, ...params });
}

function tokenRequest(form: URLSearchParams): Request {
  return new Request(`${AUTH_ISSUER}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });
}

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

/** Acme: one tenant, namespace *@acme.example, one admin client, one IdP. */
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

/** Run one assertion through the grant and return the response. */
async function exchange(
  testEnv: any,
  client: { clientId: string },
  idp: Idp,
  opts: AssertionOptions = {},
  extraForm: Record<string, string> = {}
): Promise<Response> {
  const form = bearerForm({ client_id: client.clientId, ...extraForm });
  form.set("assertion", await signAssertion(idp, client.clientId, opts));
  return handleJwtBearerGrant(tokenRequest(form), testEnv, form, keySetDep(idp));
}

/** A refusal must be a refusal: 400 invalid_grant AND no token in the body. */
async function expectRefused(res: Response, label: string): Promise<any> {
  expect(res.status, label).toBe(400);
  const body = (await res.json()) as any;
  expect(body.error, label).toBe("invalid_grant");
  expect(body.access_token, label).toBeUndefined();
  return body;
}

describe("namespace binding — a tenant without one cannot be created", () => {
  const ADMIN = { authorization: "Bearer synthetic-admin-token" };

  function adminRequest(path: string, method: string, body?: unknown): Request {
    return new Request(`${AUTH_ISSUER}${path}`, {
      method,
      headers: { ...ADMIN, "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  }

  function tenantBody(clientId: string, overrides: Record<string, unknown> = {}) {
    return {
      display_name: "Acme Corp",
      allowed_audiences: ["compliance-mcp"],
      allowed_client_ids: [clientId],
      trusted_issuers: [{ issuer: ACME_ISSUER, jwks_uri: ACME_JWKS }],
      email_domains: ["*@acme.example"],
      ...overrides,
    };
  }

  it("refuses every shape of a missing namespace binding, and stores nothing", async () => {
    const testEnv = env();
    const client = await emaClient(testEnv);

    const shapes: Array<[string, unknown]> = [
      ["omitted", undefined],
      ["empty array", []],
      ["null", null],
      ["a bare string", "*@acme.example"],
      ["an array holding a non-string", ["*@acme.example", 42]],
      ["an array holding an empty string", [""]],
      ["a wildcard with no domain", ["*@"]],
      ["a lone wildcard", ["*"]],
      ["a bare domain with no local part or wildcard", ["acme.example"]],
    ];

    for (const [label, value] of shapes) {
      const body = tenantBody(client.clientId) as Record<string, unknown>;
      if (value === undefined) delete body.email_domains;
      else body.email_domains = value;

      const res = await adminTenantHandler(
        adminRequest("/admin/tenants/acme", "PUT", body),
        testEnv,
        "acme"
      );
      expect(res.status, label).toBe(400);
    }

    // Nothing was written by any of those attempts: no record, and no issuer
    // index entry that could later resolve to one.
    const listing = await testEnv.TENANT_KV.list({ prefix: "tenant:" });
    expect(listing.keys).toEqual([]);
    const index = await testEnv.TENANT_KV.list({ prefix: "issuer:" });
    expect(index.keys).toEqual([]);
  });

  it("accepts a well-formed namespace binding and stores it lowercased", async () => {
    // The positive control: the refusals above are refusing the defect, not
    // refusing everything.
    const testEnv = env();
    const client = await emaClient(testEnv);

    const res = await adminTenantHandler(
      adminRequest(
        "/admin/tenants/acme",
        "PUT",
        tenantBody(client.clientId, {
          email_domains: ["*@ACME.example", "Named.Person@acme.example"],
        })
      ),
      testEnv,
      "acme"
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as any).tenant.email_domains).toEqual([
      "*@acme.example",
      "named.person@acme.example",
    ]);
  });
});

describe("namespace binding — a record that lacks one fails closed at token time", () => {
  /**
   * Every shape below is a row that the CURRENT admin boundary would refuse,
   * but that could already be sitting in KV from before it was mandatory. The
   * type system cannot help here: KV returns untyped JSON.
   */
  const legacyShapes: Array<[string, unknown, string]> = [
    ["the field is absent entirely", undefined, "tenant_email_domains_missing"],
    ["the field is an empty array", [], "tenant_email_domains_missing"],
    ["the field is null", null, "tenant_email_domains_missing"],
    ["the field is a bare string", "*@acme.example", "tenant_email_domains_missing"],
    ["the only pattern is an empty string", [""], "email_not_in_tenant_domains"],
    ["the only pattern is a wildcard with no domain", ["*@"], "email_not_in_tenant_domains"],
    ["the only pattern is a lone wildcard", ["*"], "email_not_in_tenant_domains"],
  ];

  for (const [label, value, reason] of legacyShapes) {
    it(`refuses a pre-existing row where ${label}`, async () => {
      clearSigningKeyCache();
      clearTenantJwksCache();
      const testEnv = env();
      const client = await emaClient(testEnv);
      const idp = await makeIdp();
      await installAllowlist(testEnv);

      const raw = {
        ...tenantRecord({ allowedClientIds: [client.clientId] }),
      } as Record<string, unknown>;
      if (value === undefined) delete raw.emailDomains;
      else raw.emailDomains = value;
      await installRawTenant(testEnv, raw);

      // An assertion that is valid in every other respect.
      const res = await exchange(testEnv, client, idp);
      await expectRefused(res, label);
      expect(reasonCodes(), label).toContain(reason);
    });
  }

  it("still fails closed after the record is rewritten through the issuer sub-endpoint", async () => {
    // A legacy row can be carried forward by an admin action that does not
    // re-validate it — adding an issuer spreads the existing record. The
    // namespace binding must not be resurrectable into a mintable state that
    // way, so the token-time check is the backstop and is asserted here.
    clearSigningKeyCache();
    clearTenantJwksCache();
    const testEnv = env();
    const client = await emaClient(testEnv);
    const idp = await makeIdp();
    await installAllowlist(testEnv);

    const raw = { ...tenantRecord({ allowedClientIds: [client.clientId] }) } as Record<
      string,
      unknown
    >;
    delete raw.emailDomains;
    await installRawTenant(testEnv, raw);

    await adminTenantIssuersHandler(
      new Request(`${AUTH_ISSUER}/admin/tenants/acme/issuers`, {
        method: "POST",
        headers: {
          authorization: "Bearer synthetic-admin-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({ issuer: GLOBEX_ISSUER, jwks_uri: GLOBEX_JWKS }),
      }),
      testEnv,
      "acme"
    );

    const res = await exchange(testEnv, client, idp);
    await expectRefused(res, "legacy row after issuer add");
    expect(reasonCodes()).toContain("tenant_email_domains_missing");
  });

  it("mints for the same tenant once the namespace binding is restored", async () => {
    // Proves the refusals above are caused by the missing binding and nothing
    // else about the fixture.
    const { env: testEnv, client, idp, tenant } = await fixture();
    const raw = { ...tenant } as Record<string, unknown>;
    delete raw.emailDomains;
    await installRawTenant(testEnv, raw);

    await expectRefused(await exchange(testEnv, client, idp), "binding removed");

    await putTenant(testEnv, tenant);
    const res = await exchange(testEnv, client, idp);
    expect(res.status).toBe(200);
  });
});

describe("namespace binding — a tenant cannot assert an identity outside its namespace", () => {
  it("refuses tenant acme asserting a Techimpossible identity (the first-pass bypass)", async () => {
    // THE regression. Acme is a legitimate, fully onboarded tenant whose
    // assertion is valid in every respect except the address it names. The
    // allowlist deliberately CONTAINS *@techimpossible.com here, so the
    // namespace binding is the only thing standing between this request and a
    // token that impersonates Peter against another org's compliance data.
    const { env: testEnv, client, idp } = await fixture();
    await installAllowlist(testEnv, ["*@acme.example", "*@techimpossible.com"]);

    const res = await exchange(testEnv, client, idp, { email: STAFF_EMAIL });
    await expectRefused(res, "acme asserting staff identity");
    expect(reasonCodes()).toContain("email_not_in_tenant_domains");
  });

  it("refuses every near-miss form of an address outside the namespace", async () => {
    // A namespace binding is only as good as its matching rule. Each address
    // below defeats a plausible weaker implementation — a substring test, a
    // bare `endsWith` on the domain, a naive split on "@", or trusting the
    // claim's own formatting.
    const { env: testEnv, client, idp } = await fixture();
    await installAllowlist(testEnv, ["*@acme.example", "*@techimpossible.com"]);

    const cases: Array<[string, string]> = [
      [STAFF_EMAIL, "email_not_in_tenant_domains"],
      // "acme.example" appears in the domain, but not as the domain.
      ["attacker@notacme.example", "email_not_in_tenant_domains"],
      ["attacker@acme.example.attacker.test", "email_not_in_tenant_domains"],
      [`${STAFF_EMAIL}.acme.example`, "email_not_in_tenant_domains"],
      // A subdomain of the namespace is NOT the namespace.
      ["attacker@sub.acme.example", "email_not_in_tenant_domains"],
      // Uppercase must normalize into the check, not around it.
      [STAFF_EMAIL.toUpperCase(), "email_not_in_tenant_domains"],
      // Two addresses in one claim: whichever end a parser reads, refuse.
      [`${STAFF_EMAIL}@acme.example`, "identity_claim_malformed"],
      [`${STAFF_EMAIL},${ACME_WORKER}`, "identity_claim_malformed"],
      [`${STAFF_EMAIL};${ACME_WORKER}`, "identity_claim_malformed"],
      [`${ACME_WORKER} <${STAFF_EMAIL}>`, "identity_claim_malformed"],
      [`${STAFF_EMAIL}\n${ACME_WORKER}`, "identity_claim_malformed"],
    ];

    for (const [email, reason] of cases) {
      logLines.length = 0;
      const res = await exchange(testEnv, client, idp, { email });
      await expectRefused(res, email);
      expect(reasonCodes(), email).toContain(reason);
    }
  });

  it("mints for an address inside the namespace, in any case, with surrounding space", async () => {
    // The positive control for the matrix above.
    const { env: testEnv, client, idp } = await fixture();

    for (const email of [ACME_WORKER, "  Worker@ACME.Example  ", "worker@acme.example"]) {
      const res = await exchange(testEnv, client, idp, { email });
      expect(res.status, email).toBe(200);
      const payload = await verifyMinted(
        testEnv,
        ((await res.json()) as any).access_token,
        "compliance-mcp"
      );
      expect(payload.email, email).toBe(ACME_WORKER);
    }
  });

  it("refuses one tenant asserting another tenant's identity", async () => {
    // Not only Techimpossible identities: the binding is per tenant, so Acme
    // cannot impersonate a Globex user either — and Globex can still assert its
    // own, which proves the refusal is the binding and not the fixture.
    clearSigningKeyCache();
    clearTenantJwksCache();
    const testEnv = env();
    const client = await emaClient(testEnv);
    const idp = await makeIdp();
    await installAllowlist(testEnv);

    await installTenant(
      testEnv,
      tenantRecord({ allowedClientIds: [client.clientId], emailDomains: ["*@acme.example"] })
    );
    await installTenant(
      testEnv,
      tenantRecord({
        tenantId: "globex",
        displayName: "Globex",
        trustedIssuers: [
          { issuer: GLOBEX_ISSUER, jwksUri: GLOBEX_JWKS, addedAt: Math.floor(Date.now() / 1000) },
        ],
        allowedClientIds: [client.clientId],
        emailDomains: ["*@globex.example"],
      })
    );

    const crossed = await exchange(testEnv, client, idp, { email: GLOBEX_WORKER });
    await expectRefused(crossed, "acme asserting a globex identity");
    expect(reasonCodes()).toContain("email_not_in_tenant_domains");

    const own = await exchange(testEnv, client, idp, {
      iss: GLOBEX_ISSUER,
      email: GLOBEX_WORKER,
    });
    expect(own.status).toBe(200);
    const payload = await verifyMinted(
      testEnv,
      ((await own.json()) as any).access_token,
      "compliance-mcp"
    );
    expect(payload.tenant_id).toBe("globex");
  });
});

describe("per-user authorization — allowlist:<aud> gates the EMA grant", () => {
  it("refuses an in-namespace identity that is not on the allowlist, then admits it once added", async () => {
    // Onboarding, in the order an operator performs it. The tenant record alone
    // is not enough: a person inside a customer's own domain still has to be
    // authorized for the audience, one at a time.
    const { env: testEnv, client, idp } = await fixture();
    await installAllowlist(testEnv, ["someone.else@acme.example"]);

    const refused = await exchange(testEnv, client, idp, { email: ACME_WORKER });
    await expectRefused(refused, "not yet allowlisted");
    expect(reasonCodes()).toContain("email_not_allowlisted");

    await installAllowlist(testEnv, ["someone.else@acme.example", ACME_WORKER]);

    const admitted = await exchange(testEnv, client, idp, { email: ACME_WORKER });
    expect(admitted.status).toBe(200);
    const payload = await verifyMinted(
      testEnv,
      ((await admitted.json()) as any).access_token,
      "compliance-mcp"
    );
    expect(payload.email).toBe(ACME_WORKER);
  });

  it("keeps both controls independently necessary", async () => {
    // The architectural decision, as a test. The two controls do different
    // jobs, and neither substitutes for the other:
    //   - inside the namespace but not authorized  -> refused
    //   - authorized but outside the namespace     -> refused
    // Collapsing either into the other reopens a bypass.
    const { env: testEnv, client, idp } = await fixture();

    await installAllowlist(testEnv, ["*@techimpossible.com"]);
    const notAuthorized = await exchange(testEnv, client, idp, { email: ACME_WORKER });
    await expectRefused(notAuthorized, "in namespace, not allowlisted");
    expect(reasonCodes()).toContain("email_not_allowlisted");

    logLines.length = 0;
    const notInNamespace = await exchange(testEnv, client, idp, { email: STAFF_EMAIL });
    await expectRefused(notInNamespace, "allowlisted, outside namespace");
    expect(reasonCodes()).toContain("email_not_in_tenant_domains");

    logLines.length = 0;
    await installAllowlist(testEnv, ["*@techimpossible.com", ACME_WORKER]);
    const both = await exchange(testEnv, client, idp, { email: ACME_WORKER });
    expect(both.status).toBe(200);
  });

  it("revokes one person without touching the tenant record", async () => {
    // What "revocation is effective within the token TTL" means in practice:
    // one KV write, no redeploy, and the tenant's other users are unaffected.
    const { env: testEnv, client, idp } = await fixture();
    const colleague = "colleague@acme.example";
    await installAllowlist(testEnv, [ACME_WORKER, colleague]);

    expect((await exchange(testEnv, client, idp, { email: ACME_WORKER })).status).toBe(200);

    await installAllowlist(testEnv, [colleague]);

    await expectRefused(await exchange(testEnv, client, idp, { email: ACME_WORKER }), "revoked");
    expect((await exchange(testEnv, client, idp, { email: colleague })).status).toBe(200);
  });
});

describe("minted claims are this server's statement, not the assertion's", () => {
  it("ignores every identity-bearing claim the assertion tries to set", async () => {
    // The minted token is what resource servers authorize on. Each claim below
    // was chosen because a downstream consumer reads it: compliance-mcp uses
    // `email` as the caller identity and requires `email_verified === true`,
    // and `tenant_id` / `roles` are the Phase 2 authorization inputs.
    const { env: testEnv, client, idp } = await fixture();

    const res = await exchange(testEnv, client, idp, {
      email: ACME_WORKER,
      extraClaims: {
        email_verified: false,
        tenant_id: "globex",
        roles: ["admin", "owner"],
        iss: ACME_ISSUER,
      },
    });
    expect(res.status).toBe(200);

    const payload = await verifyMinted(
      testEnv,
      ((await res.json()) as any).access_token,
      "compliance-mcp"
    );
    expect(payload.iss).toBe(AUTH_ISSUER);
    expect(payload.aud).toBe("compliance-mcp");
    expect(payload.email).toBe(ACME_WORKER);
    // Server policy: we verified this address ourselves.
    expect(payload.email_verified).toBe(true);
    // The resolving tenant, never a claim.
    expect(payload.tenant_id).toBe("acme");
    expect(payload.roles).toEqual([]);
  });

  it("namespaces the subject under the resolving tenant, and a crafted sub cannot escape it", async () => {
    // `sub` is attacker-chosen text from an IdP we do not run. A subject that
    // already looks namespaced must not be able to pose as another tenant's.
    const { env: testEnv, client, idp } = await fixture();

    const res = await exchange(testEnv, client, idp, {
      sub: "ema:globex:victim-subject",
      email: ACME_WORKER,
    });
    expect(res.status).toBe(200);

    const payload = await verifyMinted(
      testEnv,
      ((await res.json()) as any).access_token,
      "compliance-mcp"
    );
    expect(payload.sub).toBe("ema:acme:ema:globex:victim-subject");
    expect(payload.sub).not.toBe("ema:globex:victim-subject");
  });
});
