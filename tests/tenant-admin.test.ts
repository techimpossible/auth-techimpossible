import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  SignJWT,
  type JWK,
  type JWTVerifyGetKey,
} from "jose";
import {
  adminTenantHandler,
  adminTenantIssuersHandler,
  adminTenantListHandler,
} from "../src/tenants/admin.js";
import { adminServiceClientHandler } from "../src/oauth/service-clients.js";
import { createClient } from "../src/oauth/clients.js";
import { handleJwtBearerGrant, JWT_BEARER_GRANT } from "../src/oauth/jwt-bearer.js";
import { clearSigningKeyCache } from "../src/lib/crypto.js";
import { clearTenantJwksCache } from "../src/lib/tenant-jwks.js";
import { lookupIssuerOwner } from "../src/tenants/store.js";

/** The jwt-bearer grant logs one structured line per decision; keep it out of the test output. */
beforeEach(() => {
  vi.spyOn(console, "log").mockImplementation(() => {});
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

function adminRequest(
  path: string,
  method: string,
  body?: unknown,
  token: string | null = ADMIN_TOKEN
): Request {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (token !== null) headers.authorization = `Bearer ${token}`;
  const sendsBody = method !== "GET" && method !== "HEAD" && body !== undefined;
  return new Request(`${AUTH_ISSUER}${path}`, {
    method,
    headers,
    body: sendsBody ? JSON.stringify(body) : undefined,
  });
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

function tenantBody(clientId: string, overrides: Record<string, unknown> = {}) {
  return {
    display_name: "Acme Corp",
    allowed_audiences: ["compliance-mcp"],
    allowed_client_ids: [clientId],
    trusted_issuers: [{ issuer: IDP_ISSUER, jwks_uri: IDP_JWKS }],
    // Mandatory: the tenant's namespace binding.
    email_domains: ["*@customer.example"],
    ...overrides,
  };
}

/**
 * The per-audience allowlist. It is the second identity control the jwt-bearer
 * grant applies, so the end-to-end tests below need it seeded exactly as
 * production does.
 */
async function installAllowlist(
  testEnv: any,
  emails: string[] = ["*@customer.example"]
): Promise<void> {
  for (const aud of ["compliance-mcp", "basecamp-mcp", "finance-mcp"]) {
    await testEnv.ALLOWLIST_KV.put(`allowlist:${aud}`, JSON.stringify({ emails }));
  }
}

let sharedPair: ReturnType<typeof generateKeyPair> | null = null;

/** One ephemeral RSA pair for the whole file: keygen dominates the runtime. */
async function makeIdp(kid = IDP_KID) {
  if (!sharedPair) sharedPair = generateKeyPair("RS256", { extractable: true });
  const { privateKey, publicKey } = await sharedPair;
  const jwk = (await exportJWK(publicKey)) as JWK;
  jwk.kid = kid;
  jwk.alg = "RS256";
  jwk.use = "sig";
  return { privateKey, kid, keySet: createLocalJWKSet({ keys: [jwk] }) as JWTVerifyGetKey };
}

type Idp = Awaited<ReturnType<typeof makeIdp>>;

async function signAssertion(idp: Idp, clientId: string, iss = IDP_ISSUER): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    iss,
    aud: AUTH_ISSUER,
    sub: "idp-subject-0001",
    jti: `jti-${Math.random().toString(36).slice(2)}`,
    client_id: clientId,
    email: "worker@customer.example",
    email_verified: true,
    iat: now,
    exp: now + 300,
  })
    .setProtectedHeader({ alg: "RS256", kid: idp.kid, typ: "oauth-id-jag+jwt" })
    .sign(idp.privateKey);
}

function bearerForm(clientId: string, assertion: string): URLSearchParams {
  return new URLSearchParams({
    grant_type: JWT_BEARER_GRANT,
    client_id: clientId,
    assertion,
  });
}

function tokenRequest(form: URLSearchParams): Request {
  return new Request(`${AUTH_ISSUER}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });
}

describe("tenant admin — authentication", () => {
  it("refuses every method without a bearer token", async () => {
    const testEnv = env();
    for (const [path, method] of [
      ["/admin/tenants", "GET"],
      ["/admin/tenants/acme", "GET"],
      ["/admin/tenants/acme", "PUT"],
      ["/admin/tenants/acme/issuers", "POST"],
    ] as const) {
      const handler =
        path === "/admin/tenants"
          ? adminTenantListHandler(adminRequest(path, method, undefined, null), testEnv)
          : path.endsWith("/issuers")
            ? adminTenantIssuersHandler(adminRequest(path, method, {}, null), testEnv, "acme")
            : adminTenantHandler(adminRequest(path, method, {}, null), testEnv, "acme");
      const res = await handler;
      expect(res.status).toBe(401);
    }
  });

  it("refuses a wrong bearer token", async () => {
    const testEnv = env();
    const res = await adminTenantListHandler(
      adminRequest("/admin/tenants", "GET", undefined, "not-the-admin-token"),
      testEnv
    );
    expect(res.status).toBe(401);
  });

  it("fails closed when ADMIN_API_TOKEN is unset", async () => {
    const testEnv = { ...env(), ADMIN_API_TOKEN: "" };
    const res = await adminTenantListHandler(
      adminRequest("/admin/tenants", "GET", undefined, ADMIN_TOKEN),
      testEnv
    );
    expect(res.status).toBe(401);
  });
});

describe("tenant admin — setting a tenant's trusted issuer", () => {
  it("creates a tenant, writes the reverse index, and lists it", async () => {
    const testEnv = env();
    const client = await emaClient(testEnv);

    const res = await adminTenantHandler(
      adminRequest("/admin/tenants/acme", "PUT", tenantBody(client.clientId)),
      testEnv,
      "acme"
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.tenant.tenant_id).toBe("acme");
    expect(body.tenant.status).toBe("active");
    expect(body.tenant.trusted_issuers).toEqual([
      expect.objectContaining({ issuer: IDP_ISSUER, jwks_uri: IDP_JWKS }),
    ]);
    expect(body.tenant.allowed_client_ids).toEqual([client.clientId]);

    expect(await lookupIssuerOwner(testEnv, IDP_ISSUER)).toBe("acme");

    const listed = await adminTenantListHandler(adminRequest("/admin/tenants", "GET"), testEnv);
    expect(((await listed.json()) as any).tenants).toEqual(["acme"]);

    const fetched = await adminTenantHandler(
      adminRequest("/admin/tenants/acme", "GET"),
      testEnv,
      "acme"
    );
    expect(fetched.status).toBe(200);
    expect(((await fetched.json()) as any).tenant.display_name).toBe("Acme Corp");
  });

  it("normalizes the stored issuer (trailing slash stripped)", async () => {
    const testEnv = env();
    const client = await emaClient(testEnv);
    const res = await adminTenantHandler(
      adminRequest(
        "/admin/tenants/acme",
        "PUT",
        tenantBody(client.clientId, {
          trusted_issuers: [{ issuer: `${IDP_ISSUER}/`, jwks_uri: IDP_JWKS }],
        })
      ),
      testEnv,
      "acme"
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as any).tenant.trusted_issuers[0].issuer).toBe(IDP_ISSUER);
  });

  it("rejects an issuer that is not a public https URL", async () => {
    const testEnv = env();
    const client = await emaClient(testEnv);
    for (const issuer of [
      "http://idp.customer.example",
      "https://idp.internal",
      "https://localhost",
      "https://10.0.0.5",
      "https://idp.customer.example:8443",
      "https://idp.customer.example?x=1",
      // Aiming the Worker's own outbound fetch at our zone is blocked outright.
      "https://auth.techimpossible.com",
    ]) {
      const res = await adminTenantHandler(
        adminRequest(
          "/admin/tenants/acme",
          "PUT",
          tenantBody(client.clientId, { trusted_issuers: [{ issuer, jwks_uri: IDP_JWKS }] })
        ),
        testEnv,
        "acme"
      );
      expect(res.status).toBe(400);
    }
  });

  it("requires the jwks_uri to be same-origin with the issuer", async () => {
    const testEnv = env();
    const client = await emaClient(testEnv);
    const res = await adminTenantHandler(
      adminRequest(
        "/admin/tenants/acme",
        "PUT",
        tenantBody(client.clientId, {
          trusted_issuers: [{ issuer: IDP_ISSUER, jwks_uri: "https://evil.example/jwks" }],
        })
      ),
      testEnv,
      "acme"
    );
    expect(res.status).toBe(400);
  });

  it("rejects an unsupported audience", async () => {
    const testEnv = env();
    const client = await emaClient(testEnv);
    const res = await adminTenantHandler(
      adminRequest(
        "/admin/tenants/acme",
        "PUT",
        tenantBody(client.clientId, { allowed_audiences: ["something-else"] })
      ),
      testEnv,
      "acme"
    );
    expect(res.status).toBe(400);
  });

  it("rejects a tenant_id that does not match the id pattern", async () => {
    const testEnv = env();
    const client = await emaClient(testEnv);
    const res = await adminTenantHandler(
      adminRequest("/admin/tenants/Acme.Corp", "PUT", tenantBody(client.clientId)),
      testEnv,
      "Acme.Corp"
    );
    expect(res.status).toBe(400);
  });

  it("requires email_domains: a tenant with no namespace binding cannot be created", async () => {
    const testEnv = env();
    const client = await emaClient(testEnv);

    const empty = await adminTenantHandler(
      adminRequest("/admin/tenants/acme", "PUT", tenantBody(client.clientId, { email_domains: [] })),
      testEnv,
      "acme"
    );
    expect(empty.status).toBe(400);

    // Omission used to be accepted, and a tenant without a namespace binding
    // could then assert any identity, including a Techimpossible one.
    const body = tenantBody(client.clientId) as Record<string, unknown>;
    delete body.email_domains;
    const missing = await adminTenantHandler(
      adminRequest("/admin/tenants/acme", "PUT", body),
      testEnv,
      "acme"
    );
    expect(missing.status).toBe(400);
    expect(((await missing.json()) as any).error_description).toContain("email_domains is required");

    const stored = await adminTenantHandler(
      adminRequest("/admin/tenants/acme", "GET"),
      testEnv,
      "acme"
    );
    expect(stored.status).toBe(404);
  });

  it("rejects an email_domains entry that is not a usable pattern", async () => {
    const testEnv = env();
    const client = await emaClient(testEnv);
    for (const pattern of ["customer.example", "*@", "*", "*@customer example"]) {
      const res = await adminTenantHandler(
        adminRequest(
          "/admin/tenants/acme",
          "PUT",
          tenantBody(client.clientId, { email_domains: [pattern] })
        ),
        testEnv,
        "acme"
      );
      expect(res.status).toBe(400);
    }
  });

  it("requires default_audience to be one of allowed_audiences", async () => {
    const testEnv = env();
    const client = await emaClient(testEnv);

    const bad = await adminTenantHandler(
      adminRequest(
        "/admin/tenants/acme",
        "PUT",
        tenantBody(client.clientId, { default_audience: "basecamp-mcp" })
      ),
      testEnv,
      "acme"
    );
    expect(bad.status).toBe(400);

    const good = await adminTenantHandler(
      adminRequest(
        "/admin/tenants/acme",
        "PUT",
        tenantBody(client.clientId, {
          allowed_audiences: ["compliance-mcp", "basecamp-mcp"],
          default_audience: "basecamp-mcp",
        })
      ),
      testEnv,
      "acme"
    );
    expect(good.status).toBe(200);
    expect(((await good.json()) as any).tenant.default_audience).toBe("basecamp-mcp");
  });

  it("binds jwks_uri underneath the issuer's path, not merely to its origin", async () => {
    // A multi-tenant IdP host gives each customer one path. Origin-only matching
    // would let tenant A's key source be customer B's key endpoint.
    const testEnv = env();
    const client = await emaClient(testEnv);

    const foreignPath = await adminTenantHandler(
      adminRequest(
        "/admin/tenants/acme",
        "PUT",
        tenantBody(client.clientId, {
          trusted_issuers: [
            {
              issuer: "https://idp.saas.example/customer-a",
              jwks_uri: "https://idp.saas.example/customer-b/jwks",
            },
          ],
        })
      ),
      testEnv,
      "acme"
    );
    expect(foreignPath.status).toBe(400);

    const ownPath = await adminTenantHandler(
      adminRequest(
        "/admin/tenants/acme",
        "PUT",
        tenantBody(client.clientId, {
          trusted_issuers: [
            {
              issuer: "https://idp.saas.example/customer-a",
              jwks_uri: "https://idp.saas.example/customer-a/v1/keys",
            },
          ],
        })
      ),
      testEnv,
      "acme"
    );
    expect(ownPath.status).toBe(200);
  });

  it("bounds max_assertion_age_seconds", async () => {
    const testEnv = env();
    const client = await emaClient(testEnv);
    for (const age of [10, 7200, 60.5, "300"]) {
      const res = await adminTenantHandler(
        adminRequest(
          "/admin/tenants/acme",
          "PUT",
          tenantBody(client.clientId, { max_assertion_age_seconds: age })
        ),
        testEnv,
        "acme"
      );
      expect(res.status).toBe(400);
    }
  });
});

describe("tenant admin — client provenance gate", () => {
  it("rejects a self-registered (DCR) client", async () => {
    const testEnv = env();
    const { record } = await createClient(testEnv, {
      redirect_uris: [],
      client_name: "self-registered",
      token_endpoint_auth_method: "none",
      grant_types: [JWT_BEARER_GRANT],
    });

    const res = await adminTenantHandler(
      adminRequest("/admin/tenants/acme", "PUT", tenantBody(record.clientId)),
      testEnv,
      "acme"
    );
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error_description).toContain("self-registered");
  });

  it("rejects an admin client that does not carry the jwt-bearer grant", async () => {
    const testEnv = env();
    const { record } = await createClient(testEnv, {
      redirect_uris: [],
      client_name: "cc-only",
      grant_types: ["client_credentials"],
      registration_source: "admin",
    });

    const res = await adminTenantHandler(
      adminRequest("/admin/tenants/acme", "PUT", tenantBody(record.clientId)),
      testEnv,
      "acme"
    );
    expect(res.status).toBe(400);
  });

  it("rejects an unknown client_id and an empty allowed_client_ids", async () => {
    const testEnv = env();

    const unknown = await adminTenantHandler(
      adminRequest("/admin/tenants/acme", "PUT", tenantBody("ti-does-not-exist")),
      testEnv,
      "acme"
    );
    expect(unknown.status).toBe(400);

    const client = await emaClient(testEnv);
    const empty = await adminTenantHandler(
      adminRequest(
        "/admin/tenants/acme",
        "PUT",
        tenantBody(client.clientId, { allowed_client_ids: [] })
      ),
      testEnv,
      "acme"
    );
    expect(empty.status).toBe(400);
  });

  it("accepts an EMA client minted through /admin/service-clients", async () => {
    const testEnv = env();
    const created = await adminServiceClientHandler(
      adminRequest("/admin/service-clients", "POST", {
        client_name: "claude-ema",
        service_email: "ema@customer.example",
        allowed_audiences: ["compliance-mcp"],
        grant_types: [JWT_BEARER_GRANT],
        token_endpoint_auth_method: "none",
      }),
      testEnv
    );
    expect(created.status).toBe(200);
    const createdBody = (await created.json()) as any;
    expect(createdBody.client_secret).toBeNull();

    const res = await adminTenantHandler(
      adminRequest("/admin/tenants/acme", "PUT", tenantBody(createdBody.client_id)),
      testEnv,
      "acme"
    );
    expect(res.status).toBe(200);
  });
});

describe("tenant admin — issuer to tenant is 1:1", () => {
  it("returns 409 when another tenant already owns the issuer", async () => {
    const testEnv = env();
    const client = await emaClient(testEnv);

    const first = await adminTenantHandler(
      adminRequest("/admin/tenants/acme", "PUT", tenantBody(client.clientId)),
      testEnv,
      "acme"
    );
    expect(first.status).toBe(200);

    const second = await adminTenantHandler(
      adminRequest("/admin/tenants/globex", "PUT", tenantBody(client.clientId)),
      testEnv,
      "globex"
    );
    expect(second.status).toBe(409);
    expect(((await second.json()) as any).error).toBe("issuer_conflict");

    // The original binding is untouched.
    expect(await lookupIssuerOwner(testEnv, IDP_ISSUER)).toBe("acme");
  });

  it("lets the owning tenant rewrite its own issuer without conflicting with itself", async () => {
    const testEnv = env();
    const client = await emaClient(testEnv);
    await adminTenantHandler(
      adminRequest("/admin/tenants/acme", "PUT", tenantBody(client.clientId)),
      testEnv,
      "acme"
    );

    const again = await adminTenantHandler(
      adminRequest(
        "/admin/tenants/acme",
        "PUT",
        tenantBody(client.clientId, { display_name: "Acme Corporation" })
      ),
      testEnv,
      "acme"
    );
    expect(again.status).toBe(200);
    expect(((await again.json()) as any).tenant.display_name).toBe("Acme Corporation");
  });

  it("rejects duplicate issuers inside one request", async () => {
    const testEnv = env();
    const client = await emaClient(testEnv);
    const res = await adminTenantHandler(
      adminRequest(
        "/admin/tenants/acme",
        "PUT",
        tenantBody(client.clientId, {
          trusted_issuers: [
            { issuer: IDP_ISSUER, jwks_uri: IDP_JWKS },
            { issuer: `${IDP_ISSUER}/`, jwks_uri: IDP_JWKS },
          ],
        })
      ),
      testEnv,
      "acme"
    );
    expect(res.status).toBe(400);
  });
});

describe("tenant admin — per-issuer add and remove", () => {
  async function seeded() {
    const testEnv = env();
    const client = await emaClient(testEnv);
    await adminTenantHandler(
      adminRequest("/admin/tenants/acme", "PUT", tenantBody(client.clientId)),
      testEnv,
      "acme"
    );
    return { env: testEnv, client };
  }

  it("adds a second issuer and indexes it", async () => {
    const { env: testEnv } = await seeded();
    const res = await adminTenantIssuersHandler(
      adminRequest("/admin/tenants/acme/issuers", "POST", {
        issuer: SECOND_ISSUER,
        jwks_uri: SECOND_JWKS,
      }),
      testEnv,
      "acme"
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as any).tenant.trusted_issuers).toHaveLength(2);
    expect(await lookupIssuerOwner(testEnv, SECOND_ISSUER)).toBe("acme");
  });

  it("refuses to add an issuer owned by another tenant", async () => {
    const { env: testEnv, client } = await seeded();
    await adminTenantHandler(
      adminRequest(
        "/admin/tenants/globex",
        "PUT",
        tenantBody(client.clientId, {
          trusted_issuers: [{ issuer: SECOND_ISSUER, jwks_uri: SECOND_JWKS }],
        })
      ),
      testEnv,
      "globex"
    );

    const res = await adminTenantIssuersHandler(
      adminRequest("/admin/tenants/acme/issuers", "POST", {
        issuer: SECOND_ISSUER,
        jwks_uri: SECOND_JWKS,
      }),
      testEnv,
      "acme"
    );
    expect(res.status).toBe(409);
  });

  it("removes an issuer and drops its index entry", async () => {
    const { env: testEnv } = await seeded();
    await adminTenantIssuersHandler(
      adminRequest("/admin/tenants/acme/issuers", "POST", {
        issuer: SECOND_ISSUER,
        jwks_uri: SECOND_JWKS,
      }),
      testEnv,
      "acme"
    );

    const res = await adminTenantIssuersHandler(
      adminRequest("/admin/tenants/acme/issuers", "DELETE", { issuer: IDP_ISSUER }),
      testEnv,
      "acme"
    );
    expect(res.status).toBe(200);
    expect(await lookupIssuerOwner(testEnv, IDP_ISSUER)).toBeNull();
    expect(await lookupIssuerOwner(testEnv, SECOND_ISSUER)).toBe("acme");
  });

  it("refuses to remove the last issuer, and refuses an issuer it does not have", async () => {
    const { env: testEnv } = await seeded();

    const last = await adminTenantIssuersHandler(
      adminRequest("/admin/tenants/acme/issuers", "DELETE", { issuer: IDP_ISSUER }),
      testEnv,
      "acme"
    );
    expect(last.status).toBe(400);

    const absent = await adminTenantIssuersHandler(
      adminRequest("/admin/tenants/acme/issuers", "DELETE", { issuer: SECOND_ISSUER }),
      testEnv,
      "acme"
    );
    expect(absent.status).toBe(404);
  });

  it("404s for a tenant that does not exist", async () => {
    const testEnv = env();
    const res = await adminTenantIssuersHandler(
      adminRequest("/admin/tenants/nobody/issuers", "POST", {
        issuer: IDP_ISSUER,
        jwks_uri: IDP_JWKS,
      }),
      testEnv,
      "nobody"
    );
    expect(res.status).toBe(404);
  });
});

describe("tenant admin — an issuer cannot be stolen through a side door", () => {
  it("refuses to re-index an issuer that now belongs to another tenant", async () => {
    const testEnv = env();
    const acmeClient = await emaClient(testEnv, "acme-ema");
    const betaClient = await emaClient(testEnv, "beta-ema");

    // 1. Acme owns issuer X.
    expect(
      (
        await adminTenantHandler(
          adminRequest("/admin/tenants/acme", "PUT", tenantBody(acmeClient.clientId)),
          testEnv,
          "acme"
        )
      ).status
    ).toBe(200);

    // 2. Acme is disabled. That unbinds X but deliberately keeps it on the record.
    expect(
      (await adminTenantHandler(adminRequest("/admin/tenants/acme", "DELETE"), testEnv, "acme"))
        .status
    ).toBe(200);
    expect(await lookupIssuerOwner(testEnv, IDP_ISSUER)).toBeNull();

    // 3. Beta legitimately takes issuer X.
    expect(
      (
        await adminTenantHandler(
          adminRequest("/admin/tenants/beta", "PUT", tenantBody(betaClient.clientId)),
          testEnv,
          "beta"
        )
      ).status
    ).toBe(200);
    expect(await lookupIssuerOwner(testEnv, IDP_ISSUER)).toBe("beta");

    // 4. Adding an UNRELATED issuer to acme used to silently re-point X at acme,
    //    because the commit re-indexes every issuer on the record while the
    //    conflict check looked only at the new one. Beta went dark with a
    //    misleading reason code.
    const stolen = await adminTenantIssuersHandler(
      adminRequest("/admin/tenants/acme/issuers", "POST", { issuer: SECOND_ISSUER, jwks_uri: SECOND_JWKS }),
      testEnv,
      "acme"
    );
    expect(stolen.status).toBe(409);
    expect(((await stolen.json()) as any).error).toBe("issuer_conflict");
    expect(await lookupIssuerOwner(testEnv, IDP_ISSUER)).toBe("beta");
    expect(await lookupIssuerOwner(testEnv, SECOND_ISSUER)).toBeNull();

    // 5. And re-enabling acme with X still on its record is refused too.
    const reEnabled = await adminTenantHandler(
      adminRequest("/admin/tenants/acme", "PUT", tenantBody(acmeClient.clientId)),
      testEnv,
      "acme"
    );
    expect(reEnabled.status).toBe(409);
    expect(await lookupIssuerOwner(testEnv, IDP_ISSUER)).toBe("beta");
  });

  it("a second disable does not unbind an issuer another tenant now owns", async () => {
    // The mirror image of the same class of bug: the disable path walks the
    // tenant's own (retained) issuer list, and an unconditional index delete
    // would silently take the new owner off the air.
    const testEnv = env();
    const acmeClient = await emaClient(testEnv, "acme-ema");
    const betaClient = await emaClient(testEnv, "beta-ema");

    await adminTenantHandler(
      adminRequest("/admin/tenants/acme", "PUT", tenantBody(acmeClient.clientId)),
      testEnv,
      "acme"
    );
    await adminTenantHandler(adminRequest("/admin/tenants/acme", "DELETE"), testEnv, "acme");
    await adminTenantHandler(
      adminRequest("/admin/tenants/beta", "PUT", tenantBody(betaClient.clientId)),
      testEnv,
      "beta"
    );
    expect(await lookupIssuerOwner(testEnv, IDP_ISSUER)).toBe("beta");

    // Acme is disabled again (idempotent operator action, or a cleanup script).
    expect(
      (await adminTenantHandler(adminRequest("/admin/tenants/acme", "DELETE"), testEnv, "acme"))
        .status
    ).toBe(200);
    expect(await lookupIssuerOwner(testEnv, IDP_ISSUER)).toBe("beta");
  });
});

describe("tenant admin — end to end with the jwt-bearer grant", () => {
  it("an admin-registered issuer mints tokens, and revocation stops them", async () => {
    clearSigningKeyCache();
    clearTenantJwksCache();
    const testEnv = env();
    await installAllowlist(testEnv);
    const client = await emaClient(testEnv);
    const idp = await makeIdp();
    const deps = { resolveKeySet: async () => idp.keySet };

    const created = await adminTenantHandler(
      adminRequest("/admin/tenants/acme", "PUT", tenantBody(client.clientId)),
      testEnv,
      "acme"
    );
    expect(created.status).toBe(200);

    const okForm = bearerForm(client.clientId, await signAssertion(idp, client.clientId));
    const ok = await handleJwtBearerGrant(tokenRequest(okForm), testEnv, okForm, deps);
    expect(ok.status).toBe(200);

    // DELETE disables the tenant and unbinds every issuer.
    const disabled = await adminTenantHandler(
      adminRequest("/admin/tenants/acme", "DELETE"),
      testEnv,
      "acme"
    );
    expect(disabled.status).toBe(200);
    expect(((await disabled.json()) as any).tenant.status).toBe("disabled");
    expect(await lookupIssuerOwner(testEnv, IDP_ISSUER)).toBeNull();

    const revokedForm = bearerForm(client.clientId, await signAssertion(idp, client.clientId));
    const revoked = await handleJwtBearerGrant(
      tokenRequest(revokedForm),
      testEnv,
      revokedForm,
      deps
    );
    expect(revoked.status).toBe(400);
    expect(((await revoked.json()) as any).error).toBe("invalid_grant");
  });

  it("an issuer registered for one tenant cannot be used by another tenant's client", async () => {
    clearSigningKeyCache();
    clearTenantJwksCache();
    const testEnv = env();
    await installAllowlist(testEnv);
    const acmeClient = await emaClient(testEnv, "acme-ema");
    const globexClient = await emaClient(testEnv, "globex-ema");
    const idp = await makeIdp();
    const deps = { resolveKeySet: async () => idp.keySet };

    await adminTenantHandler(
      adminRequest("/admin/tenants/acme", "PUT", tenantBody(acmeClient.clientId)),
      testEnv,
      "acme"
    );
    await adminTenantHandler(
      adminRequest(
        "/admin/tenants/globex",
        "PUT",
        tenantBody(globexClient.clientId, {
          trusted_issuers: [{ issuer: SECOND_ISSUER, jwks_uri: SECOND_JWKS }],
        })
      ),
      testEnv,
      "globex"
    );

    // Acme's issuer, signed by Acme's IdP, presented by Globex's client.
    const form = bearerForm(globexClient.clientId, await signAssertion(idp, globexClient.clientId));
    const res = await handleJwtBearerGrant(tokenRequest(form), testEnv, form, deps);
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
  });
});
