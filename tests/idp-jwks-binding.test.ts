import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { adminTenantHandler, adminTenantIssuersHandler } from "../src/tenants/admin.js";
import { createClient } from "../src/oauth/clients.js";
import { JWT_BEARER_GRANT } from "../src/oauth/grants.js";
import { classifyJwksBinding, isSharedMultiTenantIssuer } from "../src/tenants/model.js";
import { lookupIssuerOwner } from "../src/tenants/store.js";

/**
 * WHERE A TENANT'S SIGNING KEYS MAY COME FROM.
 *
 * The check exists to stop one thing: on a shared multi-tenant IdP host, tenant
 * A nominating tenant B's key endpoint as A's key source, after which key
 * material from B's trust domain decides what is accepted as A.
 *
 * It used to assert that as "the jwks_uri must sit underneath the issuer's PATH
 * PREFIX", which is not how the largest IdP in the estate publishes. Microsoft
 * Entra v2.0 serves
 *
 *     issuer    https://login.microsoftonline.com/<tenant-guid>/v2.0
 *     jwks_uri  https://login.microsoftonline.com/<tenant-guid>/discovery/v2.0/keys
 *
 * The keys sit BESIDE the issuer path while still being inside the same tenant
 * GUID, so `PUT /admin/tenants/<id>` returned 400 for every Entra tenant,
 * through the explicit branch and the discovery branch alike — while
 * `docs/enterprise-managed-auth.md` named Entra as supported.
 *
 * These tests hold both halves at once: the real IdP shapes register, and the
 * cross-tenant attack the rule exists to stop is still refused — before any
 * outbound request is made.
 *
 * NO REQUEST LEAVES THE PROCESS. `fetch` is replaced by a routing table, and a
 * URL with no route models an unreachable host. Tests that must prove the
 * decision was made with NO network dependency assert on the call list itself,
 * which is the point: a registration-time check that silently became a fetch
 * would make an admin write depend on the IdP being up.
 */

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

/** Synthetic GUIDs. Shaped like Entra tenant ids; they identify nothing real. */
const ENTRA_A = "8f2a1c34-5b6d-4e7f-9a0b-1c2d3e4f5a6b";
const ENTRA_B = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
const PINGONE_ENV = "b1f2c3d4-e5a6-4b7c-8d9e-0f1a2b3c4d5e";

function env() {
  return {
    OAUTH_KV: inMemoryKV(),
    ALLOWLIST_KV: inMemoryKV(),
    TENANT_KV: inMemoryKV(),
    ISSUER: AUTH_ISSUER,
    ADMIN_API_TOKEN: ADMIN_TOKEN,
  } as any;
}

/** url -> the JSON document served there. Anything else is unreachable. */
let routes: Map<string, unknown>;
let fetchCalls: string[];

beforeEach(() => {
  vi.spyOn(console, "log").mockImplementation(() => {});
  routes = new Map();
  fetchCalls = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input: any) => {
    const url = typeof input === "string" ? input : input.url;
    fetchCalls.push(url);
    const doc = routes.get(url);
    if (doc === undefined) throw new Error(`no synthetic route for ${url}`);
    return new Response(JSON.stringify(doc), {
      status: 200,
      headers: { "content-type": "application/json" },
    }) as any;
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

/** Publish an OIDC discovery document at the issuer's well-known location. */
function publishDiscovery(issuer: string, doc: Record<string, unknown>): void {
  routes.set(`${issuer}/.well-known/openid-configuration`, doc);
}

function adminRequest(path: string, method: string, body?: unknown): Request {
  return new Request(`${AUTH_ISSUER}${path}`, {
    method,
    headers: { "content-type": "application/json", authorization: `Bearer ${ADMIN_TOKEN}` },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function emaClient(testEnv: any): Promise<string> {
  const { record } = await createClient(testEnv, {
    redirect_uris: [],
    client_name: "claude-ema",
    token_endpoint_auth_method: "none",
    grant_types: [JWT_BEARER_GRANT],
    response_types: [],
    registration_source: "admin",
  });
  return record.clientId;
}

function tenantBody(clientId: string, trustedIssuers: unknown[], overrides = {}) {
  return {
    display_name: "Acme Corp",
    allowed_audiences: ["compliance-mcp"],
    allowed_client_ids: [clientId],
    trusted_issuers: trustedIssuers,
    email_domains: ["*@acme.example"],
    ...overrides,
  };
}

/** PUT one tenant carrying exactly the trusted_issuers entries given. */
async function putTenantWithIssuers(
  testEnv: any,
  tenantId: string,
  trustedIssuers: unknown[]
): Promise<Response> {
  const clientId = await emaClient(testEnv);
  return adminTenantHandler(
    adminRequest(`/admin/tenants/${tenantId}`, "PUT", tenantBody(clientId, trustedIssuers)),
    testEnv,
    tenantId
  );
}

type IdpRow = {
  name: string;
  tenantId: string;
  /** What the operator pastes. */
  given: string;
  /** What normalizeIssuer stores. */
  stored: string;
  jwksUri: string;
  /**
   * True when the keys sit BESIDE the issuer path rather than underneath it, so
   * the issuer's own metadata has to designate them. Entra is the case that
   * forced the rule to be rewritten.
   */
  needsDiscovery: boolean;
};

/**
 * The identity providers this server is documented to support, with the issuer
 * and jwks_uri shapes each one actually publishes.
 */
const IDP_MATRIX: IdpRow[] = [
  {
    name: "Microsoft Entra ID v2.0",
    tenantId: "entra-customer",
    given: `https://login.microsoftonline.com/${ENTRA_A}/v2.0`,
    stored: `https://login.microsoftonline.com/${ENTRA_A}/v2.0`,
    jwksUri: `https://login.microsoftonline.com/${ENTRA_A}/discovery/v2.0/keys`,
    needsDiscovery: true,
  },
  {
    name: "Okta org authorization server",
    tenantId: "okta-org",
    given: "https://acme.okta.example",
    stored: "https://acme.okta.example",
    jwksUri: "https://acme.okta.example/oauth2/v1/keys",
    needsDiscovery: false,
  },
  {
    name: "Okta custom authorization server",
    tenantId: "okta-custom",
    given: "https://acme.okta.example/oauth2/aus1a2b3c4d5e6f7g8h9",
    stored: "https://acme.okta.example/oauth2/aus1a2b3c4d5e6f7g8h9",
    jwksUri: "https://acme.okta.example/oauth2/aus1a2b3c4d5e6f7g8h9/v1/keys",
    needsDiscovery: false,
  },
  {
    name: "Auth0",
    tenantId: "auth0-customer",
    // Auth0 publishes its issuer WITH a trailing slash.
    given: "https://acme.eu.auth0.example/",
    stored: "https://acme.eu.auth0.example",
    jwksUri: "https://acme.eu.auth0.example/.well-known/jwks.json",
    needsDiscovery: false,
  },
  {
    name: "Keycloak realm",
    tenantId: "keycloak-customer",
    given: "https://sso.acme.example/realms/acme",
    stored: "https://sso.acme.example/realms/acme",
    jwksUri: "https://sso.acme.example/realms/acme/protocol/openid-connect/certs",
    needsDiscovery: false,
  },
  {
    name: "PingOne",
    tenantId: "pingone-customer",
    given: `https://auth.pingone.example/${PINGONE_ENV}/as`,
    stored: `https://auth.pingone.example/${PINGONE_ENV}/as`,
    jwksUri: `https://auth.pingone.example/${PINGONE_ENV}/as/jwks`,
    needsDiscovery: false,
  },
];

describe("the real IdP matrix registers — explicit jwks_uri", () => {
  it.each(IDP_MATRIX)("$name", async (row) => {
    const testEnv = env();
    if (row.needsDiscovery) {
      publishDiscovery(row.stored, { issuer: row.stored, jwks_uri: row.jwksUri });
    }

    const res = await putTenantWithIssuers(testEnv, row.tenantId, [
      { issuer: row.given, jwks_uri: row.jwksUri },
    ]);

    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.tenant.trusted_issuers).toEqual([
      expect.objectContaining({ issuer: row.stored, jwks_uri: row.jwksUri }),
    ]);
    expect(await lookupIssuerOwner(testEnv, row.stored)).toBe(row.tenantId);

    // A binding that is self-evident costs no network call. Only the sibling
    // tier — the keys beside the issuer path — has to ask the issuer.
    expect(fetchCalls).toHaveLength(row.needsDiscovery ? 1 : 0);
  });
});

describe("the real IdP matrix registers — jwks_uri omitted, read from discovery", () => {
  it.each(IDP_MATRIX)("$name", async (row) => {
    // The recommended onboarding route: the URL comes from the vendor rather
    // than from a human paste. It must work for every row, Entra included.
    const testEnv = env();
    publishDiscovery(row.stored, {
      issuer: row.stored,
      jwks_uri: row.jwksUri,
      authorization_endpoint: `${row.stored}/authorize`,
    });

    const res = await putTenantWithIssuers(testEnv, row.tenantId, [{ issuer: row.given }]);

    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.tenant.trusted_issuers).toEqual([
      expect.objectContaining({ issuer: row.stored, jwks_uri: row.jwksUri }),
    ]);

    // Exactly one fetch: the document whose `issuer` member was just matched IS
    // the confirmation the sibling tier asks for, so it is not read twice.
    expect(fetchCalls).toEqual([`${row.stored}/.well-known/openid-configuration`]);
  });
});

describe("Microsoft Entra specifically", () => {
  const ISSUER_A = `https://login.microsoftonline.com/${ENTRA_A}/v2.0`;
  const KEYS_A = `https://login.microsoftonline.com/${ENTRA_A}/discovery/v2.0/keys`;

  it("can also be added to an existing tenant through POST /admin/tenants/<id>/issuers", async () => {
    // The other write path onto the same record. Both endpoints resolve issuers
    // through one function, and both were shut to Entra.
    const testEnv = env();
    const clientId = await emaClient(testEnv);
    const created = await adminTenantHandler(
      adminRequest(
        "/admin/tenants/acme",
        "PUT",
        tenantBody(clientId, [
          { issuer: "https://sso.acme.example/realms/acme", jwks_uri: "https://sso.acme.example/realms/acme/protocol/openid-connect/certs" },
        ])
      ),
      testEnv,
      "acme"
    );
    expect(created.status).toBe(200);

    publishDiscovery(ISSUER_A, { issuer: ISSUER_A, jwks_uri: KEYS_A });
    const added = await adminTenantIssuersHandler(
      adminRequest("/admin/tenants/acme/issuers", "POST", {
        issuer: ISSUER_A,
        jwks_uri: KEYS_A,
      }),
      testEnv,
      "acme"
    );

    expect(added.status).toBe(200);
    const issuers = ((await added.json()) as any).tenant.trusted_issuers;
    expect(issuers).toHaveLength(2);
    expect(issuers[1]).toMatchObject({ issuer: ISSUER_A, jwks_uri: KEYS_A });
  });

  it("refuses the shared alias endpoints, which can assert any subject", async () => {
    // `/common`, `/organizations` and `/consumers` issue tokens for any Microsoft
    // tenant. The 1:1 issuer index would only have refused the SECOND tenant to
    // claim one — by which point the first had been granted an issuer that can
    // assert anybody. This is refused at registration, before any fetch.
    for (const alias of [
      "https://login.microsoftonline.com/common/v2.0",
      "https://login.microsoftonline.com/organizations/v2.0",
      "https://login.microsoftonline.com/consumers/v2.0",
      "https://login.microsoftonline.com",
      "https://sts.windows.net/common",
    ]) {
      const testEnv = env();
      const res = await putTenantWithIssuers(testEnv, "acme", [{ issuer: alias }]);
      expect(res.status, alias).toBe(400);
      const body = (await res.json()) as any;
      expect(body.error, alias).toBe("invalid_body");
      expect(body.error_description, alias).toContain("shared multi-tenant endpoint");
      expect(isSharedMultiTenantIssuer(alias), alias).toBe(true);
    }
    expect(fetchCalls).toEqual([]);
  });

  it("still accepts a tenant-specific issuer on the same shared host", async () => {
    const testEnv = env();
    publishDiscovery(ISSUER_A, { issuer: ISSUER_A, jwks_uri: KEYS_A });
    const res = await putTenantWithIssuers(testEnv, "acme", [{ issuer: ISSUER_A }]);
    expect(res.status).toBe(200);
    expect(isSharedMultiTenantIssuer(ISSUER_A)).toBe(false);
  });

  it("refuses the sibling binding when the issuer's own metadata does not confirm it", async () => {
    // This is what makes the sibling tier safe. Sharing the first path segment
    // is only structurally plausible; the issuer's own document has to name the
    // exact URL.
    const testEnv = env();
    publishDiscovery(ISSUER_A, {
      issuer: ISSUER_A,
      jwks_uri: `https://login.microsoftonline.com/${ENTRA_A}/discovery/v2.0/other-keys`,
    });

    const res = await putTenantWithIssuers(testEnv, "acme", [
      { issuer: ISSUER_A, jwks_uri: KEYS_A },
    ]);
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_body");
  });

  it("refuses the sibling binding when the issuer's metadata cannot be read", async () => {
    // No route published, so the host is unreachable. Fails closed, and says so
    // as a retryable condition rather than a malformed request.
    const testEnv = env();
    const res = await putTenantWithIssuers(testEnv, "acme", [
      { issuer: ISSUER_A, jwks_uri: KEYS_A },
    ]);
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("issuer_unreachable");
  });

  it("refuses a discovery document that claims a different issuer", async () => {
    // RFC 8414 §3.3. Without it, a document served anywhere could vouch for a
    // key source on behalf of an issuer it does not own.
    const testEnv = env();
    publishDiscovery(ISSUER_A, {
      issuer: `https://login.microsoftonline.com/${ENTRA_B}/v2.0`,
      jwks_uri: KEYS_A,
    });

    const res = await putTenantWithIssuers(testEnv, "acme", [
      { issuer: ISSUER_A, jwks_uri: KEYS_A },
    ]);
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("issuer_unreachable");
  });
});

describe("the cross-tenant attack the rule exists to stop", () => {
  it("refuses tenant A's issuer pointed at tenant B's key endpoint, with no fetch at all", async () => {
    // THE ATTACK. Same host, same vendor, same structural shape as the accepted
    // Entra row above — and refused, before any network call, because the tenant
    // discriminator segment differs.
    const testEnv = env();
    const issuerA = `https://login.microsoftonline.com/${ENTRA_A}/v2.0`;
    const keysB = `https://login.microsoftonline.com/${ENTRA_B}/discovery/v2.0/keys`;

    const res = await putTenantWithIssuers(testEnv, "acme", [
      { issuer: issuerA, jwks_uri: keysB },
    ]);
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_body");
    expect(fetchCalls).toEqual([]);
    expect(await lookupIssuerOwner(testEnv, issuerA)).toBeNull();
  });

  it("refuses it through the discovery branch too", async () => {
    // The discovery document is customer-controlled input, so the URL it names
    // gets the same binding check as one pasted by hand.
    const testEnv = env();
    const issuerA = `https://login.microsoftonline.com/${ENTRA_A}/v2.0`;
    publishDiscovery(issuerA, {
      issuer: issuerA,
      jwks_uri: `https://login.microsoftonline.com/${ENTRA_B}/discovery/v2.0/keys`,
    });

    const res = await putTenantWithIssuers(testEnv, "acme", [{ issuer: issuerA }]);
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("issuer_unreachable");
  });

  it("is not fooled by a path that merely starts with the neighbour's", async () => {
    // Prefix confusion: `/customer-abc` starts with the string `/customer-a`.
    // Segment arrays are compared, so this never depends on remembering to
    // append a separator.
    const testEnv = env();
    const res = await putTenantWithIssuers(testEnv, "acme", [
      { issuer: "https://idp.example/customer-a", jwks_uri: "https://idp.example/customer-abc/keys" },
    ]);
    expect(res.status).toBe(400);
    expect(fetchCalls).toEqual([]);
  });

  it("does not let a generic first segment stand in for a tenant boundary", async () => {
    // On a host whose first segment is a collection name, two customers share
    // it, so "same first segment" alone proves nothing — which is exactly why
    // the sibling tier must be confirmed by the issuer's own document. Here the
    // document names the issuer's own keys, not the neighbour's, so the
    // neighbour's URL is refused.
    const testEnv = env();
    const issuer = "https://idp.example/tenants/customer-a";
    publishDiscovery(issuer, {
      issuer,
      jwks_uri: "https://idp.example/tenants/customer-a/keys",
    });

    const res = await putTenantWithIssuers(testEnv, "acme", [
      { issuer, jwks_uri: "https://idp.example/tenants/customer-b/keys" },
    ]);
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_body");
  });
});

describe("a jwks_uri on an unrelated host is refused", () => {
  it.each([
    ["the attacker's own host", "https://attacker.example/keys"],
    ["a lookalike of the IdP host", `https://login.microsoftonline.evil.example/${ENTRA_A}/discovery/v2.0/keys`],
    ["the IdP host as a mere path", `https://evil.example/login.microsoftonline.com/${ENTRA_A}/keys`],
    ["this authorization server's own JWKS", "https://auth.techimpossible.com/.well-known/jwks.json"],
    ["a private network name", "https://vault.internal/keys"],
    ["plain http", `http://login.microsoftonline.com/${ENTRA_A}/discovery/v2.0/keys`],
  ])("%s", async (_name, jwksUri) => {
    const testEnv = env();
    const issuer = `https://login.microsoftonline.com/${ENTRA_A}/v2.0`;

    const res = await putTenantWithIssuers(testEnv, "acme", [{ issuer, jwks_uri: jwksUri }]);
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_body");
    // Same-origin is settled locally: nothing is fetched to find that out.
    expect(fetchCalls).toEqual([]);
  });

  it("refuses an off-origin jwks_uri named by an otherwise valid discovery document", async () => {
    const testEnv = env();
    const issuer = "https://sso.acme.example/realms/acme";
    publishDiscovery(issuer, { issuer, jwks_uri: "https://attacker.example/keys" });

    const res = await putTenantWithIssuers(testEnv, "acme", [{ issuer }]);
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("issuer_unreachable");
  });
});

describe("host exclusivity — what makes the origin-only tier as tight as the tenant boundary", () => {
  it("refuses a second tenant a trust domain on a host one tenant already owns whole", async () => {
    // A no-path issuer owns its whole origin, so its keys may be at any path
    // there. That is only safe while no OTHER tenant has a trust domain on the
    // same host, so the loosest tier is bounded by the data model rather than by
    // the network.
    const testEnv = env();
    const first = await putTenantWithIssuers(testEnv, "okta-org", [
      { issuer: "https://shared.okta.example", jwks_uri: "https://shared.okta.example/oauth2/v1/keys" },
    ]);
    expect(first.status).toBe(200);

    const second = await putTenantWithIssuers(testEnv, "other-customer", [
      {
        issuer: "https://shared.okta.example/oauth2/aus9z8y7x6w5v4u3t2s1",
        jwks_uri: "https://shared.okta.example/oauth2/aus9z8y7x6w5v4u3t2s1/v1/keys",
      },
    ]);
    expect(second.status).toBe(409);
    expect(((await second.json()) as any).error).toBe("issuer_conflict");
  });

  it("lets two path-scoped tenants share a host, which is how Entra and PingOne work", async () => {
    // Each is already bound to its own first path segment, so sharing the host
    // costs nothing. If this were refused, the second Entra customer could never
    // be onboarded at all.
    const testEnv = env();
    const issuerA = `https://login.microsoftonline.com/${ENTRA_A}/v2.0`;
    const issuerB = `https://login.microsoftonline.com/${ENTRA_B}/v2.0`;
    publishDiscovery(issuerA, {
      issuer: issuerA,
      jwks_uri: `https://login.microsoftonline.com/${ENTRA_A}/discovery/v2.0/keys`,
    });
    publishDiscovery(issuerB, {
      issuer: issuerB,
      jwks_uri: `https://login.microsoftonline.com/${ENTRA_B}/discovery/v2.0/keys`,
    });

    expect((await putTenantWithIssuers(testEnv, "customer-a", [{ issuer: issuerA }])).status).toBe(200);
    expect((await putTenantWithIssuers(testEnv, "customer-b", [{ issuer: issuerB }])).status).toBe(200);
    expect(await lookupIssuerOwner(testEnv, issuerA)).toBe("customer-a");
    expect(await lookupIssuerOwner(testEnv, issuerB)).toBe("customer-b");
  });

  it("lets one tenant keep both a whole-host issuer and a path-scoped one on that host", async () => {
    // The rule is about two DIFFERENT tenants. Inside one trust domain there is
    // nothing to separate.
    const testEnv = env();
    const res = await putTenantWithIssuers(testEnv, "okta-org", [
      { issuer: "https://acme.okta.example", jwks_uri: "https://acme.okta.example/oauth2/v1/keys" },
      {
        issuer: "https://acme.okta.example/oauth2/aus1a2b3c4d5e6f7g8h9",
        jwks_uri: "https://acme.okta.example/oauth2/aus1a2b3c4d5e6f7g8h9/v1/keys",
      },
    ]);
    expect(res.status).toBe(200);
  });
});

describe("classifyJwksBinding — the tiers, as a pure function", () => {
  it.each([
    // Underneath the issuer's own path: self-evident, accepted with no fetch.
    [
      "Keycloak realm",
      "https://sso.acme.example/realms/acme",
      "https://sso.acme.example/realms/acme/protocol/openid-connect/certs",
      "subtree",
    ],
    [
      "Okta custom authorization server",
      "https://acme.okta.example/oauth2/aus1a2b3c4d5e6f7g8h9",
      "https://acme.okta.example/oauth2/aus1a2b3c4d5e6f7g8h9/v1/keys",
      "subtree",
    ],
    // Beside the issuer path, inside the same tenant segment: needs the issuer's
    // own metadata to confirm.
    [
      "Entra v2.0",
      `https://login.microsoftonline.com/${ENTRA_A}/v2.0`,
      `https://login.microsoftonline.com/${ENTRA_A}/discovery/v2.0/keys`,
      "sibling",
    ],
    // The issuer carries no path, so it owns the whole host.
    ["Auth0", "https://acme.eu.auth0.example", "https://acme.eu.auth0.example/.well-known/jwks.json", "origin-only"],
    ["Okta org", "https://acme.okta.example", "https://acme.okta.example/oauth2/v1/keys", "origin-only"],
    // The tenant discriminator differs: the attack.
    [
      "cross-tenant on a shared host",
      `https://login.microsoftonline.com/${ENTRA_A}/v2.0`,
      `https://login.microsoftonline.com/${ENTRA_B}/discovery/v2.0/keys`,
      "reject",
    ],
    [
      "prefix confusion",
      "https://idp.example/customer-a",
      "https://idp.example/customer-abc/keys",
      "reject",
    ],
    ["off-origin", "https://sso.acme.example/realms/acme", "https://attacker.example/keys", "reject"],
    [
      "issuer with a path, jwks at the bare origin",
      "https://idp.example/customer-a",
      "https://idp.example/keys",
      "reject",
    ],
    [
      "a fragment, which is meaningless to a fetch",
      "https://sso.acme.example/realms/acme",
      "https://sso.acme.example/realms/acme/certs#keys",
      "reject",
    ],
  ])("%s", (_name, issuer, jwksUri, expected) => {
    expect(classifyJwksBinding(jwksUri, issuer)).toBe(expected);
  });
});
