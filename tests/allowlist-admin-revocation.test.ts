import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  SignJWT,
  type JWK,
  type JWTVerifyGetKey,
} from "jose";
import type { AuthCodeRecord, AuthStateRecord, TenantRecord } from "../src/env.js";
import { adminAllowlistDeniedHandler, adminAllowlistHandler } from "../src/allowlist/admin.js";
import { handleJwtBearerGrant, JWT_BEARER_GRANT } from "../src/oauth/jwt-bearer.js";
import { tokenHandler } from "../src/oauth/token.js";
import { createClient } from "../src/oauth/clients.js";
import { clearSigningKeyCache } from "../src/lib/crypto.js";
import { clearTenantJwksCache } from "../src/lib/tenant-jwks.js";
import { putIssuerIndex, putTenant } from "../src/tenants/store.js";

/**
 * REVOCATION AS A PIPELINE, from the operator's command to the grant that must
 * stop minting.
 *
 * `tests/refresh-revocation.test.ts` proved the TOKEN end: every use of a
 * refresh token re-reads `allowlist:<aud>` and re-decides. That fix is only half
 * the control, because it assumes the operator's revocation command actually
 * changed the record. It did not.
 *
 * `DELETE /admin/allowlist/<aud>` removed an entry from `emails[]` by EXACT
 * STRING equality, while `isEmailAllowed` — the consumer — lowercases, trims and
 * honours `*@domain` wildcards. Two consequences, both of which returned
 * HTTP 200 and revoked nobody:
 *
 *   (a) DELETE "Peter@Techimpossible.com" against a stored
 *       "peter@techimpossible.com" matched nothing.
 *   (b) Against a domain-scoped audience — `["*@techimpossible.com"]`, the
 *       likely production shape — DELETE of ANY individual address matched
 *       nothing, so the revoked user kept refreshing forever.
 *
 * A success response for a revocation that did not take effect is worse than an
 * error: the operator stops looking. So the contract asserted here is not just
 * "removal works" but "a silent 200-with-no-effect is impossible" — every 200
 * carries a `decision_after` verdict recomputed from the record that was
 * actually written, and any refusal names the blocker and writes nothing.
 *
 * The deny list is the mechanism that makes (b) revocable at all without
 * deprovisioning the whole customer. It is enforced inside
 * `evaluateAllowlistRecord`, which is reached through `checkStillAuthorized` —
 * so the last describe block below proves all THREE consumers honour it: the
 * interactive Google path, the refresh grant, and the EMA jwt-bearer grant.
 *
 * Everything below the KV seam is the real thing: the real admin handlers, the
 * real token handler, the real callback handler, the real EMA grant.
 */

/** Mutable stub state for the interactive path. Hoisted: vi.mock factories are. */
const google = vi.hoisted(() => ({
  email: "revoked.user@acme.example",
  sub: "google-subject-9001",
}));

vi.mock("../src/google/exchange.js", () => ({
  exchangeGoogleAuthCode: async () => ({
    id_token: "synthetic-google-id-token",
    token_type: "Bearer",
  }),
}));

vi.mock("../src/google/verify.js", () => ({
  verifyGoogleIdToken: async () => ({
    email: google.email,
    sub: google.sub,
    emailVerified: true,
    payload: {},
  }),
}));

const { googleCallbackHandler } = await import("../src/google/callback.js");

type Put = { key: string; value: string };

/** KV that records writes, so "nothing was written" is assertable, and that can
 *  be made to fail its reads. */
function inMemoryKV() {
  const map = new Map<string, string>();
  const puts: Put[] = [];
  // `swallowPuts` models a LOST UPDATE: the put resolves successfully, exactly
  // as KV does, but the stored value is not the one we wrote — because a
  // concurrent writer won. KV has no compare-and-swap, so this is reachable in
  // production and is invisible to any check that trusts the in-memory object.
  const state = { failGets: false, failPuts: false, swallowPuts: false };
  return {
    __puts: puts,
    __state: state,
    async get(key: string, opts?: any) {
      if (state.failGets) throw new Error("synthetic KV read failure");
      const v = map.get(key);
      if (v === undefined) return null;
      if (opts === "json" || (opts && opts.type === "json")) return JSON.parse(v);
      return v;
    },
    async put(key: string, value: string) {
      if (state.failPuts) throw new Error("synthetic KV write failure");
      puts.push({ key, value });
      if (state.swallowPuts) return; // resolves, but the write does not land
      map.set(key, value);
    },
    async delete(key: string) {
      map.delete(key);
    },
    async list(opts?: { prefix?: string }) {
      const names = [...map.keys()].filter((n) => !opts?.prefix || n.startsWith(opts.prefix));
      return { keys: names.map((name) => ({ name })), list_complete: true, cursor: "" };
    },
  };
}

const ISSUER = "https://auth.example.test";
const ADMIN_TOKEN = "synthetic-admin-token";
const AUD = "compliance-mcp";
const REDIRECT_URI = "http://127.0.0.1/callback";

/** The two identities at the wildcard-scoped customer. Revoking one must not
 *  touch the other — that is the whole point of a deny entry over removing the
 *  pattern. */
const REVOKED = "revoked.user@acme.example";
const COLLEAGUE = "kept.user@acme.example";

const IDP_ISSUER = "https://idp.acme.example";
const IDP_JWKS = "https://idp.acme.example/jwks";
const IDP_KID = "synthetic-idp-key-1";

function env() {
  clearSigningKeyCache();
  clearTenantJwksCache();
  return {
    OAUTH_KV: inMemoryKV(),
    ALLOWLIST_KV: inMemoryKV(),
    TENANT_KV: inMemoryKV(),
    ISSUER,
    ADMIN_API_TOKEN: ADMIN_TOKEN,
    GOOGLE_OIDC_CLIENT_ID: "synthetic-oidc-client.apps.googleusercontent.test",
    GOOGLE_OIDC_CLIENT_SECRET: "synthetic-value-not-a-credential",
  } as any;
}

/** Admin routes and grants each log one structured line; keep the output clean.
 *  One test below asserts on what those lines do NOT contain. */
const logLines: string[] = [];
beforeEach(() => {
  logLines.length = 0;
  google.email = REVOKED;
  google.sub = "google-subject-9001";
  vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    logLines.push(args.map((a) => String(a)).join(" "));
  });
});
afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// admin plumbing
// ---------------------------------------------------------------------------

function adminRequest(method: string, aud: string, body?: unknown, path = ""): Request {
  return new Request(`${ISSUER}/admin/allowlist/${aud}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${ADMIN_TOKEN}`,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

/** DELETE /admin/allowlist/<aud> — THE revocation command. */
async function revoke(testEnv: any, aud: string, body: unknown): Promise<Response> {
  return adminAllowlistHandler(adminRequest("DELETE", aud, body), testEnv, aud);
}

async function denied(
  testEnv: any,
  aud: string,
  method: string,
  body?: unknown
): Promise<Response> {
  return adminAllowlistDeniedHandler(
    adminRequest(method, aud, body, "/denied"),
    testEnv,
    aud
  );
}

async function storedRecord(testEnv: any, aud: string): Promise<any> {
  return testEnv.ALLOWLIST_KV.get(`allowlist:${aud}`, "json");
}

async function installAllowlist(
  testEnv: any,
  aud: string,
  emails: string[],
  deniedEntries?: string[]
): Promise<void> {
  await testEnv.ALLOWLIST_KV.put(
    `allowlist:${aud}`,
    JSON.stringify({ emails, ...(deniedEntries ? { denied: deniedEntries } : {}) })
  );
}

/** Writes to ALLOWLIST_KV made after this point. */
function allowlistWritesSince(testEnv: any, mark: number): Put[] {
  return (testEnv.ALLOWLIST_KV.__puts as Put[]).slice(mark);
}

function writeMark(testEnv: any): number {
  return (testEnv.ALLOWLIST_KV.__puts as Put[]).length;
}

// ---------------------------------------------------------------------------
// consumer 1: the refresh grant
// ---------------------------------------------------------------------------

function tokenRequest(params: Record<string, string>): Request {
  return new Request(`${ISSUER}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params).toString(),
  });
}

type Chain = { clientId: string; clientSecret: string; refreshToken: string };

/**
 * A refresh chain issued through the real authorization_code exchange, for a
 * named identity. The exchange does not consult the allowlist (the interactive
 * path already decided), which is what lets a test issue a chain and then revoke
 * the identity underneath it.
 */
async function issueChain(testEnv: any, email: string, aud = AUD): Promise<Chain> {
  const { record, clientSecret } = await createClient(testEnv, {
    redirect_uris: [REDIRECT_URI],
  });
  const code = `synthetic-auth-code-${Math.random().toString(36).slice(2)}`;
  const authCode: AuthCodeRecord = {
    clientId: record.clientId,
    userId: email,
    redirectUri: REDIRECT_URI,
    scope: "openid email offline_access",
    codeChallenge: null,
    codeChallengeMethod: null,
    props: { email, sub: `sub-${email}`, tenant_id: null, roles: [] },
    aud,
    createdAt: Math.floor(Date.now() / 1000),
  };
  await testEnv.OAUTH_KV.put(`authcode:${code}`, JSON.stringify(authCode));

  const res = await tokenHandler(
    tokenRequest({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: record.clientId,
      client_secret: clientSecret!,
    }),
    testEnv
  );
  expect(res.status).toBe(200);
  const body = (await res.json()) as any;
  return { clientId: record.clientId, clientSecret: clientSecret!, refreshToken: body.refresh_token };
}

async function refresh(testEnv: any, chain: Chain): Promise<Response> {
  return tokenHandler(
    tokenRequest({
      grant_type: "refresh_token",
      refresh_token: chain.refreshToken,
      client_id: chain.clientId,
      client_secret: chain.clientSecret,
    }),
    testEnv
  );
}

// ---------------------------------------------------------------------------
// consumer 2: the interactive Google path
// ---------------------------------------------------------------------------

async function interactiveCallback(testEnv: any, aud = AUD): Promise<Response> {
  const { record } = await createClient(testEnv, {
    redirect_uris: ["https://client.example.test/callback"],
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  });
  const state = `synthetic-state-${Math.random().toString(36).slice(2)}`;
  const stateRecord: AuthStateRecord = {
    responseType: "code",
    clientId: record.clientId,
    redirectUri: "https://client.example.test/callback",
    scope: "openid email",
    state: "client-state-0001",
    codeChallenge: null,
    codeChallengeMethod: null,
    aud,
    createdAt: Math.floor(Date.now() / 1000),
  };
  await testEnv.OAUTH_KV.put(`authstate:${state}`, JSON.stringify(stateRecord));
  return googleCallbackHandler(
    new Request(`${ISSUER}/oauth/callback?code=synthetic-google-code&state=${state}`),
    testEnv
  );
}

// ---------------------------------------------------------------------------
// consumer 3: the EMA jwt-bearer grant
// ---------------------------------------------------------------------------

async function makeIdp() {
  const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
  const jwk = (await exportJWK(publicKey)) as JWK;
  jwk.kid = IDP_KID;
  jwk.alg = "RS256";
  jwk.use = "sig";
  const jwks = { keys: [jwk] };
  return { privateKey, kid: IDP_KID, keySet: createLocalJWKSet(jwks) as JWTVerifyGetKey };
}

type Idp = Awaited<ReturnType<typeof makeIdp>>;

function keySetDep(idp: Idp) {
  return { resolveKeySet: async () => idp.keySet };
}

async function emaFixture(testEnv: any) {
  const { record: client } = await createClient(testEnv, {
    redirect_uris: [],
    client_name: "claude-ema",
    token_endpoint_auth_method: "none",
    grant_types: [JWT_BEARER_GRANT],
    response_types: [],
    registration_source: "admin",
  });
  const idp = await makeIdp();
  const now = Math.floor(Date.now() / 1000);
  const tenant: TenantRecord = {
    tenantId: "acme",
    displayName: "Acme Corp",
    status: "active",
    trustedIssuers: [{ issuer: IDP_ISSUER, jwksUri: IDP_JWKS, addedAt: now }],
    allowedAudiences: [AUD],
    allowedClientIds: [client.clientId],
    emailDomains: ["*@acme.example"],
    createdAt: now,
    updatedAt: now,
  };
  await putTenant(testEnv, tenant);
  await putIssuerIndex(testEnv, IDP_ISSUER, tenant.tenantId);
  return { client, idp };
}

async function emaGrant(
  testEnv: any,
  fixture: { client: any; idp: Idp },
  email: string
): Promise<Response> {
  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({
    iss: IDP_ISSUER,
    aud: ISSUER,
    sub: `idp-sub-${email}`,
    jti: `jti-${Math.random().toString(36).slice(2)}`,
    client_id: fixture.client.clientId,
    email,
    email_verified: true,
    iat: now,
    exp: now + 300,
  })
    .setProtectedHeader({ alg: "RS256", kid: fixture.idp.kid, typ: "oauth-id-jag+jwt" })
    .sign(fixture.idp.privateKey);

  const form = new URLSearchParams({
    grant_type: JWT_BEARER_GRANT,
    client_id: fixture.client.clientId,
    assertion,
    resource: AUD,
    scope: "openid email",
  });
  return handleJwtBearerGrant(tokenRequest(Object.fromEntries(form)), testEnv, form, keySetDep(fixture.idp) as any);
}

// ===========================================================================

describe("revocation — the operator's DELETE matches the way the consumer matches", () => {
  it("revokes a stored literal sent in different case and with surrounding whitespace", async () => {
    // DEFECT (a). `emails.filter(e => e !== body.email)` against a stored
    // "peter@techimpossible.com" left the entry untouched for
    // "  Peter@Techimpossible.com  " and still answered 200. The operator had
    // every reason to believe the user was revoked.
    const testEnv = env();
    await installAllowlist(testEnv, AUD, ["peter@techimpossible.com", "other@techimpossible.com"]);
    const chain = await issueChain(testEnv, "peter@techimpossible.com");
    expect((await refresh(testEnv, chain)).status).toBe(200);

    const res = await revoke(testEnv, AUD, { email: "  Peter@Techimpossible.com  " });

    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.outcome).toBe("removed");
    expect(body.changed).toBe(true);
    expect(body.removed).toEqual(["peter@techimpossible.com"]);
    // The 200 is gated on a verdict recomputed from what was written.
    expect(body.decision_after.status).toBe("denied");

    // The record really changed, and only for the intended entry.
    expect((await storedRecord(testEnv, AUD)).emails).toEqual(["other@techimpossible.com"]);

    // THE POINT: the next refresh is refused.
    const after = await refresh(testEnv, chain);
    expect(after.status).toBe(400);
    expect(((await after.json()) as any).error).toBe("invalid_grant");
  });

  it("normalizes the address stored by POST, so a later revocation can find it", async () => {
    // The other half of the same defect: if a grant stores "Bob@Acme.Example"
    // verbatim, a normalized DELETE would miss it. Both ends normalize.
    const testEnv = env();
    await installAllowlist(testEnv, AUD, ["seed@acme.example"]);

    const added = await adminAllowlistHandler(
      adminRequest("POST", AUD, { email: "  Bob@Acme.Example  " }),
      testEnv,
      AUD
    );
    expect(added.status).toBe(200);
    expect((await storedRecord(testEnv, AUD)).emails).toContain("bob@acme.example");

    const res = await revoke(testEnv, AUD, { email: "bob@acme.example" });
    expect(res.status).toBe(200);
    expect(((await res.json()) as any).decision_after.status).toBe("denied");
    expect((await storedRecord(testEnv, AUD)).emails).not.toContain("bob@acme.example");
  });
});

describe("revocation — a wildcard-scoped audience, where removal alone revokes nobody", () => {
  it("revokes one identity under '*@domain' and leaves the pattern and everyone else intact", async () => {
    // DEFECT (b), the production shape. `["*@acme.example"]` authorizes bob
    // without listing him, so there is no entry to remove: the old handler
    // answered 200 having changed nothing, and bob refreshed forever.
    const testEnv = env();
    await installAllowlist(testEnv, AUD, ["*@acme.example"]);
    const revokedChain = await issueChain(testEnv, REVOKED);
    const colleagueChain = await issueChain(testEnv, COLLEAGUE);
    expect((await refresh(testEnv, revokedChain)).status).toBe(200);

    const res = await revoke(testEnv, AUD, { email: REVOKED });

    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.outcome).toBe("denied");
    expect(body.changed).toBe(true);
    expect(body.denied_added).toEqual([REVOKED]);
    expect(body.covering_patterns).toEqual(["*@acme.example"]);
    expect(body.decision_after).toMatchObject({ status: "denied", reason: "deny_entry" });

    // The customer's pattern is untouched — this is a revocation, not a
    // deprovisioning.
    const record = await storedRecord(testEnv, AUD);
    expect(record.emails).toEqual(["*@acme.example"]);
    expect(record.denied).toEqual([REVOKED]);

    // The revoked user is refused...
    const after = await refresh(testEnv, revokedChain);
    expect(after.status).toBe(400);
    expect(((await after.json()) as any).error).toBe("invalid_grant");

    // ...and the colleague, still covered by the same pattern, is not.
    expect((await refresh(testEnv, colleagueChain)).status).toBe(200);
  });

  it("refuses with 409 and writes nothing when remove_only cannot reach the wildcard", async () => {
    // The contract for an operator who explicitly asks not to add a deny entry:
    // a NON-2xx that names the blocker. Never a 200 that did nothing.
    const testEnv = env();
    await installAllowlist(testEnv, AUD, ["*@acme.example"]);
    const chain = await issueChain(testEnv, REVOKED);
    const mark = writeMark(testEnv);

    const res = await revoke(testEnv, AUD, { email: REVOKED, mode: "remove_only" });

    expect(res.status).toBe(409);
    const body = (await res.json()) as any;
    expect(body.error).toBe("covered_by_wildcard");
    expect(body.covering_patterns).toEqual(["*@acme.example"]);
    expect(body.changed).toBe(false);
    // It names both ways forward rather than leaving the operator guessing.
    expect(body.error_description).toContain("*@acme.example");

    expect(allowlistWritesSince(testEnv, mark)).toEqual([]);
    // Still authorized, and the response said so.
    expect((await refresh(testEnv, chain)).status).toBe(200);
  });

  it("will not deprovision a whole customer without explicit confirmation", async () => {
    // Removing '*@acme.example' is a legitimate operation and still works, but a
    // single-user revocation command must not be able to reach it by accident.
    const testEnv = env();
    await installAllowlist(testEnv, AUD, ["*@acme.example"]);
    const colleagueChain = await issueChain(testEnv, COLLEAGUE);
    const mark = writeMark(testEnv);

    const refused = await revoke(testEnv, AUD, { email: "*@acme.example" });
    expect(refused.status).toBe(409);
    expect(((await refused.json()) as any).error).toBe(
      "wildcard_removal_requires_confirmation"
    );
    expect(allowlistWritesSince(testEnv, mark)).toEqual([]);
    expect((await refresh(testEnv, colleagueChain)).status).toBe(200);

    const confirmed = await revoke(testEnv, AUD, {
      email: "*@acme.example",
      confirm_wildcard_removal: true,
    });
    expect(confirmed.status).toBe(200);
    const body = (await confirmed.json()) as any;
    expect(body.outcome).toBe("wildcard_removed");
    expect(body.decision_after.status).toBe("denied");

    // Now everyone at the domain is out, which is what was confirmed.
    const after = await refresh(testEnv, colleagueChain);
    expect(after.status).toBe(400);
  });
});

describe("revocation — a success response always means the identity is actually revoked", () => {
  it("never answers 2xx for an address it did not revoke", async () => {
    // The invariant, swept across every shape an operator can send at a
    // wildcard-scoped audience. A 200 is only ever paired with a denied verdict
    // computed from the stored record; anything else is a named refusal.
    const testEnv = env();

    const cases: Array<{ label: string; body: unknown; emails: string[] }> = [
      { label: "literal present", body: { email: REVOKED }, emails: [REVOKED, COLLEAGUE] },
      { label: "covered by wildcard", body: { email: REVOKED }, emails: ["*@acme.example"] },
      { label: "case-shifted literal", body: { email: "REVOKED.USER@ACME.EXAMPLE" }, emails: [REVOKED] },
      { label: "remove_only under wildcard", body: { email: REVOKED, mode: "remove_only" }, emails: ["*@acme.example"] },
      { label: "not listed at all", body: { email: REVOKED }, emails: [COLLEAGUE] },
      { label: "wildcard, unconfirmed", body: { email: "*@acme.example" }, emails: ["*@acme.example"] },
    ];

    for (const testCase of cases) {
      const caseEnv = env();
      await installAllowlist(caseEnv, AUD, testCase.emails);
      const res = await revoke(caseEnv, AUD, testCase.body);
      const body = (await res.json()) as any;

      if (res.status === 200) {
        // A 200 must be backed by the stored record denying the address.
        expect(body.decision_after?.status, testCase.label).toBe("denied");
        const record = await storedRecord(caseEnv, AUD);
        const chain = await issueChain(caseEnv, REVOKED);
        expect(
          (await refresh(caseEnv, chain)).status,
          `${testCase.label} answered 200 over ${JSON.stringify(record)}`
        ).toBe(400);
      } else {
        // Any other answer must be a refusal that names the blocker and says
        // plainly that nothing changed.
        expect(res.status, testCase.label).toBeGreaterThanOrEqual(400);
        expect(body.error, testCase.label).toBeTruthy();
        expect(body.changed, testCase.label).toBe(false);
      }
    }
    void testEnv;
  });

  it("answers 404, not 200, for an address no entry authorizes", async () => {
    // A typo'd revocation that returns success is how an operator ends up
    // believing a live identity is gone.
    const testEnv = env();
    await installAllowlist(testEnv, AUD, [COLLEAGUE]);
    const mark = writeMark(testEnv);

    const res = await revoke(testEnv, AUD, { email: "typo@acme.example" });

    expect(res.status).toBe(404);
    const body = (await res.json()) as any;
    expect(body.error).toBe("not_allowlisted");
    expect(body.changed).toBe(false);
    expect(allowlistWritesSince(testEnv, mark)).toEqual([]);
  });

  it("answers 404 for an audience that has no record, and creates nothing", async () => {
    const testEnv = env();
    const mark = writeMark(testEnv);

    const res = await revoke(testEnv, AUD, { email: REVOKED });

    expect(res.status).toBe(404);
    expect(((await res.json()) as any).error).toBe("allowlist_not_found");
    // A revocation must never be the thing that creates a live-looking record.
    expect(allowlistWritesSince(testEnv, mark)).toEqual([]);
    expect(await storedRecord(testEnv, AUD)).toBeNull();
  });

  it("answers 404 for an audience name no token is ever minted for", async () => {
    const testEnv = env();
    const res = await revoke(testEnv, "compliance_mcp", { email: REVOKED });
    expect(res.status).toBe(404);
    const body = (await res.json()) as any;
    expect(body.error).toBe("unknown_audience");
    expect(body.supported_audiences).toContain(AUD);
  });

  it("is idempotent: re-revoking an already-revoked identity stays 200 and writes nothing", async () => {
    const testEnv = env();
    await installAllowlist(testEnv, AUD, ["*@acme.example"], [REVOKED]);
    const mark = writeMark(testEnv);

    const res = await revoke(testEnv, AUD, { email: REVOKED });

    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.outcome).toBe("already_revoked");
    expect(body.changed).toBe(false);
    expect(body.decision_after.status).toBe("denied");
    expect(allowlistWritesSince(testEnv, mark)).toEqual([]);
  });

  it("answers 503 and writes nothing when the record is malformed", async () => {
    // ITEM 4's distinction, at the operator end: a corrupt record is an
    // infrastructure fault, not "this user is not listed". Reporting 404 here
    // would invite the operator to "fix" it by re-adding entries to a record
    // they cannot see.
    const testEnv = env();
    await testEnv.ALLOWLIST_KV.put(`allowlist:${AUD}`, JSON.stringify({ emails: "not-an-array" }));
    const mark = writeMark(testEnv);

    const res = await revoke(testEnv, AUD, { email: REVOKED });

    expect(res.status).toBe(503);
    const body = (await res.json()) as any;
    expect(body.error).toBe("temporarily_unavailable");
    expect(body.changed).toBe(false);
    expect(res.headers.get("retry-after")).toBe("5");
    expect(allowlistWritesSince(testEnv, mark)).toEqual([]);
  });

  it("answers 503, not 200, when the write itself fails", async () => {
    // The operator must not be told a revocation landed when KV rejected it.
    const testEnv = env();
    await installAllowlist(testEnv, AUD, ["*@acme.example"]);
    testEnv.ALLOWLIST_KV.__state.failPuts = true;

    const res = await revoke(testEnv, AUD, { email: REVOKED });

    expect(res.status).toBe(503);
    expect(((await res.json()) as any).error).toBe("temporarily_unavailable");
  });

  it("still requires the admin bearer token", async () => {
    // The revocation route is not a place to have loosened the guard.
    const testEnv = env();
    await installAllowlist(testEnv, AUD, [REVOKED]);

    const res = await adminAllowlistHandler(
      new Request(`${ISSUER}/admin/allowlist/${AUD}`, {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: REVOKED }),
      }),
      testEnv,
      AUD
    );
    expect(res.status).toBe(401);
    expect((await storedRecord(testEnv, AUD)).emails).toEqual([REVOKED]);
  });

  it("keeps the revoked address out of the audit log", async () => {
    // The address goes to the authenticated operator in the response body and is
    // hashed in the log, matching the existing sub_hash discipline.
    const testEnv = env();
    await installAllowlist(testEnv, AUD, ["*@acme.example"]);

    await revoke(testEnv, AUD, { email: REVOKED });

    const adminLines = logLines.filter((line) => line.includes("allowlist_admin"));
    expect(adminLines.length).toBeGreaterThan(0);
    for (const line of adminLines) {
      expect(line).not.toContain(REVOKED);
      expect(line).not.toContain("revoked.user");
    }
    // The domain is kept, because it is what makes a log line actionable.
    expect(adminLines.some((line) => line.includes("acme.example"))).toBe(true);
  });
});

describe("revocation — the deny entry is honoured by all three grants that mint an identity", () => {
  /**
   * A control enforced on one path and not another is not a control. All three
   * consumers reach the deny list through `checkStillAuthorized`, and this block
   * is what proves it stays that way: the interactive Google path, the refresh
   * grant, and the EMA jwt-bearer grant, each against the same stored record.
   */

  it("refuses the interactive Google callback for a denied identity", async () => {
    const testEnv = env();
    await installAllowlist(testEnv, AUD, ["*@acme.example"], [REVOKED]);
    google.email = REVOKED;

    const res = await interactiveCallback(testEnv);

    expect(res.status).toBe(403);
    // Nothing to redeem: no authorization code was written.
    const codes = await testEnv.OAUTH_KV.list({ prefix: "authcode:" });
    expect(codes.keys).toEqual([]);
  });

  it("still admits a colleague the same wildcard covers, on that same path", async () => {
    const testEnv = env();
    await installAllowlist(testEnv, AUD, ["*@acme.example"], [REVOKED]);
    google.email = COLLEAGUE;

    const res = await interactiveCallback(testEnv);

    expect(res.status).toBe(302);
    const codes = await testEnv.OAUTH_KV.list({ prefix: "authcode:" });
    expect(codes.keys).toHaveLength(1);
  });

  it("refuses the refresh grant for a denied identity, and keeps serving a colleague", async () => {
    const testEnv = env();
    await installAllowlist(testEnv, AUD, ["*@acme.example"]);
    const revokedChain = await issueChain(testEnv, REVOKED);
    const colleagueChain = await issueChain(testEnv, COLLEAGUE);

    await installAllowlist(testEnv, AUD, ["*@acme.example"], [REVOKED]);

    const refused = await refresh(testEnv, revokedChain);
    expect(refused.status).toBe(400);
    expect(((await refused.json()) as any).error).toBe("invalid_grant");

    expect((await refresh(testEnv, colleagueChain)).status).toBe(200);
  });

  it("refuses the EMA jwt-bearer grant for a denied identity, and keeps serving a colleague", async () => {
    // EMA is the path where the tenant, not Techimpossible, controls the
    // identity — so the per-audience deny list is the only lever an operator
    // here holds over it.
    const testEnv = env();
    await installAllowlist(testEnv, AUD, ["*@acme.example"], [REVOKED]);
    const fixture = await emaFixture(testEnv);

    const refused = await emaGrant(testEnv, fixture, REVOKED);
    expect(refused.status).toBe(400);
    expect(((await refused.json()) as any).error).toBe("invalid_grant");

    const allowed = await emaGrant(testEnv, fixture, COLLEAGUE);
    expect(allowed.status).toBe(200);
    expect(typeof ((await allowed.json()) as any).access_token).toBe("string");
  });

  it("scopes a deny entry to its own audience", async () => {
    // The allowlist is per-audience, and so is the deny list. Revoking a user
    // from compliance-mcp must not silently revoke them from basecamp-mcp.
    const testEnv = env();
    await installAllowlist(testEnv, AUD, ["*@acme.example"], [REVOKED]);
    await installAllowlist(testEnv, "basecamp-mcp", ["*@acme.example"]);

    const chainHere = await issueChain(testEnv, REVOKED, AUD);
    const chainThere = await issueChain(testEnv, REVOKED, "basecamp-mcp");

    expect((await refresh(testEnv, chainHere)).status).toBe(400);
    expect((await refresh(testEnv, chainThere)).status).toBe(200);
  });
});

describe("re-instatement — the deny entry an operator added can be taken back off", () => {
  it("re-authorizes a user through the deny sub-resource", async () => {
    const testEnv = env();
    await installAllowlist(testEnv, AUD, ["*@acme.example"]);
    const chain = await issueChain(testEnv, REVOKED);

    await revoke(testEnv, AUD, { email: REVOKED });
    expect((await refresh(testEnv, chain)).status).toBe(400);

    const listed = await denied(testEnv, AUD, "GET");
    expect(listed.status).toBe(200);
    expect(((await listed.json()) as any).denied).toEqual([REVOKED]);

    const res = await denied(testEnv, AUD, "DELETE", { email: "  Revoked.User@Acme.Example  " });
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.outcome).toBe("deny_entry_removed");
    expect(body.decision_after).toMatchObject({ status: "allowed" });

    // A fresh chain works again; the wildcard authorizes them as it did before.
    const fresh = await issueChain(testEnv, REVOKED);
    expect((await refresh(testEnv, fresh)).status).toBe(200);
  });

  it("answers 404 when there is no such deny entry to remove", async () => {
    const testEnv = env();
    await installAllowlist(testEnv, AUD, ["*@acme.example"]);

    const res = await denied(testEnv, AUD, "DELETE", { email: REVOKED });
    expect(res.status).toBe(404);
    expect(((await res.json()) as any).error).toBe("deny_entry_not_found");
  });

  it("refuses to re-add an address a deny entry still covers, rather than pretending to", async () => {
    // POST /admin/allowlist/<aud> for a denied address would be evaluated
    // deny-first and have no effect, so it is a 409 naming the deny entry, not a
    // 200 the operator will trust.
    const testEnv = env();
    await installAllowlist(testEnv, AUD, ["*@acme.example"], [REVOKED]);

    const res = await adminAllowlistHandler(
      adminRequest("POST", AUD, { email: REVOKED }),
      testEnv,
      AUD
    );

    expect(res.status).toBe(409);
    const body = (await res.json()) as any;
    expect(body.error).toBe("denied_entry_conflict");
    expect(body.covering_deny_patterns).toEqual([REVOKED]);
    expect(body.changed).toBe(false);
  });

  it("preserves the deny list across a PUT that does not mention it", async () => {
    // A routine "replace the emails" call must not quietly resurrect everyone
    // who was revoked.
    const testEnv = env();
    await installAllowlist(testEnv, AUD, ["*@acme.example"], [REVOKED]);

    const res = await adminAllowlistHandler(
      adminRequest("PUT", AUD, { emails: ["*@acme.example", "new@acme.example"] }),
      testEnv,
      AUD
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.denied_preserved).toBe(true);
    expect((await storedRecord(testEnv, AUD)).denied).toEqual([REVOKED]);

    const chain = await issueChain(testEnv, REVOKED);
    expect((await refresh(testEnv, chain)).status).toBe(400);
  });

  it("clears the deny list only when a PUT says so explicitly", async () => {
    const testEnv = env();
    await installAllowlist(testEnv, AUD, ["*@acme.example"], [REVOKED]);

    const res = await adminAllowlistHandler(
      adminRequest("PUT", AUD, { emails: ["*@acme.example"], denied: [] }),
      testEnv,
      AUD
    );

    expect(res.status).toBe(200);
    const chain = await issueChain(testEnv, REVOKED);
    expect((await refresh(testEnv, chain)).status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// The success gate must reflect KV, not intent
// ---------------------------------------------------------------------------

/**
 * The gate that proves a revocation took effect used to re-evaluate the
 * IN-MEMORY object the handler had just built, not the record KV actually kept.
 *
 * That is the original bug wearing the costume of its own fix. Workers KV has no
 * compare-and-swap, so under a concurrent write the last writer wins and the
 * in-memory object becomes a claim about a record that does not exist. The
 * handler would then return HTTP 200 with `decision_after: denied` for a deny
 * entry that is not stored — a success response for a revocation that did not
 * take effect, which is precisely what this contract exists to prevent.
 *
 * `swallowPuts` reproduces the lost update: every put resolves, nothing lands.
 * No response on any mutating route may claim success under that condition.
 */
describe("success gate reads back from KV", () => {
  it("refuses to report a revocation that KV did not keep", async () => {
    const testEnv = env();
    await installAllowlist(testEnv, AUD, ["*@acme.example"]);

    testEnv.ALLOWLIST_KV.__state.swallowPuts = true;
    const res = await revoke(testEnv, AUD, { email: REVOKED });

    expect(res.status).not.toBe(200);
    expect(res.status).toBeGreaterThanOrEqual(400);

    // The read-back returns the record the concurrent writer left behind, which
    // is itself valid — so the gate cannot detect this by validity. It detects
    // it by re-deciding: the identity is STILL ALLOWED by the stored record, so
    // the revocation demonstrably did not take effect and no 200 is possible.
    const body = (await res.json()) as any;
    expect(body.decision_after?.status ?? body.decision_after).not.toBe("denied");

    // And the record really is unchanged, so the refusal told the truth.
    const stored = await storedRecord(testEnv, AUD);
    expect(stored.denied ?? []).not.toContain(REVOKED);
  });

  it("refuses to report a grant that KV did not keep", async () => {
    const testEnv = env();
    await installAllowlist(testEnv, AUD, ["seed@acme.example"]);

    testEnv.ALLOWLIST_KV.__state.swallowPuts = true;
    const res = await adminAllowlistHandler(
      adminRequest("POST", AUD, { email: COLLEAGUE }),
      testEnv,
      AUD
    );

    expect(res.status).not.toBe(200);
    const stored = await storedRecord(testEnv, AUD);
    expect(stored.emails).not.toContain(COLLEAGUE);
  });

  it("refuses to report a deny entry that KV did not keep", async () => {
    const testEnv = env();
    await installAllowlist(testEnv, AUD, ["*@acme.example"]);

    testEnv.ALLOWLIST_KV.__state.swallowPuts = true;
    const res = await denied(testEnv, AUD, "POST", { email: REVOKED });

    expect(res.status).not.toBe(200);
    const stored = await storedRecord(testEnv, AUD);
    expect(stored.denied ?? []).not.toContain(REVOKED);
  });

  it("still succeeds normally when the write does land", async () => {
    const testEnv = env();
    await installAllowlist(testEnv, AUD, ["*@acme.example"]);

    const res = await revoke(testEnv, AUD, { email: REVOKED });

    expect(res.status).toBe(200);
    expect(((await res.json()) as any).decision_after.status).toBe("denied");
    expect((await storedRecord(testEnv, AUD)).denied).toContain(REVOKED);
  });
});
