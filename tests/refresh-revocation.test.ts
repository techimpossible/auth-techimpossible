import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { importJWK, jwtVerify } from "jose";
import type { AuthCodeRecord } from "../src/env.js";
import { tokenHandler } from "../src/oauth/token.js";
import { createClient } from "../src/oauth/clients.js";
import { clearSigningKeyCache, getSigningKey } from "../src/lib/crypto.js";

/**
 * REVOCATION, on the grant that is exercised most and was checked least.
 *
 * `handleRefreshGrant` used to re-mint an access token straight out of the
 * stored refresh record and never read `allowlist:<aud>` at all, while every
 * rotation wrote another full 30-day TTL. So `DELETE /admin/allowlist/<aud>`
 * stopped new logins and stopped nothing else: anyone already holding a refresh
 * token kept minting tokens indefinitely. The MCP-Auth runbook documents
 * revocation as effective within about an hour, which made the documented
 * control false rather than merely weak.
 *
 * The suite could not see it. `tests/token-grants-regression.test.ts` proves the
 * grant still WORKS; nothing proved it still DECIDES. This file asserts the
 * decision — that the grant re-runs the per-audience allowlist check on every
 * single use, and that it does so for the refresh records already sitting in
 * production KV, which were written in an older shape.
 *
 * Everything below the KV seam is the real thing: the real token handler, the
 * real client resolution and secret verification, the real
 * checkStillAuthorized, and real RS256 signing.
 */

type Put = { key: string; value: string; ttl?: number };

/**
 * KV that records what was written with which TTL (the rotated token's lifetime
 * is part of the fix) and that can be made to fail its reads (an ALLOWLIST_KV
 * blip must not read as a revocation).
 */
function inMemoryKV() {
  const map = new Map<string, string>();
  const puts: Put[] = [];
  const state = { failGets: false };
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
    async put(key: string, value: string, opts?: { expirationTtl?: number }) {
      puts.push({ key, value, ttl: opts?.expirationTtl });
      map.set(key, value);
    },
    async delete(key: string) {
      map.delete(key);
    },
    async list(opts?: { prefix?: string }) {
      const names = [...map.keys()].filter((name) => !opts?.prefix || name.startsWith(opts.prefix));
      return { keys: names.map((name) => ({ name })), list_complete: true, cursor: "" };
    },
  };
}

const ISSUER = "https://auth.example.test";
const REDIRECT_URI = "http://127.0.0.1/callback";
const USER = "peter.skaronis@techimpossible.com";
const SUBJECT = "google-subject-0001";
const DAY = 24 * 3600;
const REFRESH_IDLE_TTL = 30 * DAY;
/**
 * The absolute chain cap that used to live in src/oauth/token.ts, kept here only
 * as the yardstick for the tests that now prove age alone decides nothing. It
 * was removed because it scheduled an outage: `/authorize` needs a human at a
 * browser, so Hermes could not have re-authenticated itself when its chain
 * expired. `allowlist:<aud>`, re-decided on every use, is the revocation
 * control.
 */
const FORMER_CHAIN_CAP = 90 * DAY;

function env() {
  clearSigningKeyCache();
  return {
    OAUTH_KV: inMemoryKV(),
    ALLOWLIST_KV: inMemoryKV(),
    TENANT_KV: inMemoryKV(),
    ISSUER,
  } as any;
}

/** The grant logs one structured line per decision; keep it out of the output. */
let logSpy: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
  logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
});
afterEach(() => {
  vi.restoreAllMocks();
});

function tokenRequest(params: Record<string, string>): Request {
  return new Request(`${ISSUER}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params).toString(),
  });
}

async function installAllowlist(testEnv: any, aud: string, emails: string[]): Promise<void> {
  await testEnv.ALLOWLIST_KV.put(`allowlist:${aud}`, JSON.stringify({ emails }));
}

function now(): number {
  return Math.floor(Date.now() / 1000);
}

/** The authorization code the Google callback would have written. */
async function seedAuthCode(
  testEnv: any,
  clientId: string,
  overrides: Partial<AuthCodeRecord> = {}
): Promise<string> {
  const code = `synthetic-auth-code-${Math.random().toString(36).slice(2)}`;
  const record: AuthCodeRecord = {
    clientId,
    userId: USER,
    redirectUri: REDIRECT_URI,
    scope: "openid email offline_access",
    codeChallenge: null,
    codeChallengeMethod: null,
    props: { email: USER, sub: SUBJECT, tenant_id: null, roles: [] },
    aud: "compliance-mcp",
    createdAt: now(),
    ...overrides,
  };
  await testEnv.OAUTH_KV.put(`authcode:${code}`, JSON.stringify(record));
  return code;
}

type Chain = { clientId: string; clientSecret: string; refreshToken: string };

/**
 * A refresh chain issued the way production issues one: through the real
 * authorization_code exchange, so the stored record has the exact shape the
 * handler writes today. The exchange itself does not consult the allowlist (the
 * interactive path already decided at `src/google/callback.ts`), which is what
 * lets a test issue a chain and then revoke the identity underneath it.
 */
async function issueChain(testEnv: any, aud = "compliance-mcp"): Promise<Chain> {
  const { record, clientSecret } = await createClient(testEnv, {
    redirect_uris: [REDIRECT_URI],
  });
  const code = await seedAuthCode(testEnv, record.clientId, { aud });
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
  expect(typeof body.refresh_token).toBe("string");
  return {
    clientId: record.clientId,
    clientSecret: clientSecret!,
    refreshToken: body.refresh_token,
  };
}

async function refresh(testEnv: any, chain: Chain, token = chain.refreshToken): Promise<Response> {
  return tokenHandler(
    tokenRequest({
      grant_type: "refresh_token",
      refresh_token: token,
      client_id: chain.clientId,
      client_secret: chain.clientSecret,
    }),
    testEnv
  );
}

async function refreshRecord(testEnv: any, token: string): Promise<any | null> {
  return testEnv.OAUTH_KV.get(`refresh:${token}`, "json");
}

/** The TTL the handler asked KV for when it wrote this refresh token. */
function ttlFor(testEnv: any, token: string): number | undefined {
  const writes = (testEnv.OAUTH_KV.__puts as Put[]).filter((p) => p.key === `refresh:${token}`);
  return writes[writes.length - 1]?.ttl;
}

async function verifyAccessToken(testEnv: any, token: string, audience: string) {
  const material = await getSigningKey(testEnv.OAUTH_KV);
  const publicKey = await importJWK(material.publicJwk, "RS256");
  const { payload } = await jwtVerify(token, publicKey, {
    issuer: ISSUER,
    audience,
    algorithms: ["RS256"],
  });
  return payload;
}

describe("refresh_token grant — allowlist:<aud> is re-decided on every use", () => {
  it("mints a working access token while the identity is still authorized", async () => {
    const testEnv = env();
    await installAllowlist(testEnv, "compliance-mcp", ["*@techimpossible.com"]);
    const chain = await issueChain(testEnv);

    const res = await refresh(testEnv, chain);
    expect(res.status).toBe(200);

    const body = (await res.json()) as any;
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBe(3600);
    expect(body.scope).toBe("openid email offline_access");
    // Rotation (OAuth 2.0 Security BCP §4.14) survives the fix.
    expect(typeof body.refresh_token).toBe("string");
    expect(body.refresh_token).not.toBe(chain.refreshToken);

    // "Working" means a resource server can actually verify it.
    const payload = await verifyAccessToken(testEnv, body.access_token, "compliance-mcp");
    expect(payload.sub).toBe(SUBJECT);
    expect(payload.email).toBe(USER);
    expect(payload.email_verified).toBe(true);
    expect(payload.tenant_id).toBeNull();
    expect(payload.roles).toEqual([]);
  });

  it("refuses to re-mint once the identity is removed from allowlist:<aud>", async () => {
    // THE HEADLINE. Before the fix this second call returned 200 with a fresh
    // hour-long token, and would have kept doing so forever.
    const testEnv = env();
    await installAllowlist(testEnv, "compliance-mcp", [USER, "someone.else@techimpossible.com"]);
    const chain = await issueChain(testEnv);

    const before = await refresh(testEnv, chain);
    expect(before.status).toBe(200);
    const rotated = ((await before.json()) as any).refresh_token as string;

    // The operator's single revocation action: one PUT to ALLOWLIST_KV.
    await installAllowlist(testEnv, "compliance-mcp", ["someone.else@techimpossible.com"]);

    const after = await refresh(testEnv, chain, rotated);
    expect(after.status).toBe(400);
    const body = (await after.json()) as any;
    expect(body.error).toBe("invalid_grant");
    expect(body.access_token).toBeUndefined();
    expect(body.refresh_token).toBeUndefined();
  });

  it("keeps refusing on every subsequent attempt, and does not consume the record", async () => {
    // A denial is not a rotation: the record survives, because the credential is
    // powerless for as long as the address is off the list, and an address
    // removed by mistake must be repairable without a human at a browser.
    const testEnv = env();
    await installAllowlist(testEnv, "compliance-mcp", [USER]);
    const chain = await issueChain(testEnv);

    await installAllowlist(testEnv, "compliance-mcp", []);
    for (let attempt = 0; attempt < 3; attempt++) {
      const res = await refresh(testEnv, chain);
      expect(res.status, `attempt ${attempt}`).toBe(400);
    }
    expect(await refreshRecord(testEnv, chain.refreshToken)).not.toBeNull();

    // Re-authorized: the same token resumes, with no new interactive login.
    await installAllowlist(testEnv, "compliance-mcp", [USER]);
    const resumed = await refresh(testEnv, chain);
    expect(resumed.status).toBe(200);
  });

  it("fails closed when the audience has no allowlist record at all", async () => {
    // A missing key must read as "nobody", never as "no restriction in force".
    const testEnv = env();
    const chain = await issueChain(testEnv);

    const res = await refresh(testEnv, chain);
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
  });

  it("reports 503, not invalid_grant, when the allowlist record is present but malformed", async () => {
    // A corrupt record is an infrastructure fault, exactly like a failed read:
    // it mints nothing, but it must not be reported as a decision about this
    // identity. 400 invalid_grant reads as permanent to every OAuth client, so
    // one bad KV value used to deprovision an entire audience for good.
    const testEnv = env();
    await testEnv.ALLOWLIST_KV.put("allowlist:compliance-mcp", JSON.stringify({ emails: "*" }));
    const chain = await issueChain(testEnv);

    const res = await refresh(testEnv, chain);
    expect(res.status).toBe(503);
    expect(((await res.json()) as any).error).toBe("temporarily_unavailable");
    expect(res.headers.get("Retry-After")).toBe("5");

    // Nothing was minted and nothing was consumed, so repairing the record
    // restores service with no interactive re-authentication.
    expect(await refreshRecord(testEnv, chain.refreshToken)).not.toBeNull();
    await installAllowlist(testEnv, "compliance-mcp", [USER]);
    expect((await refresh(testEnv, chain)).status).toBe(200);
  });

  it("decides against the audience the chain was issued for, not any audience", async () => {
    // Per-audience authorization: the same person may hold compliance-mcp and
    // not basecamp-mcp, and a basecamp-mcp chain must not be rescued by a
    // compliance-mcp entry.
    const testEnv = env();
    await installAllowlist(testEnv, "compliance-mcp", [USER]);
    await installAllowlist(testEnv, "basecamp-mcp", ["someone.else@techimpossible.com"]);

    const basecamp = await issueChain(testEnv, "basecamp-mcp");
    expect((await refresh(testEnv, basecamp)).status).toBe(400);

    const compliance = await issueChain(testEnv, "compliance-mcp");
    expect((await refresh(testEnv, compliance)).status).toBe(200);
  });

  it("matches the address whole, not as a substring of an allowed domain", async () => {
    const testEnv = env();
    await installAllowlist(testEnv, "compliance-mcp", ["*@techimpossible.com"]);
    const chain = await issueChain(testEnv);

    // Rewrite the stored identity to a near miss, leaving everything else alone.
    const record = await refreshRecord(testEnv, chain.refreshToken);
    await testEnv.OAUTH_KV.put(
      `refresh:${chain.refreshToken}`,
      JSON.stringify({ ...record, email: "attacker@techimpossible.com.evil.test" })
    );

    expect((await refresh(testEnv, chain)).status).toBe(400);
  });

  it("returns 503 with Retry-After, not invalid_grant, when ALLOWLIST_KV cannot be read", async () => {
    // A KV blip is not a revocation. Collapsing it into 400 invalid_grant would
    // make a well-behaved client throw a still-valid credential away and demand
    // an interactive re-authentication — for a headless client, a human at a
    // browser, because of a transient read failure.
    const testEnv = env();
    await installAllowlist(testEnv, "compliance-mcp", [USER]);
    const chain = await issueChain(testEnv);

    testEnv.ALLOWLIST_KV.__state.failGets = true;
    const res = await refresh(testEnv, chain);
    expect(res.status).toBe(503);
    expect(((await res.json()) as any).error).toBe("temporarily_unavailable");
    expect(res.headers.get("Retry-After")).toBe("5");

    // The credential is untouched, so the retry the header invites succeeds.
    testEnv.ALLOWLIST_KV.__state.failGets = false;
    expect((await refresh(testEnv, chain)).status).toBe(200);
  });

  it("logs the decision without the email address or the token", async () => {
    // The log is how an operator answers "did that revocation take effect?", so
    // it has to exist — and it must not become a place secrets accumulate.
    const testEnv = env();
    await installAllowlist(testEnv, "compliance-mcp", [USER]);
    const chain = await issueChain(testEnv);

    const allowed = await refresh(testEnv, chain);
    const rotated = ((await allowed.json()) as any).refresh_token as string;
    await installAllowlist(testEnv, "compliance-mcp", []);
    await refresh(testEnv, chain, rotated);

    const lines = logSpy.mock.calls
      .map((call) => String(call[0]))
      .filter((line) => line.includes("refresh.token"))
      .map((line) => JSON.parse(line));
    expect(lines).toHaveLength(2);
    expect(lines[0]).toMatchObject({ decision: "allow", reason_code: "ok", aud: "compliance-mcp" });
    expect(lines[1]).toMatchObject({ decision: "deny", reason_code: "not_allowlisted" });

    for (const line of lines) {
      const serialized = JSON.stringify(line);
      expect(serialized).not.toContain(USER);
      expect(serialized).not.toContain(chain.refreshToken);
      expect(serialized).not.toContain(rotated);
      expect(serialized).not.toContain(SUBJECT);
    }
  });

  it("refuses a record that cannot name an identity or an audience, rather than skipping the check", async () => {
    // A check that cannot run must not be treated as a check that passed. KV
    // holds untyped JSON, so the declared record type is not a runtime
    // guarantee, and a truncated record must not be a way around the allowlist.
    // Each allowlist below WOULD admit this identity, so a pass here could only
    // come from the check being skipped.
    const testEnv = env();
    await installAllowlist(testEnv, "compliance-mcp", ["*@techimpossible.com"]);
    await installAllowlist(testEnv, "not-an-audience", ["*@techimpossible.com"]);

    const cases: Array<[string, Record<string, unknown>]> = [
      ["no email", { email: undefined }],
      ["blank email", { email: "   " }],
      ["no subject", { sub: undefined }],
      ["blank subject", { sub: "" }],
      ["audience this server does not mint for", { aud: "not-an-audience" }],
    ];

    for (const [name, overrides] of cases) {
      const chain = await issueChain(testEnv);
      const record = await refreshRecord(testEnv, chain.refreshToken);
      await testEnv.OAUTH_KV.put(
        `refresh:${chain.refreshToken}`,
        JSON.stringify({ ...record, ...overrides })
      );

      const res = await refresh(testEnv, chain);
      expect(res.status, name).toBe(400);
      expect(((await res.json()) as any).error, name).toBe("invalid_grant");
    }
  });
});

describe("refresh_token grant — records written in the pre-fix shape", () => {
  /**
   * The shape at git HEAD, byte for byte: no `chainStartedAt`. Records like this
   * are live in production OAUTH_KV right now, so the fix has to be judged on
   * them and not only on records it writes itself.
   */
  async function seedLegacyRecord(
    testEnv: any,
    chain: Chain,
    overrides: Record<string, unknown> = {}
  ): Promise<string> {
    const token = `synthetic-legacy-refresh-${Math.random().toString(36).slice(2)}`;
    const record = {
      clientId: chain.clientId,
      userId: USER,
      aud: "compliance-mcp",
      sub: SUBJECT,
      email: USER,
      scope: "openid email offline_access",
      createdAt: now() - 10 * DAY,
      ...overrides,
    };
    expect(record).not.toHaveProperty("chainStartedAt");
    await testEnv.OAUTH_KV.put(`refresh:${token}`, JSON.stringify(record));
    return token;
  }

  it("keeps working for a still-authorized identity, and stamps no chain anchor", async () => {
    // THE COMPATIBILITY CONSTRAINT. A fix that invalidated every live refresh
    // token would be worse than the bug, so a record written in the pre-fix
    // shape rotates normally.
    const testEnv = env();
    await installAllowlist(testEnv, "compliance-mcp", [USER]);
    const chain = await issueChain(testEnv);
    const legacyCreatedAt = now() - 10 * DAY;
    const legacy = await seedLegacyRecord(testEnv, chain, { createdAt: legacyCreatedAt });

    const res = await refresh(testEnv, chain, legacy);
    expect(res.status).toBe(200);
    const rotatedToken = ((await res.json()) as any).refresh_token as string;

    // No absolute window exists any more, so nothing anchors the chain and the
    // rotated record simply advances `createdAt`.
    const rotated = await refreshRecord(testEnv, rotatedToken);
    expect(rotated).not.toHaveProperty("chainStartedAt");
    expect(rotated.createdAt).toBeGreaterThanOrEqual(legacyCreatedAt);
    expect(ttlFor(testEnv, rotatedToken)).toBe(REFRESH_IDLE_TTL);
  });

  it("is subject to the revocation control in full — no grandfathering", async () => {
    // `aud` and `email` are in every record this server has ever written, so the
    // control can be applied to a legacy record with nothing missing. A legacy
    // record is exactly the credential a revoked user is holding today.
    const testEnv = env();
    await installAllowlist(testEnv, "compliance-mcp", [USER]);
    const chain = await issueChain(testEnv);
    const legacy = await seedLegacyRecord(testEnv, chain);

    await installAllowlist(testEnv, "compliance-mcp", []);
    const res = await refresh(testEnv, chain, legacy);
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
    expect(await refreshRecord(testEnv, legacy)).not.toBeNull();
  });

  it("keeps serving a chain far older than the removed cap, while the identity stays allowlisted", async () => {
    // AGE ALONE DECIDES NOTHING. The 90-day absolute cap that used to sit here
    // guaranteed a scheduled outage for a headless client: Hermes cannot walk an
    // interactive /authorize by itself, so an expired chain meant a human at a
    // browser or a dead integration. Authorization is re-decided on every single
    // use from `allowlist:<aud>` instead, which is what actually revokes.
    const testEnv = env();
    await installAllowlist(testEnv, "compliance-mcp", [USER]);
    const chain = await issueChain(testEnv);
    const ancient = await seedLegacyRecord(testEnv, chain, {
      createdAt: now() - (FORMER_CHAIN_CAP + DAY),
    });

    const res = await refresh(testEnv, chain, ancient);
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    const rotatedToken = body.refresh_token as string;

    // "Works" means a resource server can verify what it minted.
    const payload = await verifyAccessToken(testEnv, body.access_token, "compliance-mcp");
    expect(payload.email).toBe(USER);

    // And the control that does apply still applies to it, at any age.
    await installAllowlist(testEnv, "compliance-mcp", []);
    const revoked = await refresh(testEnv, chain, rotatedToken);
    expect(revoked.status).toBe(400);
    expect(((await revoked.json()) as any).error).toBe("invalid_grant");
  });

  it("writes the full idle window on every rotation, whatever the chain's age", async () => {
    // Rotation is what keeps a live integration alive: each use buys another 30
    // idle days. There is no remaining-absolute-window clamp to compute, so a
    // chain minted moments ago and one older than the removed cap get the same
    // TTL, and neither can be walked down towards zero by age.
    const testEnv = env();
    await installAllowlist(testEnv, "compliance-mcp", [USER]);
    const chain = await issueChain(testEnv);

    for (const age of [DAY, FORMER_CHAIN_CAP - 3600, FORMER_CHAIN_CAP + DAY]) {
      const legacy = await seedLegacyRecord(testEnv, chain, { createdAt: now() - age });
      const res = await refresh(testEnv, chain, legacy);
      expect(res.status, `age ${age}`).toBe(200);
      const rotatedToken = ((await res.json()) as any).refresh_token as string;
      expect(ttlFor(testEnv, rotatedToken), `age ${age}`).toBe(REFRESH_IDLE_TTL);
    }
  });
});
