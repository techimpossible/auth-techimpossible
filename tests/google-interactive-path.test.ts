import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { importJWK, jwtVerify } from "jose";
import type { AuthCodeRecord, AuthStateRecord } from "../src/env.js";
import { tokenHandler } from "../src/oauth/token.js";
import { createClient } from "../src/oauth/clients.js";
import { clearSigningKeyCache, getSigningKey } from "../src/lib/crypto.js";

/**
 * The INTERACTIVE Google path — /authorize -> Google -> /oauth/callback — and
 * specifically its `allowlist:<aud>` check at src/google/callback.ts.
 *
 * This file exists because that check had no test at all. Deleting the whole
 * check left the entire suite green, which is the same blind spot that let the
 * first pass ship an authentication bypass: the control everyone reasons about
 * was never the control anything asserted on. Every other test in the repo
 * SEEDS the authorization code this handler writes, so they all start after the
 * allowlist decision has already been made.
 *
 * It matters more than its line count suggests. Hermes reaches compliance-mcp
 * through this path, it is the only route for a client with no supported
 * identity provider, and `allowlist:<aud>` is the control Peter revokes with.
 *
 * SCOPE. Google's two I/O collaborators are stubbed at the module seam, so no
 * request leaves the process and no credential is needed: `exchange.ts` (the
 * code-for-id_token call) and `verify.ts` (whose signature check runs against
 * Google's live JWKS over node:https, and is therefore not unit-testable here).
 * Everything on this side of that seam is the real thing — the real callback
 * handler, the real checkStillAuthorized decision, real KV, and a real
 * authorization-code exchange through the real token handler.
 */

/** Mutable stub state. `vi.hoisted` because vi.mock factories are hoisted. */
const google = vi.hoisted(() => ({
  email: "peter.skaronis@techimpossible.com",
  sub: "google-subject-0001",
  /** When set, verifyGoogleIdToken rejects — what it does for a bad signature,
   *  a non-Google issuer, or email_verified !== true. */
  verifyError: null as string | null,
  exchangeCalls: 0,
}));

vi.mock("../src/google/exchange.js", () => ({
  exchangeGoogleAuthCode: async () => {
    google.exchangeCalls++;
    return { id_token: "synthetic-google-id-token", token_type: "Bearer" };
  },
}));

vi.mock("../src/google/verify.js", () => ({
  verifyGoogleIdToken: async () => {
    if (google.verifyError) throw new Error(google.verifyError);
    return { email: google.email, sub: google.sub, emailVerified: true, payload: {} };
  },
}));

const { googleCallbackHandler } = await import("../src/google/callback.js");

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

const ISSUER = "https://auth.example.test";
const REDIRECT_URI = "https://client.example.test/callback";
const STAFF = "peter.skaronis@techimpossible.com";
const CONTRACTOR = "contractor@techimpossible.com";
const OUTSIDER = "stranger@elsewhere.example";

function env() {
  clearSigningKeyCache();
  return {
    OAUTH_KV: inMemoryKV(),
    ALLOWLIST_KV: inMemoryKV(),
    TENANT_KV: inMemoryKV(),
    ISSUER,
    GOOGLE_OIDC_CLIENT_ID: "synthetic-oidc-client.apps.googleusercontent.test",
    GOOGLE_OIDC_CLIENT_SECRET: "synthetic-value-not-a-credential",
  } as any;
}

beforeEach(() => {
  google.email = STAFF;
  google.sub = "google-subject-0001";
  google.verifyError = null;
  google.exchangeCalls = 0;
});

afterEach(() => {
  vi.restoreAllMocks();
});

/** Seed the authorize-time state record that the callback consumes. */
async function seedState(
  testEnv: any,
  aud: string,
  clientId: string,
  state = "synthetic-state-0001"
): Promise<string> {
  const record: AuthStateRecord = {
    responseType: "code",
    clientId,
    redirectUri: REDIRECT_URI,
    scope: "openid email",
    state: "client-state-0001",
    codeChallenge: null,
    codeChallengeMethod: null,
    aud,
    createdAt: Math.floor(Date.now() / 1000),
  };
  await testEnv.OAUTH_KV.put(`authstate:${state}`, JSON.stringify(record));
  return state;
}

async function callback(testEnv: any, state: string): Promise<Response> {
  return googleCallbackHandler(
    new Request(`${ISSUER}/oauth/callback?code=synthetic-google-code&state=${state}`),
    testEnv
  );
}

async function oauthClient(testEnv: any) {
  const { record } = await createClient(testEnv, {
    redirect_uris: [REDIRECT_URI],
    client_name: "synthetic-interactive-client",
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  });
  return record;
}

async function installAllowlist(testEnv: any, aud: string, emails: string[]) {
  await testEnv.ALLOWLIST_KV.put(`allowlist:${aud}`, JSON.stringify({ emails }));
}

/** Every authorization code currently sitting in KV. */
async function authCodeKeys(testEnv: any): Promise<string[]> {
  const listing = await testEnv.OAUTH_KV.list({ prefix: "authcode:" });
  return listing.keys.map((k: { name: string }) => k.name);
}

describe("interactive Google path — allowlist:<aud> is enforced at the callback", () => {
  it("issues an authorization code for an allowlisted identity, and the code exchanges for a token", async () => {
    // The whole route Hermes uses, end to end: callback -> authorization code
    // -> /token -> a minted access token carrying that identity.
    const testEnv = env();
    const client = await oauthClient(testEnv);
    await installAllowlist(testEnv, "compliance-mcp", ["*@techimpossible.com"]);
    const state = await seedState(testEnv, "compliance-mcp", client.clientId);

    const res = await callback(testEnv, state);
    expect(res.status).toBe(302);

    const location = new URL(res.headers.get("location") ?? "");
    expect(location.origin + location.pathname).toBe(REDIRECT_URI);
    // The client's own `state` is echoed back, not the internal KV key.
    expect(location.searchParams.get("state")).toBe("client-state-0001");
    const code = location.searchParams.get("code") ?? "";
    expect(code).not.toBe("");

    const stored = (await testEnv.OAUTH_KV.get(`authcode:${code}`, "json")) as AuthCodeRecord;
    expect(stored.props.email).toBe(STAFF);
    expect(stored.aud).toBe("compliance-mcp");
    // The interactive path is not a tenant path: it must never mint a tenant_id.
    expect(stored.props.tenant_id).toBeNull();

    const token = await tokenHandler(
      new Request(`${ISSUER}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: REDIRECT_URI,
          client_id: client.clientId,
        }).toString(),
      }),
      testEnv
    );
    expect(token.status).toBe(200);

    const body = (await token.json()) as any;
    const material = await getSigningKey(testEnv.OAUTH_KV);
    const publicKey = await importJWK(material.publicJwk, "RS256");
    const { payload } = await jwtVerify(body.access_token, publicKey, {
      issuer: ISSUER,
      audience: "compliance-mcp",
      algorithms: ["RS256"],
    });
    expect(payload.email).toBe(STAFF);
    expect(payload.email_verified).toBe(true);
    expect(payload.tenant_id).toBeNull();
  });

  it("refuses an identity that is not on the allowlist, and writes no authorization code", async () => {
    const testEnv = env();
    const client = await oauthClient(testEnv);
    await installAllowlist(testEnv, "compliance-mcp", ["*@techimpossible.com"]);
    google.email = OUTSIDER;
    const state = await seedState(testEnv, "compliance-mcp", client.clientId);

    const res = await callback(testEnv, state);
    expect(res.status).toBe(403);
    expect(res.headers.get("content-type")).toContain("text/html");

    // A 403 page that still left a usable code behind would be theatre.
    expect(await authCodeKeys(testEnv)).toEqual([]);
  });

  it("fails closed when the audience has no allowlist at all", async () => {
    // A missing `allowlist:<aud>` key must read as "nobody", never as "no
    // restriction" — the same absent-means-unrestricted defect the EMA grant's
    // namespace binding had.
    const testEnv = env();
    const client = await oauthClient(testEnv);
    const state = await seedState(testEnv, "compliance-mcp", client.clientId);

    const res = await callback(testEnv, state);
    expect(res.status).toBe(403);
    expect(await authCodeKeys(testEnv)).toEqual([]);
  });

  it("answers 503, not 403, when the allowlist record is present but malformed", async () => {
    // A corrupt record means the decision could not be made, not that this
    // person was refused. Rendering "access denied" would tell a legitimate user
    // they have been deprovisioned because of one bad value in KV, and 403 is
    // what an OAuth client and a human both read as final.
    const testEnv = env();
    const client = await oauthClient(testEnv);
    await testEnv.ALLOWLIST_KV.put("allowlist:compliance-mcp", JSON.stringify({ emails: "*" }));
    const state = await seedState(testEnv, "compliance-mcp", client.clientId);

    const res = await callback(testEnv, state);
    expect(res.status).toBe(503);
    expect(res.headers.get("Retry-After")).toBe("5");
    expect(res.headers.get("content-type")).toContain("text/html");
    // It still mints nothing: unavailable refuses exactly as hard as denied.
    expect(await authCodeKeys(testEnv)).toEqual([]);
  });

  it("applies the allowlist of the audience the authorization started for", async () => {
    // Per-audience authorization: the same person may hold compliance-mcp and
    // not basecamp-mcp.
    const testEnv = env();
    const client = await oauthClient(testEnv);
    await installAllowlist(testEnv, "compliance-mcp", [STAFF]);
    await installAllowlist(testEnv, "basecamp-mcp", ["someone.else@techimpossible.com"]);

    const allowed = await callback(
      testEnv,
      await seedState(testEnv, "compliance-mcp", client.clientId, "state-compliance")
    );
    expect(allowed.status).toBe(302);

    const refused = await callback(
      testEnv,
      await seedState(testEnv, "basecamp-mcp", client.clientId, "state-basecamp")
    );
    expect(refused.status).toBe(403);
    expect(await authCodeKeys(testEnv)).toHaveLength(1);
  });

  it("stops an identity the operator has removed from the allowlist", async () => {
    // Revocation with no redeploy and no client-side action — the property the
    // MCP-Auth runbook promises, proved on the path that implements it.
    const testEnv = env();
    const client = await oauthClient(testEnv);
    await installAllowlist(testEnv, "compliance-mcp", [STAFF, CONTRACTOR]);
    google.email = CONTRACTOR;

    const before = await callback(
      testEnv,
      await seedState(testEnv, "compliance-mcp", client.clientId, "state-before")
    );
    expect(before.status).toBe(302);

    await installAllowlist(testEnv, "compliance-mcp", [STAFF]);

    const after = await callback(
      testEnv,
      await seedState(testEnv, "compliance-mcp", client.clientId, "state-after")
    );
    expect(after.status).toBe(403);
    expect(await authCodeKeys(testEnv)).toHaveLength(1);
  });

  it("matches the allowlist on the whole address, not on a substring of the domain", async () => {
    const testEnv = env();
    const client = await oauthClient(testEnv);
    await installAllowlist(testEnv, "compliance-mcp", ["*@techimpossible.com"]);

    for (const [i, email] of [
      "attacker@nottechimpossible.com",
      "attacker@techimpossible.com.evil.test",
      "attacker@evil.test",
    ].entries()) {
      google.email = email;
      const res = await callback(
        testEnv,
        await seedState(testEnv, "compliance-mcp", client.clientId, `state-near-miss-${i}`)
      );
      expect(res.status, email).toBe(403);
    }
    expect(await authCodeKeys(testEnv)).toEqual([]);
  });

  it("returns 401 and writes no code when the Google id_token fails verification", async () => {
    // verify.ts rejects a bad signature, a non-Google issuer, and an id_token
    // whose email_verified is not true. This asserts the callback's handling of
    // that rejection: no allowlist consultation, no code, no 5xx.
    const testEnv = env();
    const client = await oauthClient(testEnv);
    await installAllowlist(testEnv, "compliance-mcp", ["*@techimpossible.com"]);
    google.verifyError = "Google ID token email_verified is not true";
    const state = await seedState(testEnv, "compliance-mcp", client.clientId);

    const res = await callback(testEnv, state);
    expect(res.status).toBe(401);
    expect(((await res.json()) as any).error).toBe("google_id_token_invalid");
    expect(await authCodeKeys(testEnv)).toEqual([]);
  });

  it("consumes the state record, so a replayed callback cannot mint a second code", async () => {
    const testEnv = env();
    const client = await oauthClient(testEnv);
    await installAllowlist(testEnv, "compliance-mcp", ["*@techimpossible.com"]);
    const state = await seedState(testEnv, "compliance-mcp", client.clientId);

    expect((await callback(testEnv, state)).status).toBe(302);

    const replay = await callback(testEnv, state);
    expect(replay.status).toBe(400);
    expect(((await replay.json()) as any).error).toBe("invalid_state");
    expect(await authCodeKeys(testEnv)).toHaveLength(1);
    // The second attempt never even reached Google.
    expect(google.exchangeCalls).toBe(1);
  });

  it("rejects a callback with an unknown state before talking to Google", async () => {
    const testEnv = env();
    await oauthClient(testEnv);

    const res = await callback(testEnv, "state-that-was-never-issued");
    expect(res.status).toBe(400);
    expect(google.exchangeCalls).toBe(0);
    expect(await authCodeKeys(testEnv)).toEqual([]);
  });
});
