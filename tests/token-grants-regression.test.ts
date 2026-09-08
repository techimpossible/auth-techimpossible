import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { importJWK, jwtVerify } from "jose";
import type { AuthCodeRecord } from "../src/env.js";
import { tokenHandler } from "../src/oauth/token.js";
import { createClient } from "../src/oauth/clients.js";
import { clearSigningKeyCache, getSigningKey, sha256Base64Url } from "../src/lib/crypto.js";

/**
 * Regression cover for the three grants that predate Enterprise Managed Auth.
 * The EMA work touched token.ts's dispatch, clients.ts's resolution and jwt.ts's
 * claim shape, so each existing grant is re-proved end to end here.
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
    async list() {
      return { keys: [...map.keys()].map((name) => ({ name })), list_complete: true, cursor: "" };
    },
  } as unknown as KVNamespace;
}

/**
 * The refresh grant logs one structured line per decision. Silence it here so a
 * real failure in this file is not buried in decision logs; the log's own shape
 * is asserted in tests/refresh-revocation.test.ts.
 */
beforeEach(() => {
  vi.spyOn(console, "log").mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
});

const ISSUER = "https://auth.example.test";
const REDIRECT_URI = "http://127.0.0.1/callback";

function env() {
  clearSigningKeyCache();
  return {
    OAUTH_KV: inMemoryKV(),
    ALLOWLIST_KV: inMemoryKV(),
    TENANT_KV: inMemoryKV(),
    ISSUER,
  } as any;
}

function tokenRequest(params: Record<string, string>): Request {
  return new Request(`${ISSUER}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params).toString(),
  });
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

/** Seed the authorization code the Google callback would have written. */
async function seedAuthCode(
  testEnv: any,
  clientId: string,
  overrides: Partial<AuthCodeRecord> = {}
): Promise<string> {
  const code = `synthetic-auth-code-${Math.random().toString(36).slice(2)}`;
  const record: AuthCodeRecord = {
    clientId,
    userId: "peter@techimpossible.com",
    redirectUri: REDIRECT_URI,
    scope: "openid email offline_access",
    codeChallenge: null,
    codeChallengeMethod: null,
    props: {
      email: "peter@techimpossible.com",
      sub: "google-subject-0001",
      tenant_id: null,
      roles: [],
    },
    aud: "compliance-mcp",
    createdAt: Math.floor(Date.now() / 1000),
    ...overrides,
  };
  await testEnv.OAUTH_KV.put(`authcode:${code}`, JSON.stringify(record));
  return code;
}

describe("authorization_code grant (regression)", () => {
  it("exchanges a code for an access token, refresh token and id token", async () => {
    const testEnv = env();
    const { record, clientSecret } = await createClient(testEnv, {
      redirect_uris: [REDIRECT_URI],
    });
    const code = await seedAuthCode(testEnv, record.clientId);

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
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBe(3600);
    expect(body.scope).toBe("openid email offline_access");
    expect(typeof body.refresh_token).toBe("string");
    expect(typeof body.id_token).toBe("string");

    const payload = await verifyAccessToken(testEnv, body.access_token, "compliance-mcp");
    expect(payload.sub).toBe("google-subject-0001");
    expect(payload.email).toBe("peter@techimpossible.com");
    expect(payload.email_verified).toBe(true);
    // The EMA work added tenant_id/emailVerified parameters to mintAccessToken;
    // the historical claim shape must be byte-identical without them.
    expect(payload.tenant_id).toBeNull();
    expect(payload.roles).toEqual([]);
  });

  it("still enforces PKCE S256", async () => {
    const testEnv = env();
    const { record, clientSecret } = await createClient(testEnv, {
      redirect_uris: [REDIRECT_URI],
    });
    const verifier = "synthetic-code-verifier-0123456789-0123456789";
    const challenge = await sha256Base64Url(verifier);

    const badCode = await seedAuthCode(testEnv, record.clientId, {
      codeChallenge: challenge,
      codeChallengeMethod: "S256",
    });
    const bad = await tokenHandler(
      tokenRequest({
        grant_type: "authorization_code",
        code: badCode,
        redirect_uri: REDIRECT_URI,
        client_id: record.clientId,
        client_secret: clientSecret!,
        code_verifier: "not-the-verifier",
      }),
      testEnv
    );
    expect(bad.status).toBe(400);
    expect(((await bad.json()) as any).error).toBe("invalid_grant");

    const goodCode = await seedAuthCode(testEnv, record.clientId, {
      codeChallenge: challenge,
      codeChallengeMethod: "S256",
    });
    const good = await tokenHandler(
      tokenRequest({
        grant_type: "authorization_code",
        code: goodCode,
        redirect_uri: REDIRECT_URI,
        client_id: record.clientId,
        client_secret: clientSecret!,
        code_verifier: verifier,
      }),
      testEnv
    );
    expect(good.status).toBe(200);
  });

  it("still rejects a replayed code, a mismatched redirect_uri and a foreign client", async () => {
    const testEnv = env();
    const { record, clientSecret } = await createClient(testEnv, {
      redirect_uris: [REDIRECT_URI],
    });
    const other = await createClient(testEnv, { redirect_uris: [REDIRECT_URI] });

    const code = await seedAuthCode(testEnv, record.clientId);
    const first = await tokenHandler(
      tokenRequest({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        client_id: record.clientId,
        client_secret: clientSecret!,
      }),
      testEnv
    );
    expect(first.status).toBe(200);

    const replay = await tokenHandler(
      tokenRequest({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        client_id: record.clientId,
        client_secret: clientSecret!,
      }),
      testEnv
    );
    expect(replay.status).toBe(400);

    const mismatched = await seedAuthCode(testEnv, record.clientId);
    const wrongRedirect = await tokenHandler(
      tokenRequest({
        grant_type: "authorization_code",
        code: mismatched,
        redirect_uri: "http://127.0.0.1/other",
        client_id: record.clientId,
        client_secret: clientSecret!,
      }),
      testEnv
    );
    expect(wrongRedirect.status).toBe(400);

    const stolen = await seedAuthCode(testEnv, record.clientId);
    const wrongClient = await tokenHandler(
      tokenRequest({
        grant_type: "authorization_code",
        code: stolen,
        redirect_uri: REDIRECT_URI,
        client_id: other.record.clientId,
        client_secret: other.clientSecret!,
      }),
      testEnv
    );
    expect(wrongClient.status).toBe(400);
  });

  it("omits the refresh token when offline_access was not requested", async () => {
    const testEnv = env();
    const { record, clientSecret } = await createClient(testEnv, {
      redirect_uris: [REDIRECT_URI],
    });
    const code = await seedAuthCode(testEnv, record.clientId, { scope: "openid email" });

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
    expect(body.refresh_token).toBeUndefined();
    expect(typeof body.id_token).toBe("string");
  });
});

describe("refresh_token grant (regression)", () => {
  async function issueRefreshToken(testEnv: any) {
    // The refresh grant now re-runs the per-audience allowlist decision on every
    // use, so the identity seedAuthCode issues for has to be on
    // allowlist:compliance-mcp exactly as it is in production. Before that
    // control existed the grant read no allowlist at all, so this fixture never
    // needed one.
    await testEnv.ALLOWLIST_KV.put(
      "allowlist:compliance-mcp",
      JSON.stringify({ emails: ["peter@techimpossible.com"] })
    );

    const { record, clientSecret } = await createClient(testEnv, {
      redirect_uris: [REDIRECT_URI],
    });
    const code = await seedAuthCode(testEnv, record.clientId);
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
    const body = (await res.json()) as any;
    return { record, clientSecret: clientSecret!, refreshToken: body.refresh_token as string };
  }

  it("mints a fresh access token and rotates the refresh token", async () => {
    const testEnv = env();
    const { record, clientSecret, refreshToken } = await issueRefreshToken(testEnv);

    const res = await tokenHandler(
      tokenRequest({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: record.clientId,
        client_secret: clientSecret,
      }),
      testEnv
    );
    expect(res.status).toBe(200);

    const body = (await res.json()) as any;
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBe(3600);
    expect(typeof body.refresh_token).toBe("string");
    expect(body.refresh_token).not.toBe(refreshToken);
    expect(body.scope).toBe("openid email offline_access");

    const payload = await verifyAccessToken(testEnv, body.access_token, "compliance-mcp");
    expect(payload.sub).toBe("google-subject-0001");
    expect(payload.email).toBe("peter@techimpossible.com");
    expect(payload.tenant_id).toBeNull();

    // The rotated-out token is dead.
    const reuse = await tokenHandler(
      tokenRequest({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: record.clientId,
        client_secret: clientSecret,
      }),
      testEnv
    );
    expect(reuse.status).toBe(400);
    expect(((await reuse.json()) as any).error).toBe("invalid_grant");
  });

  it("rejects a refresh token presented by a different client", async () => {
    const testEnv = env();
    const { refreshToken } = await issueRefreshToken(testEnv);
    const other = await createClient(testEnv, { redirect_uris: [REDIRECT_URI] });

    const res = await tokenHandler(
      tokenRequest({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: other.record.clientId,
        client_secret: other.clientSecret!,
      }),
      testEnv
    );
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_grant");
  });

  it("rejects an unknown refresh token and a bad client secret", async () => {
    const testEnv = env();
    const { record, clientSecret, refreshToken } = await issueRefreshToken(testEnv);

    const unknown = await tokenHandler(
      tokenRequest({
        grant_type: "refresh_token",
        refresh_token: "synthetic-unknown-refresh-token",
        client_id: record.clientId,
        client_secret: clientSecret,
      }),
      testEnv
    );
    expect(unknown.status).toBe(400);

    const badSecret = await tokenHandler(
      tokenRequest({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: record.clientId,
        client_secret: "wrong",
      }),
      testEnv
    );
    expect(badSecret.status).toBe(401);
  });
});

describe("client_credentials grant (regression)", () => {
  async function serviceClient(testEnv: any) {
    return createClient(testEnv, {
      redirect_uris: [],
      client_name: "vendor-review-agent",
      grant_types: ["client_credentials"],
      service_email: "vendor-review-agent@techimpossible.com",
      allowed_audiences: ["compliance-mcp"],
    });
  }

  it("still mints a service token with the historical claim shape", async () => {
    const testEnv = env();
    const { record, clientSecret } = await serviceClient(testEnv);

    const res = await tokenHandler(
      tokenRequest({
        grant_type: "client_credentials",
        client_id: record.clientId,
        client_secret: clientSecret!,
        audience: "compliance-mcp",
      }),
      testEnv
    );
    expect(res.status).toBe(200);

    const body = (await res.json()) as any;
    expect(body.expires_in).toBe(3600);
    expect(body.refresh_token).toBeUndefined();

    const payload = await verifyAccessToken(testEnv, body.access_token, "compliance-mcp");
    expect(payload.sub).toBe(record.clientId);
    expect(payload.email).toBe("vendor-review-agent@techimpossible.com");
    expect(payload.email_verified).toBe(true);
    expect(payload.tenant_id).toBeNull();
  });

  it("still refuses an audience outside allowed_audiences", async () => {
    const testEnv = env();
    const { record, clientSecret } = await serviceClient(testEnv);

    const res = await tokenHandler(
      tokenRequest({
        grant_type: "client_credentials",
        client_id: record.clientId,
        client_secret: clientSecret!,
        audience: "basecamp-mcp",
      }),
      testEnv
    );
    expect(res.status).toBe(403);
  });

  it("still authenticates over HTTP Basic", async () => {
    const testEnv = env();
    const { record, clientSecret } = await serviceClient(testEnv);

    const res = await tokenHandler(
      new Request(`${ISSUER}/token`, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          authorization: `Basic ${btoa(`${record.clientId}:${clientSecret}`)}`,
        },
        body: new URLSearchParams({
          grant_type: "client_credentials",
          audience: "compliance-mcp",
        }).toString(),
      }),
      testEnv
    );
    expect(res.status).toBe(200);
  });
});

describe("token endpoint dispatch (regression)", () => {
  it("rejects a non-POST request and a wrong content type", async () => {
    const testEnv = env();

    const wrongMethod = await tokenHandler(new Request(`${ISSUER}/token`), testEnv);
    expect(wrongMethod.status).toBe(405);

    const wrongType = await tokenHandler(
      new Request(`${ISSUER}/token`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      }),
      testEnv
    );
    expect(wrongType.status).toBe(400);
  });

  it("rejects an unknown grant_type", async () => {
    const testEnv = env();
    const res = await tokenHandler(tokenRequest({ grant_type: "password" }), testEnv);
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("unsupported_grant_type");
  });
});
