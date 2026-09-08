import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { authorizeHandler } from "../src/oauth/authorize.js";
import { tokenHandler } from "../src/oauth/token.js";
import { createClient } from "../src/oauth/clients.js";
import { SUPPORTED_AUDS as LIVE_AUDS } from "../src/oauth/audiences.js";
import { SUPPORTED_AUDS as RESOLVER_AUDS } from "../src/oauth/audience.js";
import { clearSigningKeyCache } from "../src/lib/crypto.js";

/**
 * Wiring cover for the audience resolver. tests/audience.test.ts proves what
 * `resolveAuthorizeAudience()` returns; this file proves the live handlers
 * actually call it. The two once diverged (a second SUPPORTED_AUDS without
 * `vanta-audit-mcp`, an /authorize that never called the resolver) and every
 * unit test stayed green while Internal Auditor auth broke in production.
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
      const keys = [...map.keys()]
        .filter((k) => !opts?.prefix || k.startsWith(opts.prefix))
        .map((name) => ({ name }));
      return { keys, list_complete: true, cursor: "" };
    },
  } as unknown as KVNamespace;
}

const ISSUER = "https://auth.example.test";
const REDIRECT_URI = "http://127.0.0.1/callback";
const USER = "peter.skaronis@techimpossible.com";
const SUBJECT = "google-subject-0001";
const VANTA = "vanta-audit-mcp";
const VANTA_RESOURCE = "https://vanta-audit-mcp.techimpossible.com/mcp";

function env() {
  clearSigningKeyCache();
  return {
    OAUTH_KV: inMemoryKV(),
    ALLOWLIST_KV: inMemoryKV(),
    TENANT_KV: inMemoryKV(),
    ISSUER,
    GOOGLE_OIDC_CLIENT_ID: "synthetic-oidc-client.apps.googleusercontent.test",
    GOOGLE_OIDC_CLIENT_SECRET: "synthetic-value-not-a-credential",
    ADMIN_API_TOKEN: "synthetic-admin-token",
  } as any;
}

beforeEach(() => {
  vi.spyOn(console, "log").mockImplementation(() => {});
});
afterEach(() => {
  vi.restoreAllMocks();
});

function authorizeRequest(params: Record<string, string>): Request {
  const url = new URL(`${ISSUER}/authorize`);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  return new Request(url.toString());
}

function tokenRequest(params: Record<string, string>): Request {
  return new Request(`${ISSUER}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params).toString(),
  });
}

/** The aud /authorize stored for the Google leg, read back from OAUTH_KV. */
async function storedAuthStateAud(testEnv: any): Promise<string | undefined> {
  const listing = await testEnv.OAUTH_KV.list({ prefix: "authstate:" });
  expect(listing.keys).toHaveLength(1);
  const record = await testEnv.OAUTH_KV.get(listing.keys[0].name, "json");
  return record?.aud;
}

async function authorize(testEnv: any, extra: Record<string, string>, clientOverrides = {}) {
  const { record } = await createClient(testEnv, {
    redirect_uris: [REDIRECT_URI],
    ...clientOverrides,
  });
  const res = await authorizeHandler(
    authorizeRequest({
      response_type: "code",
      client_id: record.clientId,
      redirect_uri: REDIRECT_URI,
      state: "s",
      ...extra,
    }),
    testEnv
  );
  return res;
}

describe("one audience set", () => {
  it("audiences.ts and audience.ts export the same live set, including vanta-audit-mcp", () => {
    expect(RESOLVER_AUDS).toBe(LIVE_AUDS);
    expect(LIVE_AUDS.has(VANTA)).toBe(true);
    expect(LIVE_AUDS.has("compliance-mcp")).toBe(true);
    expect(LIVE_AUDS.has("basecamp-mcp")).toBe(true);
  });
});

describe("/authorize resolves the audience through resolveAuthorizeAudience()", () => {
  it("accepts the vanta resource URL", async () => {
    const testEnv = env();
    const res = await authorize(testEnv, { resource: VANTA_RESOURCE });
    expect(res.status).toBe(302);
    expect(await storedAuthStateAud(testEnv)).toBe(VANTA);
  });

  it("accepts the bare vanta-audit-mcp aud", async () => {
    const testEnv = env();
    const res = await authorize(testEnv, { resource: VANTA });
    expect(res.status).toBe(302);
    expect(await storedAuthStateAud(testEnv)).toBe(VANTA);
  });

  it("falls back to resource_metadata when resource= is absent", async () => {
    const testEnv = env();
    const res = await authorize(testEnv, {
      resource_metadata:
        "https://vanta-audit-mcp.techimpossible.com/.well-known/oauth-protected-resource",
    });
    expect(res.status).toBe(302);
    expect(await storedAuthStateAud(testEnv)).toBe(VANTA);
  });

  it("uses the client's single allowed audience when resource= is omitted (Grok connect card)", async () => {
    const testEnv = env();
    const res = await authorize(testEnv, {}, { allowed_audiences: [VANTA] });
    expect(res.status).toBe(302);
    expect(await storedAuthStateAud(testEnv)).toBe(VANTA);
  });

  it("still defaults to compliance-mcp for a client with no audience hint", async () => {
    const testEnv = env();
    const res = await authorize(testEnv, {});
    expect(res.status).toBe(302);
    expect(await storedAuthStateAud(testEnv)).toBe("compliance-mcp");
  });

  it("still refuses the public catalogue host", async () => {
    const testEnv = env();
    const res = await authorize(testEnv, { resource: "https://mcp.techimpossible.com/mcp" });
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_request");
  });
});

describe("refresh_token grant honours live vanta-audit-mcp records", () => {
  it("rotates a refresh record whose aud is vanta-audit-mcp", async () => {
    const testEnv = env();
    await testEnv.ALLOWLIST_KV.put(`allowlist:${VANTA}`, JSON.stringify({ emails: [USER] }));
    const { record, clientSecret } = await createClient(testEnv, {
      redirect_uris: [REDIRECT_URI],
    });
    const token = "synthetic-live-vanta-refresh";
    await testEnv.OAUTH_KV.put(
      `refresh:${token}`,
      JSON.stringify({
        clientId: record.clientId,
        userId: USER,
        aud: VANTA,
        sub: SUBJECT,
        email: USER,
        scope: "openid email offline_access",
        createdAt: Math.floor(Date.now() / 1000) - 3600,
      })
    );

    const res = await tokenHandler(
      tokenRequest({
        grant_type: "refresh_token",
        refresh_token: token,
        client_id: record.clientId,
        client_secret: clientSecret!,
      }),
      testEnv
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(typeof body.access_token).toBe("string");
    expect(typeof body.refresh_token).toBe("string");
  });
});

describe("client_credentials grant normalizes the vanta resource URL", () => {
  it("maps the resource URL to the vanta-audit-mcp aud", async () => {
    const testEnv = env();
    const { record, clientSecret } = await createClient(testEnv, {
      redirect_uris: [REDIRECT_URI],
      grant_types: ["client_credentials"],
      service_email: "auditor@techimpossible.com",
      allowed_audiences: [VANTA],
      registration_source: "admin",
    });
    const res = await tokenHandler(
      tokenRequest({
        grant_type: "client_credentials",
        resource: VANTA_RESOURCE,
        client_id: record.clientId,
        client_secret: clientSecret!,
      }),
      testEnv
    );
    expect(res.status).toBe(200);
  });
});
