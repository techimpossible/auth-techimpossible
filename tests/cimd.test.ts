import { afterEach, describe, expect, it, vi } from "vitest";
import { authorizeHandler } from "../src/oauth/authorize.js";
import { tokenHandler } from "../src/oauth/token.js";
import { resolveClient } from "../src/oauth/clients.js";
import { clearCimdCache, isCimdClientIdAllowed, resolveCimdClient } from "../src/oauth/cimd.js";
import type { JsonFetchOutcome } from "../src/lib/safe-fetch.js";

const ISSUER = "https://auth.example.test";
const ATTACKER = "https://attacker.example/victim/metadata.json";
const APPROVED = "https://client.example/mcp/client-metadata.json";

type PutRecord = { key: string; value: string; ttl?: number };

function inMemoryKV(puts: PutRecord[]): KVNamespace {
  const map = new Map<string, string>();
  return {
    async get(key: string, opts?: any) {
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
    async list() {
      return { keys: [...map.keys()].map((name) => ({ name })), list_complete: true, cursor: "" };
    },
  } as unknown as KVNamespace;
}

function env(overrides: Record<string, unknown> = {}) {
  const puts: PutRecord[] = [];
  return {
    puts,
    env: {
      OAUTH_KV: inMemoryKV(puts),
      ALLOWLIST_KV: inMemoryKV([]),
      TENANT_KV: inMemoryKV([]),
      ISSUER,
      GOOGLE_OIDC_CLIENT_ID: "synthetic-google-client-id",
      ADMIN_API_TOKEN: "synthetic-admin-token",
      ...overrides,
    } as any,
  };
}

function metadataDocument(clientId: string): Record<string, unknown> {
  return {
    client_id: clientId,
    client_name: "Example MCP client",
    redirect_uris: [new URL(clientId).origin + "/callback"],
    grant_types: ["authorization_code", "refresh_token"],
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("CIMD resolution is refused for client_ids no operator approved", () => {
  it("makes no outbound request and no KV write from an unauthenticated /token call", async () => {
    // Before the allowlist, three unauthenticated POSTs with attacker-chosen
    // URLs produced three outbound fetches from Cloudflare's egress plus one
    // negative-cache KV write each — and varying the path defeated the cache.
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const { env: testEnv, puts } = env();

    for (let i = 0; i < 3; i++) {
      const res = await tokenHandler(
        new Request(`${ISSUER}/token`, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code: "irrelevant",
            redirect_uri: "https://attacker.example/cb",
            client_id: `https://attacker.example/victim/path-${i}.json`,
          }).toString(),
        }),
        testEnv
      );
      expect(res.status).toBe(401);
    }

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(puts).toHaveLength(0);
  });

  it("makes no outbound request from an unauthenticated /authorize call", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const { env: testEnv, puts } = env();

    const res = await authorizeHandler(
      new Request(
        `${ISSUER}/authorize?response_type=code&client_id=${encodeURIComponent(
          ATTACKER
        )}&redirect_uri=https%3A%2F%2Fattacker.example%2Fcb`
      ),
      testEnv
    );
    expect(res.status).toBe(400);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(puts).toHaveLength(0);
  });

  it("resolves to null for a non-allowlisted client_id without touching KV", async () => {
    const { env: testEnv, puts } = env();
    const fetchJson = vi.fn(async (): Promise<JsonFetchOutcome> => ({
      status: "ok",
      doc: metadataDocument(ATTACKER),
    }));

    expect(await resolveCimdClient(testEnv, ATTACKER, { fetchJson })).toBeNull();
    expect(fetchJson).not.toHaveBeenCalled();
    expect(puts).toHaveLength(0);
    expect(isCimdClientIdAllowed(testEnv, ATTACKER)).toBe(false);
  });
});

describe("CIMD resolution for an approved client_id", () => {
  it("resolves and caches the document, and resolveClient routes to it", async () => {
    const { env: testEnv } = env({ CIMD_CLIENT_IDS: APPROVED });
    const fetchJson = vi.fn(async (): Promise<JsonFetchOutcome> => ({
      status: "ok",
      doc: metadataDocument(APPROVED),
    }));

    const record = await resolveCimdClient(testEnv, APPROVED, { fetchJson });
    expect(record?.clientId).toBe(APPROVED);
    expect(record?.registrationSource).toBe("cimd");
    expect(record?.tokenEndpointAuthMethod).toBe("none");

    // Second call is served from cache.
    await resolveCimdClient(testEnv, APPROVED, { fetchJson });
    expect(fetchJson).toHaveBeenCalledTimes(1);

    // And the shared entry point routes an https client_id here.
    expect((await resolveClient(testEnv, APPROVED))?.clientId).toBe(APPROVED);
  });

  it("barely caches an unreachable document, so one blip is not a five-minute outage", async () => {
    const { env: testEnv, puts } = env({ CIMD_CLIENT_IDS: APPROVED });
    let attempt = 0;
    const fetchJson = vi.fn(async (): Promise<JsonFetchOutcome> => {
      attempt += 1;
      return attempt === 1 ? { status: "unreachable" } : { status: "ok", doc: metadataDocument(APPROVED) };
    });

    expect(await resolveCimdClient(testEnv, APPROVED, { fetchJson })).toBeNull();
    const negative = puts.find((p) => p.key.startsWith("cimd:"));
    expect(negative?.ttl).toBeLessThanOrEqual(30);

    // The cache entry is short-lived by design; once it lapses the healthy
    // upstream resolves normally rather than staying dark.
    await clearCimdCache(testEnv, APPROVED);
    expect((await resolveCimdClient(testEnv, APPROVED, { fetchJson }))?.clientId).toBe(APPROVED);
  });

  it("caches a document it read and rejected for longer", async () => {
    const { env: testEnv, puts } = env({ CIMD_CLIENT_IDS: APPROVED });
    const fetchJson = vi.fn(async (): Promise<JsonFetchOutcome> => ({
      // Impersonation attempt: the document claims a different client_id.
      status: "ok",
      doc: { ...metadataDocument(APPROVED), client_id: "https://elsewhere.example/doc.json" },
    }));

    expect(await resolveCimdClient(testEnv, APPROVED, { fetchJson })).toBeNull();
    const negative = puts.find((p) => p.key.startsWith("cimd:"));
    expect(negative?.ttl).toBe(300);
  });
});
