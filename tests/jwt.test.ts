import { describe, expect, it } from "vitest";
import { createRemoteJWKSet, importJWK, jwtVerify } from "jose";
import { mintAccessToken } from "../src/lib/jwt.js";
import { clearSigningKeyCache, getSigningKey } from "../src/lib/crypto.js";

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

describe("mintAccessToken", () => {
  it("produces an RS256 JWT verifiable by the matching public key", async () => {
    clearSigningKeyCache();
    const env = { OAUTH_KV: inMemoryKV(), ISSUER: "https://auth.example.test" };
    const { token } = await mintAccessToken(env, {
      aud: "mcp-techimpossible",
      sub: "1234567890",
      email: "peter@techimpossible.com",
      ttlSeconds: 3600,
    });

    const material = await getSigningKey(env.OAUTH_KV);
    const publicKey = await importJWK(material.publicJwk, "RS256");
    const { payload, protectedHeader } = await jwtVerify(token, publicKey, {
      issuer: env.ISSUER,
      audience: "mcp-techimpossible",
      algorithms: ["RS256"],
    });

    expect(protectedHeader.alg).toBe("RS256");
    expect(protectedHeader.kid).toBe(material.kid);
    expect(payload.iss).toBe(env.ISSUER);
    expect(payload.aud).toBe("mcp-techimpossible");
    expect(payload.sub).toBe("1234567890");
    expect(payload.email).toBe("peter@techimpossible.com");
    expect(payload.email_verified).toBe(true);
    expect(payload.tenant_id).toBeNull();
    expect(payload.roles).toEqual([]);
  });

  it("rejects verification under a wrong audience", async () => {
    clearSigningKeyCache();
    const env = { OAUTH_KV: inMemoryKV(), ISSUER: "https://auth.example.test" };
    const { token } = await mintAccessToken(env, {
      aud: "mcp-techimpossible",
      sub: "1234567890",
      email: "peter@techimpossible.com",
      ttlSeconds: 3600,
    });

    const material = await getSigningKey(env.OAUTH_KV);
    const publicKey = await importJWK(material.publicJwk, "RS256");

    await expect(
      jwtVerify(token, publicKey, { issuer: env.ISSUER, audience: "basecamp-mcp" })
    ).rejects.toThrow();
  });

  it("rejects verification under a wrong issuer", async () => {
    clearSigningKeyCache();
    const env = { OAUTH_KV: inMemoryKV(), ISSUER: "https://auth.example.test" };
    const { token } = await mintAccessToken(env, {
      aud: "mcp-techimpossible",
      sub: "abc",
      email: "peter@techimpossible.com",
      ttlSeconds: 3600,
    });

    const material = await getSigningKey(env.OAUTH_KV);
    const publicKey = await importJWK(material.publicJwk, "RS256");

    await expect(
      jwtVerify(token, publicKey, { issuer: "https://other.example", audience: "mcp-techimpossible" })
    ).rejects.toThrow();
  });
});
