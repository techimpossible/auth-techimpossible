import { describe, expect, it } from "vitest";
import { importJWK, jwtVerify } from "jose";
import { tokenHandler } from "../src/oauth/token.js";
import { createClient } from "../src/oauth/clients.js";
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

function tokenRequest(params: Record<string, string>): Request {
  return new Request("https://auth.example.test/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params).toString(),
  });
}

async function serviceClient(env: any) {
  return createClient(env, {
    redirect_uris: [],
    client_name: "vendor-review-agent",
    grant_types: ["client_credentials"],
    service_email: "vendor-review-agent@techimpossible.com",
    allowed_audiences: ["compliance-mcp"],
  });
}

describe("client_credentials grant", () => {
  it("mints a compliance-mcp service token with the right claims", async () => {
    clearSigningKeyCache();
    const env = { OAUTH_KV: inMemoryKV(), ISSUER: "https://auth.example.test" } as any;
    const { record, clientSecret } = await serviceClient(env);

    const res = await tokenHandler(
      tokenRequest({
        grant_type: "client_credentials",
        client_id: record.clientId,
        client_secret: clientSecret!,
        audience: "compliance-mcp",
      }),
      env
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBe(3600);
    expect(body.refresh_token).toBeUndefined();

    const material = await getSigningKey(env.OAUTH_KV);
    const publicKey = await importJWK(material.publicJwk, "RS256");
    const { payload } = await jwtVerify(body.access_token, publicKey, {
      issuer: env.ISSUER,
      audience: "compliance-mcp",
    });
    expect(payload.email).toBe("vendor-review-agent@techimpossible.com");
    expect(payload.email_verified).toBe(true);
    expect(payload.sub).toBe(record.clientId);
  });

  it("defaults the audience when the client permits exactly one", async () => {
    clearSigningKeyCache();
    const env = { OAUTH_KV: inMemoryKV(), ISSUER: "https://auth.example.test" } as any;
    const { record, clientSecret } = await serviceClient(env);

    const res = await tokenHandler(
      tokenRequest({ grant_type: "client_credentials", client_id: record.clientId, client_secret: clientSecret! }),
      env
    );
    expect(res.status).toBe(200);
  });

  it("accepts an RFC 8707 resource URL and maps it to the audience", async () => {
    clearSigningKeyCache();
    const env = { OAUTH_KV: inMemoryKV(), ISSUER: "https://auth.example.test" } as any;
    const { record, clientSecret } = await serviceClient(env);

    const res = await tokenHandler(
      tokenRequest({
        grant_type: "client_credentials",
        client_id: record.clientId,
        client_secret: clientSecret!,
        resource: "https://compliance-mcp.techimpossible.com/mcp",
      }),
      env
    );
    expect(res.status).toBe(200);
  });

  it("rejects a bad client secret", async () => {
    clearSigningKeyCache();
    const env = { OAUTH_KV: inMemoryKV(), ISSUER: "https://auth.example.test" } as any;
    const { record } = await serviceClient(env);

    const res = await tokenHandler(
      tokenRequest({ grant_type: "client_credentials", client_id: record.clientId, client_secret: "wrong" }),
      env
    );
    expect(res.status).toBe(401);
  });

  it("rejects an audience not in allowed_audiences", async () => {
    clearSigningKeyCache();
    const env = { OAUTH_KV: inMemoryKV(), ISSUER: "https://auth.example.test" } as any;
    const { record, clientSecret } = await serviceClient(env);

    const res = await tokenHandler(
      tokenRequest({
        grant_type: "client_credentials",
        client_id: record.clientId,
        client_secret: clientSecret!,
        audience: "basecamp-mcp",
      }),
      env
    );
    expect(res.status).toBe(403);
  });

  it("rejects a client not permitted to use client_credentials", async () => {
    clearSigningKeyCache();
    const env = { OAUTH_KV: inMemoryKV(), ISSUER: "https://auth.example.test" } as any;
    // Default createClient grants authorization_code/refresh_token, not client_credentials.
    const { record, clientSecret } = await createClient(env, { redirect_uris: [] });

    const res = await tokenHandler(
      tokenRequest({
        grant_type: "client_credentials",
        client_id: record.clientId,
        client_secret: clientSecret!,
        audience: "compliance-mcp",
      }),
      env
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as any;
    expect(body.error).toBe("unauthorized_client");
  });
});
