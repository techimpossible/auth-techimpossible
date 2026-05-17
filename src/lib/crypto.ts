import { exportJWK, generateKeyPair, importJWK, type JWK } from "jose";

const KEY_KV_PATH = "signing-key:rs256:v1";

type SigningKeyMaterial = {
  kid: string;
  alg: "RS256";
  privateJwk: JWK;
  publicJwk: JWK;
};

let cached: SigningKeyMaterial | null = null;

export async function getSigningKey(kv: KVNamespace): Promise<SigningKeyMaterial> {
  if (cached) return cached;

  const stored = await kv.get(KEY_KV_PATH, "json");
  if (stored && typeof stored === "object") {
    cached = stored as SigningKeyMaterial;
    return cached;
  }

  const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  const publicJwk = await exportJWK(publicKey);
  const kid = await computeKid(publicJwk);
  publicJwk.kid = kid;
  publicJwk.alg = "RS256";
  publicJwk.use = "sig";
  privateJwk.kid = kid;
  privateJwk.alg = "RS256";

  const material: SigningKeyMaterial = {
    kid,
    alg: "RS256",
    privateJwk,
    publicJwk,
  };
  await kv.put(KEY_KV_PATH, JSON.stringify(material));
  cached = material;
  return material;
}

async function computeKid(publicJwk: JWK): Promise<string> {
  const ordered = {
    e: publicJwk.e,
    kty: publicJwk.kty,
    n: publicJwk.n,
  };
  const bytes = new TextEncoder().encode(JSON.stringify(ordered));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return base64UrlEncode(new Uint8Array(digest));
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlDecode(input: string): Uint8Array {
  const pad = "=".repeat((4 - (input.length % 4)) % 4);
  const b64 = (input + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function sha256Base64Url(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return base64UrlEncode(new Uint8Array(digest));
}

export function randomToken(byteLength = 32): string {
  const buf = new Uint8Array(byteLength);
  crypto.getRandomValues(buf);
  return base64UrlEncode(buf);
}

export function randomHex(byteLength = 32): string {
  const buf = new Uint8Array(byteLength);
  crypto.getRandomValues(buf);
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function getPrivateSigningKey(env: { OAUTH_KV: KVNamespace }) {
  const material = await getSigningKey(env.OAUTH_KV);
  const key = await importJWK(material.privateJwk, "RS256");
  return { key, kid: material.kid };
}

export async function getPublicJwk(env: { OAUTH_KV: KVNamespace }) {
  return getSigningKey(env.OAUTH_KV).then((m) => m.publicJwk);
}

export function clearSigningKeyCache() {
  cached = null;
}
