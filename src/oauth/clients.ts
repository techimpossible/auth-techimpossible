import type { ClientRecord, Env } from "../env.js";
import { randomToken, sha256Hex } from "../lib/crypto.js";

const CLIENT_PREFIX = "client:";

export async function lookupClient(env: Env, clientId: string): Promise<ClientRecord | null> {
  if (!clientId || !clientId.startsWith("ti-")) return null;
  return env.OAUTH_KV.get<ClientRecord>(`${CLIENT_PREFIX}${clientId}`, "json");
}

export async function createClient(
  env: Env,
  metadata: {
    redirect_uris: string[];
    client_name?: string;
    token_endpoint_auth_method?: string;
    grant_types?: string[];
    response_types?: string[];
    scope?: string;
  }
): Promise<{ record: ClientRecord; clientSecret: string | null }> {
  const clientId = `ti-${randomToken(12)}`;

  const authMethod = (metadata.token_endpoint_auth_method ?? "client_secret_post") as
    | "client_secret_post"
    | "client_secret_basic"
    | "none";

  let clientSecret: string | null = null;
  let clientSecretHash: string | null = null;
  if (authMethod !== "none") {
    clientSecret = randomToken(32);
    clientSecretHash = await sha256Hex(clientSecret);
  }

  const record: ClientRecord = {
    clientId,
    clientSecretHash,
    redirectUris: metadata.redirect_uris,
    clientName: metadata.client_name,
    tokenEndpointAuthMethod: authMethod,
    grantTypes: metadata.grant_types ?? ["authorization_code", "refresh_token"],
    responseTypes: metadata.response_types ?? ["code"],
    scope: metadata.scope,
    registrationDate: Math.floor(Date.now() / 1000),
  };

  await env.OAUTH_KV.put(`${CLIENT_PREFIX}${clientId}`, JSON.stringify(record));
  return { record, clientSecret };
}

export async function verifyClientSecret(
  client: ClientRecord,
  clientSecret: string | null
): Promise<boolean> {
  if (client.tokenEndpointAuthMethod === "none") return clientSecret === null || clientSecret === "";
  if (!clientSecret || !client.clientSecretHash) return false;
  const hash = await sha256Hex(clientSecret);
  return timingSafeEqual(hash, client.clientSecretHash);
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
