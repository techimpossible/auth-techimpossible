import type { ClientRecord, Env } from "../env.js";
import { randomToken, sha256Hex } from "../lib/crypto.js";
import { resolveCimdClient } from "./cimd.js";

const CLIENT_PREFIX = "client:";

export async function lookupClient(env: Env, clientId: string): Promise<ClientRecord | null> {
  if (!clientId || !clientId.startsWith("ti-")) return null;
  return env.OAUTH_KV.get<ClientRecord>(`${CLIENT_PREFIX}${clientId}`, "json");
}

/**
 * The single client-resolution entry point for every flow that authenticates a
 * client: `ti-` ids come from KV (DCR or the admin endpoint), an https client_id
 * is resolved as a Client ID Metadata Document, and anything else is unknown.
 *
 * Every call site must use this rather than lookupClient directly, otherwise a
 * CIMD client would work on one grant and fail on another.
 *
 * This runs on unauthenticated input (it is what /token and /authorize use to
 * FIND the client they are about to authenticate), so the CIMD branch does no
 * I/O at all unless the client_id is one an operator listed in CIMD_CLIENT_IDS.
 */
export async function resolveClient(env: Env, clientId: string): Promise<ClientRecord | null> {
  if (!clientId) return null;
  if (clientId.startsWith("ti-")) return lookupClient(env, clientId);
  if (clientId.startsWith("https://")) return resolveCimdClient(env, clientId);
  return null;
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
    // Machine-to-machine service clients (client_credentials).
    service_email?: string;
    allowed_audiences?: string[];
    // Provenance. Defaults to "dcr" (fail closed) because the only
    // unauthenticated caller of createClient is /register.
    registration_source?: "dcr" | "admin" | "cimd";
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
    ...(metadata.service_email ? { serviceEmail: metadata.service_email } : {}),
    ...(metadata.allowed_audiences ? { allowedAudiences: metadata.allowed_audiences } : {}),
    registrationSource: metadata.registration_source ?? "dcr",
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
