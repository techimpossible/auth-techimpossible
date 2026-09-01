import type { ClientRecord } from "../env.js";

export const SUPPORTED_AUDS = new Set(["compliance-mcp", "basecamp-mcp", "vanta-audit-mcp"]);

const MCP_HOST_TO_AUD: Record<string, string> = {
  "compliance-mcp.techimpossible.com": "compliance-mcp",
  "basecamp-mcp.techimpossible.com": "basecamp-mcp",
  "vanta-audit-mcp.techimpossible.com": "vanta-audit-mcp",
};

/** Hostnames that must never be inferred as a resource audience. */
const REJECTED_HOSTS = new Set(["mcp.techimpossible.com", "auth.techimpossible.com"]);

/**
 * Normalize connect-card resource inputs: trim, unwrap JSON arrays, strip quotes.
 */
export function normalizeResourceInput(raw: string | null | undefined): string | null {
  if (raw == null) return null;
  let value = raw.trim();
  if (!value) return null;

  if (value.startsWith("[")) {
    try {
      const parsed = JSON.parse(value) as unknown;
      if (Array.isArray(parsed) && parsed.length > 0 && typeof parsed[0] === "string") {
        value = parsed[0].trim();
      }
    } catch {
      // fall through with the raw string
    }
  }

  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    value = value.slice(1, -1).trim();
  }

  return value || null;
}

/**
 * Map an RFC 8707 resource URL or bare aud string to a canonical audience id.
 */
export function inferAudienceFromResource(resource: string): string | null {
  const normalized = normalizeResourceInput(resource);
  if (!normalized) return null;

  if (SUPPORTED_AUDS.has(normalized)) return normalized;

  try {
    const u = new URL(normalized);
    return hostnameToAudience(u.hostname);
  } catch {
    return null;
  }
}

function hostnameToAudience(hostname: string): string | null {
  const host = hostname.toLowerCase();
  if (REJECTED_HOSTS.has(host)) return null;
  return MCP_HOST_TO_AUD[host] ?? null;
}

function singleAllowedAudience(client: ClientRecord | null | undefined): string | null {
  if (client?.allowedAudiences?.length === 1) {
    return client.allowedAudiences[0];
  }
  return null;
}

/**
 * Resolve the audience for the authorization_code /authorize flow.
 *
 * Priority when `resource` is absent or whitespace-only:
 *   1. `resource_metadata` URL hostname (MCP protected-resource discovery)
 *   2. Client `allowedAudiences` with exactly one entry (Grok / per-MCP DCR)
 *   3. Global default `compliance-mcp` (Claude.ai vendor-review path)
 *
 * When `resource` is present but unparseable, steps 1–2 still apply; we do
 * not fall back to the global Claude default (that would mint the wrong aud).
 */
export function resolveAuthorizeAudience(
  resourceRaw: string | null,
  client: ClientRecord | null,
  resourceMetadataRaw?: string | null
): string | null {
  const resource = normalizeResourceInput(resourceRaw);
  const resourceMetadata = normalizeResourceInput(resourceMetadataRaw);

  if (resource) {
    const fromResource = inferAudienceFromResource(resource);
    if (fromResource) return fromResource;
  }

  if (resourceMetadata) {
    const fromMetadata = inferAudienceFromResource(resourceMetadata);
    if (fromMetadata) return fromMetadata;
  }

  const clientDefault = singleAllowedAudience(client);
  if (clientDefault) return clientDefault;

  if (!resource) return "compliance-mcp";

  return null;
}

/**
 * Reduce an RFC 8707 resource URL or bare audience string to the canonical aud
 * string resource servers expect. Used by the client_credentials grant.
 */
export function normalizeAudience(resource: string): string {
  const fromResource = inferAudienceFromResource(resource);
  if (fromResource) return fromResource;

  try {
    const u = new URL(resource);
    return u.hostname.split(".")[0];
  } catch {
    return resource;
  }
}
