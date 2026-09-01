import { describe, expect, it } from "vitest";
import type { ClientRecord } from "../src/env.js";
import {
  inferAudienceFromResource,
  normalizeResourceInput,
  resolveAuthorizeAudience,
} from "../src/oauth/audience.js";

function grokClient(): ClientRecord {
  return {
    clientId: "ti-grok-test",
    clientSecretHash: "abc",
    redirectUris: ["https://example.com/callback"],
    tokenEndpointAuthMethod: "client_secret_post",
    grantTypes: ["authorization_code"],
    responseTypes: ["code"],
    registrationDate: 0,
    allowedAudiences: ["vanta-audit-mcp"],
  };
}

function claudeClient(): ClientRecord {
  return {
    clientId: "ti-claude-test",
    clientSecretHash: "abc",
    redirectUris: ["http://127.0.0.1/callback"],
    tokenEndpointAuthMethod: "none",
    grantTypes: ["authorization_code"],
    responseTypes: ["code"],
    registrationDate: 0,
  };
}

describe("normalizeResourceInput", () => {
  it("unwraps a JSON array of one URL", () => {
    expect(
      normalizeResourceInput('["https://vanta-audit-mcp.techimpossible.com/mcp"]')
    ).toBe("https://vanta-audit-mcp.techimpossible.com/mcp");
  });

  it("strips surrounding quotes and whitespace", () => {
    expect(
      normalizeResourceInput('  "https://vanta-audit-mcp.techimpossible.com/mcp"  ')
    ).toBe("https://vanta-audit-mcp.techimpossible.com/mcp");
  });

  it("returns null for empty or whitespace-only input", () => {
    expect(normalizeResourceInput("")).toBeNull();
    expect(normalizeResourceInput("   ")).toBeNull();
    expect(normalizeResourceInput(null)).toBeNull();
  });
});

describe("inferAudienceFromResource", () => {
  it("maps the vanta MCP URL with /mcp", () => {
    expect(inferAudienceFromResource("https://vanta-audit-mcp.techimpossible.com/mcp")).toBe(
      "vanta-audit-mcp"
    );
  });

  it("maps the vanta MCP URL with trailing slash", () => {
    expect(inferAudienceFromResource("https://vanta-audit-mcp.techimpossible.com/mcp/")).toBe(
      "vanta-audit-mcp"
    );
  });

  it("maps the vanta host without /mcp", () => {
    expect(inferAudienceFromResource("https://vanta-audit-mcp.techimpossible.com")).toBe(
      "vanta-audit-mcp"
    );
  });

  it("maps http scheme to the same audience", () => {
    expect(inferAudienceFromResource("http://vanta-audit-mcp.techimpossible.com/mcp")).toBe(
      "vanta-audit-mcp"
    );
  });

  it("maps a URL with extra query parameters", () => {
    expect(
      inferAudienceFromResource("https://vanta-audit-mcp.techimpossible.com/mcp?foo=bar")
    ).toBe("vanta-audit-mcp");
  });

  it("accepts a bare audience string", () => {
    expect(inferAudienceFromResource("vanta-audit-mcp")).toBe("vanta-audit-mcp");
  });

  it("rejects the auth issuer URL mistaken as resource", () => {
    expect(inferAudienceFromResource("https://auth.techimpossible.com")).toBeNull();
  });
});

describe("resolveAuthorizeAudience", () => {
  it("defaults to compliance-mcp when resource is omitted (Claude path)", () => {
    expect(resolveAuthorizeAudience(null, claudeClient())).toBe("compliance-mcp");
  });

  it("defaults to compliance-mcp for a generic DCR client with no allowedAudiences", () => {
    expect(resolveAuthorizeAudience(null, null)).toBe("compliance-mcp");
  });

  it("uses client allowedAudiences when resource is omitted (Grok path)", () => {
    expect(resolveAuthorizeAudience(null, grokClient())).toBe("vanta-audit-mcp");
  });

  it("uses the vanta MCP URL when Grok sends resource=", () => {
    expect(
      resolveAuthorizeAudience(
        "https://vanta-audit-mcp.techimpossible.com/mcp",
        grokClient()
      )
    ).toBe("vanta-audit-mcp");
  });

  it("parses a JSON-array resource connect-card variant", () => {
    expect(
      resolveAuthorizeAudience(
        '["https://vanta-audit-mcp.techimpossible.com/mcp"]',
        grokClient()
      )
    ).toBe("vanta-audit-mcp");
  });

  it("infers vanta from resource_metadata when resource is omitted", () => {
    expect(
      resolveAuthorizeAudience(
        null,
        claudeClient(),
        "https://vanta-audit-mcp.techimpossible.com/.well-known/oauth-protected-resource"
      )
    ).toBe("vanta-audit-mcp");
  });

  it("falls back to client default when resource is the auth issuer URL", () => {
    expect(resolveAuthorizeAudience("https://auth.techimpossible.com", grokClient())).toBe(
      "vanta-audit-mcp"
    );
  });

  it("does not mint compliance-mcp for an unparseable resource without client hint", () => {
    expect(resolveAuthorizeAudience("https://unknown.example.com/mcp", claudeClient())).toBeNull();
  });

  it("still maps compliance-mcp when resource URL is explicit", () => {
    expect(
      resolveAuthorizeAudience("https://compliance-mcp.techimpossible.com/mcp", claudeClient())
    ).toBe("compliance-mcp");
  });
});
