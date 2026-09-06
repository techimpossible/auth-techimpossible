import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { importJWK, jwtVerify } from "jose";
import type { AuthStateRecord, ClientRecord } from "../src/env.js";
import { registerHandler } from "../src/oauth/register.js";
import { authorizeHandler } from "../src/oauth/authorize.js";
import { tokenHandler } from "../src/oauth/token.js";
import { createClient } from "../src/oauth/clients.js";
import { clearSigningKeyCache, getSigningKey, sha256Base64Url } from "../src/lib/crypto.js";

/**
 * THE PHISHING PATH, and the two live integrations that must survive closing it.
 *
 * `/register` is unauthenticated Dynamic Client Registration and a client
 * supplies its own `redirect_uris`. `/authorize` then checked the requested
 * redirect against that same self-supplied list — a check that, for a client
 * nobody vetted, always passes. There is no consent screen, and every page the
 * victim sees belongs to Google or to techimpossible.com. So anyone could
 * register a client pointing at their own server, send an `/authorize` link to
 * an allowlisted Techimpossible user, and hold a full access token bearing that
 * user's identity after one click.
 *
 * The fix is structural rather than a consent screen: an unvetted client may
 * only nominate a destination the registrant cannot READ — the user's own
 * loopback interface (RFC 8252 §7.3, any port, any path) or an https host an
 * operator vetted. It is enforced at BOTH ends, and the `/authorize` end is not
 * redundant: the defect is live, so attacker-registered `client:` records may
 * already sit in production OAUTH_KV, and only the `/authorize` check makes
 * those inert.
 *
 * The regressions below are the reason the rule is shaped this way. Claude Code
 * uses ephemeral-port loopback redirects; Claude.ai connectors register through
 * DCR; Hermes runs the interactive Google flow. All three keep working.
 *
 * Google's two I/O collaborators are stubbed at the module seam (as in
 * `tests/google-interactive-path.test.ts`), so no request leaves the process and
 * no credential is needed. Everything else is the real handler.
 */

const google = vi.hoisted(() => ({
  email: "peter.skaronis@techimpossible.com",
  sub: "google-subject-0001",
}));

vi.mock("../src/google/exchange.js", () => ({
  exchangeGoogleAuthCode: async () => ({
    id_token: "synthetic-google-id-token",
    token_type: "Bearer",
  }),
}));

vi.mock("../src/google/verify.js", () => ({
  verifyGoogleIdToken: async () => ({
    email: google.email,
    sub: google.sub,
    emailVerified: true,
    payload: {},
  }),
}));

const { googleCallbackHandler } = await import("../src/google/callback.js");

function inMemoryKV() {
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
      const names = [...map.keys()].filter((name) => !opts?.prefix || name.startsWith(opts.prefix));
      return { keys: names.map((name) => ({ name })), list_complete: true, cursor: "" };
    },
  };
}

const ISSUER = "https://auth.example.test";
const USER = "peter.skaronis@techimpossible.com";
/** The attacker's own server. Nothing in this file may ever deliver a code here. */
const ATTACKER_REDIRECT = "https://attacker.example/collect?campaign=techimpossible";

function env(overrides: Record<string, unknown> = {}) {
  clearSigningKeyCache();
  return {
    OAUTH_KV: inMemoryKV(),
    ALLOWLIST_KV: inMemoryKV(),
    TENANT_KV: inMemoryKV(),
    ISSUER,
    GOOGLE_OIDC_CLIENT_ID: "synthetic-oidc-client.apps.googleusercontent.test",
    GOOGLE_OIDC_CLIENT_SECRET: "synthetic-value-not-a-credential",
    ADMIN_API_TOKEN: "synthetic-admin-token",
    ...overrides,
  } as any;
}

/** The refusal paths log one structured line; keep them out of the output. */
beforeEach(() => {
  vi.spyOn(console, "log").mockImplementation(() => {});
});
afterEach(() => {
  vi.restoreAllMocks();
});

function registerRequest(body: unknown): Request {
  return new Request(`${ISSUER}/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

function authorizeRequest(
  params: Record<string, string>,
  headers: Record<string, string> = {}
): Request {
  const url = new URL(`${ISSUER}/authorize`);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  return new Request(url.toString(), { headers });
}

async function keysWithPrefix(testEnv: any, prefix: string): Promise<string[]> {
  const listing = await testEnv.OAUTH_KV.list({ prefix });
  return listing.keys.map((k: { name: string }) => k.name);
}

async function installAllowlist(testEnv: any, aud: string, emails: string[]): Promise<void> {
  await testEnv.ALLOWLIST_KV.put(`allowlist:${aud}`, JSON.stringify({ emails }));
}

/**
 * A `client:` record written by the defective build: unauthenticated DCR, the
 * attacker's own callback, no operator anywhere in the story. This is what may
 * be sitting in production OAUTH_KV right now.
 */
async function seedPreExistingAttackerClient(
  testEnv: any,
  overrides: Partial<ClientRecord> = {}
): Promise<ClientRecord> {
  const record: ClientRecord = {
    clientId: "ti-synthetic-attacker",
    clientSecretHash: null,
    redirectUris: [ATTACKER_REDIRECT],
    clientName: "Techimpossible Compliance",
    tokenEndpointAuthMethod: "none",
    grantTypes: ["authorization_code", "refresh_token"],
    responseTypes: ["code"],
    registrationDate: Math.floor(Date.now() / 1000),
    registrationSource: "dcr",
    ...overrides,
  };
  await testEnv.OAUTH_KV.put(`client:${record.clientId}`, JSON.stringify(record));
  return record;
}

describe("phishing — an unvetted client cannot nominate a destination it can read", () => {
  it("refuses the registration outright, and writes no client record", async () => {
    const testEnv = env();

    const res = await registerHandler(
      registerRequest({
        client_name: "Techimpossible Compliance",
        redirect_uris: [ATTACKER_REDIRECT],
      }),
      testEnv
    );

    expect(res.status).toBe(400);
    const body = (await res.json()) as any;
    expect(body.error).toBe("invalid_redirect_uri");
    expect(body.client_id).toBeUndefined();
    expect(body.client_secret).toBeUndefined();
    // A refusal that still left a usable client record behind would be theatre.
    expect(await keysWithPrefix(testEnv, "client:")).toEqual([]);
  });

  it("refuses a registration where only ONE of several destinations is the attacker's", async () => {
    // Every entry is checked, not just the first: a client that registers a
    // loopback URI alongside an attacker host must not be able to smuggle the
    // second one in behind the first.
    const testEnv = env();

    const res = await registerHandler(
      registerRequest({
        redirect_uris: ["http://127.0.0.1/callback", "https://claude.ai/cb", ATTACKER_REDIRECT],
      }),
      testEnv
    );
    expect(res.status).toBe(400);
    expect(await keysWithPrefix(testEnv, "client:")).toEqual([]);
  });

  it("neutralises an attacker client that was registered before the rule existed", async () => {
    // THE ONE THAT MATTERS FOR A LIVE SERVER. The registration check alone would
    // leave every already-registered attacker record fully usable. This branch
    // makes them inert on deploy, with no KV write and no migration.
    const testEnv = env();
    await installAllowlist(testEnv, "compliance-mcp", ["*@techimpossible.com"]);
    const attacker = await seedPreExistingAttackerClient(testEnv);

    const res = await authorizeHandler(
      authorizeRequest({
        response_type: "code",
        client_id: attacker.clientId,
        redirect_uri: ATTACKER_REDIRECT,
        scope: "openid email offline_access",
        state: "victim-state",
      }),
      testEnv
    );

    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("unauthorized_client");
    // The Google leg never starts, so the victim is never even shown a login.
    expect(await keysWithPrefix(testEnv, "authstate:")).toEqual([]);
  });

  it("gives the attacker nothing to redeem: no state, no code, no token", async () => {
    // The end-to-end statement of the attack, walked all the way to /token.
    const testEnv = env();
    await installAllowlist(testEnv, "compliance-mcp", ["*@techimpossible.com"]);
    const attacker = await seedPreExistingAttackerClient(testEnv);

    const refused = await authorizeHandler(
      authorizeRequest({
        response_type: "code",
        client_id: attacker.clientId,
        redirect_uri: ATTACKER_REDIRECT,
      }),
      testEnv
    );
    expect(refused.status).toBe(400);

    // Without an authstate record the callback cannot proceed, whatever state
    // value the attacker invents.
    const callback = await googleCallbackHandler(
      new Request(`${ISSUER}/oauth/callback?code=synthetic-google-code&state=invented-by-attacker`),
      testEnv
    );
    expect(callback.status).toBe(400);
    expect(((await callback.json()) as any).error).toBe("invalid_state");

    // And no authorization code was ever minted, so /token has nothing to give.
    expect(await keysWithPrefix(testEnv, "authcode:")).toEqual([]);
    const token = await tokenHandler(
      new Request(`${ISSUER}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: "invented-by-attacker",
          redirect_uri: ATTACKER_REDIRECT,
          client_id: attacker.clientId,
        }).toString(),
      }),
      testEnv
    );
    expect(token.status).toBe(400);
    const tokenBody = (await token.json()) as any;
    expect(tokenBody.error).toBe("invalid_grant");
    expect(tokenBody.access_token).toBeUndefined();
  });

  it("warns a victim in the browser without echoing the attacker's URL or name as markup", async () => {
    // A courtesy, not a control — the request is already refused before this
    // renders. It still must not become the attacker's own output channel: the
    // client name is attacker-supplied at registration and the URL carries an
    // attacker-planted path and query.
    const testEnv = env();
    await seedPreExistingAttackerClient(testEnv, {
      clientName: 'Techimpossible <script>alert(document.domain)</script>',
    });

    const res = await authorizeHandler(
      authorizeRequest(
        {
          response_type: "code",
          client_id: "ti-synthetic-attacker",
          redirect_uri: ATTACKER_REDIRECT,
        },
        { accept: "text/html,application/xhtml+xml" }
      ),
      testEnv
    );

    expect(res.status).toBe(400);
    expect(res.headers.get("content-type")).toContain("text/html");
    const html = await res.text();
    expect(html).toContain("not permitted to sign you in");
    // The origin is shown so the reader can judge it; the path and query are not.
    expect(html).toContain("https://attacker.example");
    expect(html).not.toContain("/collect");
    expect(html).not.toContain("campaign=techimpossible");
    // The claimed name is shown as a claim, escaped, never as live markup.
    expect(html).not.toContain("<script>alert(document.domain)</script>");
    expect(html).toContain("&lt;script&gt;");
  });

  it("refuses every destination shape that is not loopback or a vetted https host", async () => {
    const testEnv = env();
    const cases: Array<[string, string]> = [
      ["the attacker's own https host", "https://attacker.example/cb"],
      ["a lookalike of a vetted host", "https://claude.ai.evil.example/cb"],
      ["a vetted host as a mere path", "https://evil.example/claude.ai/cb"],
      ["a vetted host in the query string", "https://evil.example/cb?next=https://claude.ai"],
      ["userinfo smuggling a vetted host", "https://claude.ai@evil.example/cb"],
      ["a vetted host on a non-443 port", "https://claude.ai:8443/cb"],
      ["plain http on a public host", "http://claude.ai/cb"],
      ["a javascript: URI that new URL() parses happily", "javascript:alert(document.cookie)"],
      ["a data: URI that new URL() parses happily", "data:text/html,<script>fetch(1)</script>"],
      ["an over-long URI", `https://claude.ai/cb?p=${"a".repeat(600)}`],
    ];

    for (const [name, uri] of cases) {
      const res = await registerHandler(registerRequest({ redirect_uris: [uri] }), testEnv);
      expect(res.status, name).toBe(400);
      expect(((await res.json()) as any).error, name).toBe("invalid_redirect_uri");
    }
    expect(await keysWithPrefix(testEnv, "client:")).toEqual([]);
  });

  it("bounds what one unauthenticated registration can write into OAUTH_KV", async () => {
    // /register writes to the same namespace that holds authcode:, refresh: and
    // client: records, with no TTL and no authentication.
    const testEnv = env();

    const tooMany = await registerHandler(
      registerRequest({
        redirect_uris: Array.from({ length: 6 }, (_, i) => `http://127.0.0.1/cb-${i}`),
      }),
      testEnv
    );
    expect(tooMany.status).toBe(400);

    const longName = await registerHandler(
      registerRequest({
        redirect_uris: ["http://127.0.0.1/callback"],
        client_name: "n".repeat(129),
      }),
      testEnv
    );
    expect(longName.status).toBe(400);

    for (const body of [{}, { redirect_uris: [] }, { redirect_uris: [42] }, "not json"]) {
      const res = await registerHandler(
        typeof body === "string"
          ? new Request(`${ISSUER}/register`, { method: "POST", body })
          : registerRequest(body),
        testEnv
      );
      expect(res.status).toBe(400);
    }
    expect(await keysWithPrefix(testEnv, "client:")).toEqual([]);
  });
});

describe("regression — Claude Code loopback redirects stay port-agnostic, both forms", () => {
  /**
   * Claude Code follows RFC 8252 §7.3: it binds an ephemeral port at runtime and
   * declares the port-less `http://localhost/callback` and
   * `http://127.0.0.1/callback`. The registered value therefore NEVER equals the
   * requested one, and both forms must match on any port and any path.
   */
  const CLAUDE_CODE_URIS = ["http://localhost/callback", "http://127.0.0.1/callback"];

  async function claudeCodeClient(testEnv: any): Promise<string> {
    const res = await registerHandler(
      registerRequest({
        client_name: "Claude Code",
        redirect_uris: CLAUDE_CODE_URIS,
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
      }),
      testEnv
    );
    expect(res.status).toBe(201);
    const body = (await res.json()) as any;
    expect(body.redirect_uris).toEqual(CLAUDE_CODE_URIS);
    return body.client_id;
  }

  it("registers a client declaring both loopback forms", async () => {
    const testEnv = env();
    const clientId = await claudeCodeClient(testEnv);
    expect(clientId.startsWith("ti-")).toBe(true);
  });

  it("authorizes on an ephemeral port, for localhost and 127.0.0.1 alike", async () => {
    const testEnv = env();
    const clientId = await claudeCodeClient(testEnv);

    const requested = [
      "http://127.0.0.1:53219/callback",
      "http://localhost:53219/callback",
      "http://127.0.0.1:1024/callback",
      "http://localhost:61000/callback",
      // RFC 8252 constrains neither the port nor the path.
      "http://127.0.0.1:49152/oauth/cb",
      "http://localhost:49152/",
    ];

    for (const redirectUri of requested) {
      const res = await authorizeHandler(
        authorizeRequest({
          response_type: "code",
          client_id: clientId,
          redirect_uri: redirectUri,
          scope: "openid email offline_access",
          state: "claude-code-state",
        }),
        testEnv
      );
      expect(res.status, redirectUri).toBe(302);
      expect(res.headers.get("location"), redirectUri).toContain("accounts.google.com");
    }

    // Each one was accepted on its own merits, and the exact requested value is
    // what the callback will redirect to.
    const stateKeys = await keysWithPrefix(testEnv, "authstate:");
    expect(stateKeys).toHaveLength(requested.length);
    const stored = await Promise.all(
      stateKeys.map((key) => testEnv.OAUTH_KV.get(key, "json") as Promise<AuthStateRecord>)
    );
    expect(stored.map((r) => r.redirectUri).sort()).toEqual([...requested].sort());
  });

  it("keeps port-agnostic loopback matching for a Client ID Metadata Document client", async () => {
    // The other way Claude Code can be identified: the client_id IS an https URL
    // serving its metadata, listed by an operator in CIMD_CLIENT_IDS. A CIMD
    // client is operator-vetted and therefore exempt from the destination rule,
    // but it is still bound by cimd.ts's own loopback-or-same-origin rule and by
    // the same port-agnostic match.
    const CLIENT_ID = "https://claude.example/mcp/client-metadata.json";
    const testEnv = env({ CIMD_CLIENT_IDS: CLIENT_ID });

    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          client_id: CLIENT_ID,
          client_name: "Claude Code",
          redirect_uris: CLAUDE_CODE_URIS,
          grant_types: ["authorization_code", "refresh_token"],
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      ) as any
    );

    const res = await authorizeHandler(
      authorizeRequest({
        response_type: "code",
        client_id: CLIENT_ID,
        redirect_uri: "http://127.0.0.1:57411/callback",
        scope: "openid email",
      }),
      testEnv
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toContain("accounts.google.com");
  });

  it("still refuses a loopback redirect from a client that registered none", async () => {
    // Port-agnostic matching is a concession to loopback clients, not a hole:
    // it applies only when the client actually registered a loopback URI.
    const testEnv = env();
    const res = await registerHandler(
      registerRequest({ redirect_uris: ["https://claude.ai/api/mcp/auth_callback"] }),
      testEnv
    );
    const clientId = ((await res.json()) as any).client_id as string;

    const authorized = await authorizeHandler(
      authorizeRequest({
        response_type: "code",
        client_id: clientId,
        redirect_uri: "http://127.0.0.1:53219/callback",
      }),
      testEnv
    );
    expect(authorized.status).toBe(400);
    expect(((await authorized.json()) as any).error).toBe("invalid_redirect_uri");
  });
});

describe("regression — the IPv6 loopback an RFC 8252 client may declare", () => {
  /**
   * `isLoopbackRedirect` compared `u.hostname` to the bare "::1", but the WHATWG
   * URL parser returns an IPv6 literal host in its BRACKETED form: for
   * `http://[::1]:8123/cb`, `hostname` is "[::1]" and never "::1". So no IPv6
   * loopback redirect ever matched the predicate.
   *
   * That was cosmetic while the predicate only relaxed port matching. It stopped
   * being cosmetic when the predicate became the gate on /register: a native
   * client declaring ONLY an IPv6 loopback could no longer register at all —
   * a capability it had before the destination rule existed. RFC 8252 §7.3
   * names both address families, and a client on an IPv6-only host has nothing
   * else to offer.
   */
  const V6 = "http://[::1]/callback";

  it("parses an IPv6 literal to the bracketed host the predicate must accept", async () => {
    // The premise of the bug, asserted rather than assumed, so a future reader
    // does not "simplify" the two-value list back down to the bare form.
    expect(new URL("http://[::1]:8123/cb").hostname).toBe("[::1]");
    // The long form normalizes to the same short bracketed spelling.
    expect(new URL("http://[0:0:0:0:0:0:0:1]/cb").hostname).toBe("[::1]");
  });

  it("registers a client declaring ONLY an IPv6 loopback redirect", async () => {
    const testEnv = env();

    const res = await registerHandler(
      registerRequest({
        client_name: "IPv6-only native client",
        redirect_uris: [V6],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
      }),
      testEnv
    );

    expect(res.status).toBe(201);
    const body = (await res.json()) as any;
    expect(body.redirect_uris).toEqual([V6]);
    expect(body.client_id.startsWith("ti-")).toBe(true);
  });

  it("authorizes an IPv6 loopback on an ephemeral port, any path", async () => {
    const testEnv = env();
    const registered = await registerHandler(
      registerRequest({
        redirect_uris: [V6],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
      }),
      testEnv
    );
    const clientId = ((await registered.json()) as any).client_id as string;

    const requested = [
      "http://[::1]:53219/callback",
      "http://[::1]:1024/callback",
      "http://[::1]:49152/oauth/cb",
      "http://[::1]:61000/",
    ];

    for (const redirectUri of requested) {
      const res = await authorizeHandler(
        authorizeRequest({
          response_type: "code",
          client_id: clientId,
          redirect_uri: redirectUri,
          scope: "openid email offline_access",
          state: "ipv6-state",
        }),
        testEnv
      );
      expect(res.status, redirectUri).toBe(302);
      expect(res.headers.get("location"), redirectUri).toContain("accounts.google.com");
    }

    // The exact requested value is what the callback will redirect to.
    const stateKeys = await keysWithPrefix(testEnv, "authstate:");
    const stored = await Promise.all(
      stateKeys.map((key) => testEnv.OAUTH_KV.get(key, "json") as Promise<AuthStateRecord>)
    );
    expect(stored.map((r) => r.redirectUri).sort()).toEqual([...requested].sort());
  });

  it("accepts all three loopback forms declared side by side", async () => {
    // What Claude Code can now declare. The IPv4 forms are asserted here too:
    // the fix widened the predicate and must not have moved either of them.
    const testEnv = env();
    const uris = ["http://localhost/callback", "http://127.0.0.1/callback", V6];

    const registered = await registerHandler(
      registerRequest({ redirect_uris: uris, token_endpoint_auth_method: "none" }),
      testEnv
    );
    expect(registered.status).toBe(201);
    const clientId = ((await registered.json()) as any).client_id as string;

    for (const redirectUri of [
      "http://localhost:53219/callback",
      "http://127.0.0.1:53219/callback",
      "http://[::1]:53219/callback",
    ]) {
      const res = await authorizeHandler(
        authorizeRequest({ response_type: "code", client_id: clientId, redirect_uri: redirectUri }),
        testEnv
      );
      expect(res.status, redirectUri).toBe(302);
    }
  });

  it("completes a full authorization_code exchange over an IPv6 loopback redirect", async () => {
    // Registration and /authorize are only two thirds of it: the callback must
    // deliver the code to the bracketed destination and the code must exchange.
    const testEnv = env();
    await installAllowlist(testEnv, "compliance-mcp", ["*@techimpossible.com"]);

    const registered = await registerHandler(
      registerRequest({
        redirect_uris: [V6],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
      }),
      testEnv
    );
    const clientId = ((await registered.json()) as any).client_id as string;
    const redirectUri = "http://[::1]:53219/callback";

    const authorized = await authorizeHandler(
      authorizeRequest({
        response_type: "code",
        client_id: clientId,
        redirect_uri: redirectUri,
        scope: "openid email offline_access",
        state: "ipv6-state",
      }),
      testEnv
    );
    expect(authorized.status).toBe(302);

    const stateKeys = await keysWithPrefix(testEnv, "authstate:");
    expect(stateKeys).toHaveLength(1);
    const stateValue = stateKeys[0].slice("authstate:".length);

    const callback = await googleCallbackHandler(
      new Request(`${ISSUER}/oauth/callback?code=synthetic-google-code&state=${stateValue}`),
      testEnv
    );
    expect(callback.status).toBe(302);
    const location = new URL(callback.headers.get("location") ?? "");
    expect(location.origin).toBe("http://[::1]:53219");
    const code = location.searchParams.get("code");
    expect(typeof code).toBe("string");

    const token = await tokenHandler(
      new Request(`${ISSUER}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: code!,
          redirect_uri: redirectUri,
          client_id: clientId,
        }).toString(),
      }),
      testEnv
    );
    expect(token.status).toBe(200);
    expect(typeof ((await token.json()) as any).access_token).toBe("string");
  });

  it("does not treat an IPv6 literal as loopback over https, or any other v6 address", async () => {
    // The widening is exactly two spellings of the loopback address over http.
    // A routable IPv6 host is still an unvetted destination, and `[::1]` over
    // https is not the RFC 8252 case.
    const testEnv = env();

    for (const uri of [
      "https://[::1]/callback",
      "http://[2001:db8::1]/callback",
      "http://[::ffff:7f00:1]/callback",
    ]) {
      const res = await registerHandler(registerRequest({ redirect_uris: [uri] }), testEnv);
      expect(res.status, uri).toBe(400);
      expect(((await res.json()) as any).error, uri).toBe("invalid_redirect_uri");
    }
    expect(await keysWithPrefix(testEnv, "client:")).toEqual([]);
  });
});

describe("regression — vetted https connector hosts stay registrable", () => {
  it("keeps Claude.ai connector registration working through DCR", async () => {
    // Claude.ai adds a connector by registering through DCR. Hard-disabling
    // /register would have removed the ability to add a connector at all.
    const testEnv = env();

    for (const uri of [
      "https://claude.ai/api/mcp/auth_callback",
      "https://claude.com/api/mcp/auth_callback",
    ]) {
      const res = await registerHandler(registerRequest({ redirect_uris: [uri] }), testEnv);
      expect(res.status, uri).toBe(201);

      const clientId = ((await res.json()) as any).client_id as string;
      const authorized = await authorizeHandler(
        authorizeRequest({
          response_type: "code",
          client_id: clientId,
          redirect_uri: uri,
          resource: "https://compliance-mcp.techimpossible.com",
        }),
        testEnv
      );
      expect(authorized.status, uri).toBe(302);
    }
  });

  it("lets DCR_REDIRECT_HOSTS EXTEND the built-in hosts, never replace them", async () => {
    // The operator's escape hatch for a first-party callback host. It extends,
    // so a mistyped or forgotten variable cannot silently stop connector
    // registration working.
    const testEnv = env({ DCR_REDIRECT_HOSTS: "callback.hermes.example, *.connectors.example" });

    for (const uri of [
      "https://callback.hermes.example/oauth/cb",
      "https://eu.connectors.example/cb",
      "https://claude.ai/api/mcp/auth_callback",
    ]) {
      const res = await registerHandler(registerRequest({ redirect_uris: [uri] }), testEnv);
      expect(res.status, uri).toBe(201);
    }

    // "*.connectors.example" is a subdomain suffix, not the bare parent, and it
    // does not reach a lookalike registered elsewhere.
    for (const uri of [
      "https://connectors.example/cb",
      "https://evilconnectors.example/cb",
      "https://callback.hermes.example.evil.test/cb",
    ]) {
      const res = await registerHandler(registerRequest({ redirect_uris: [uri] }), testEnv);
      expect(res.status, uri).toBe(400);
    }
  });

  it("exempts an operator-vetted admin client from the destination rule", async () => {
    // The documented taxonomy: `admin` came through the ADMIN_API_TOKEN-gated
    // endpoint and `cimd` from a URL an operator listed, so both are vetted;
    // absent provenance reads as "dcr" and is not.
    const testEnv = env();
    const vetted = await createClient(testEnv, {
      redirect_uris: ["https://vendor.example/callback"],
      client_name: "operator-created-connector",
      token_endpoint_auth_method: "none",
      registration_source: "admin",
    });

    const res = await authorizeHandler(
      authorizeRequest({
        response_type: "code",
        client_id: vetted.record.clientId,
        redirect_uri: "https://vendor.example/callback",
      }),
      testEnv
    );
    expect(res.status).toBe(302);
  });
});

describe("regression — the interactive flow Hermes uses still completes end to end", () => {
  it("registers, authorizes, calls back, exchanges the code and refreshes", async () => {
    // Hermes reaches compliance-mcp through its own OAuth 2.1 PKCE client:
    // /authorize -> Google -> /oauth/callback -> /token, then long-lived refresh.
    // It re-authenticates rarely and may have no human at a browser, so this
    // whole path has to keep working unattended. Both fixes are in force here.
    const testEnv = env();
    await installAllowlist(testEnv, "compliance-mcp", ["*@techimpossible.com"]);

    // 1. Registration: a public PKCE client on a loopback callback.
    const registered = await registerHandler(
      registerRequest({
        client_name: "hermes-agent",
        redirect_uris: ["http://127.0.0.1/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
      }),
      testEnv
    );
    expect(registered.status).toBe(201);
    const clientId = ((await registered.json()) as any).client_id as string;

    // 2. Authorize, with a runtime-assigned port and PKCE S256.
    const verifier = "synthetic-code-verifier-0123456789-0123456789";
    const challenge = await sha256Base64Url(verifier);
    const redirectUri = "http://127.0.0.1:44311/callback";
    const authorized = await authorizeHandler(
      authorizeRequest({
        response_type: "code",
        client_id: clientId,
        redirect_uri: redirectUri,
        scope: "openid email offline_access",
        state: "hermes-state-0001",
        code_challenge: challenge,
        code_challenge_method: "S256",
        resource: "https://compliance-mcp.techimpossible.com",
      }),
      testEnv
    );
    expect(authorized.status).toBe(302);

    const googleUrl = new URL(authorized.headers.get("location") ?? "");
    expect(googleUrl.hostname).toBe("accounts.google.com");
    expect(googleUrl.searchParams.get("redirect_uri")).toBe(`${ISSUER}/oauth/callback`);
    const nonce = googleUrl.searchParams.get("state") ?? "";
    expect(nonce).not.toBe("");

    // 3. Google returns. The allowlist decision happens here.
    const callback = await googleCallbackHandler(
      new Request(`${ISSUER}/oauth/callback?code=synthetic-google-code&state=${nonce}`),
      testEnv
    );
    expect(callback.status).toBe(302);
    const back = new URL(callback.headers.get("location") ?? "");
    expect(back.origin + back.pathname).toBe("http://127.0.0.1:44311/callback");
    expect(back.searchParams.get("state")).toBe("hermes-state-0001");
    const code = back.searchParams.get("code") ?? "";
    expect(code).not.toBe("");

    // 4. Exchange the code.
    const tokenRes = await tokenHandler(
      new Request(`${ISSUER}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: redirectUri,
          client_id: clientId,
          code_verifier: verifier,
        }).toString(),
      }),
      testEnv
    );
    expect(tokenRes.status).toBe(200);
    const tokens = (await tokenRes.json()) as any;
    expect(typeof tokens.access_token).toBe("string");
    expect(typeof tokens.refresh_token).toBe("string");
    expect(typeof tokens.id_token).toBe("string");

    const material = await getSigningKey(testEnv.OAUTH_KV);
    const publicKey = await importJWK(material.publicJwk, "RS256");
    const { payload } = await jwtVerify(tokens.access_token, publicKey, {
      issuer: ISSUER,
      audience: "compliance-mcp",
      algorithms: ["RS256"],
    });
    expect(payload.email).toBe(USER);
    expect(payload.email_verified).toBe(true);
    expect(payload.tenant_id).toBeNull();

    // 5. The unattended part: refresh, which is what Hermes actually does day to
    //    day. It must not require the browser step again.
    const refreshed = await tokenHandler(
      new Request(`${ISSUER}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: tokens.refresh_token,
          client_id: clientId,
        }).toString(),
      }),
      testEnv
    );
    expect(refreshed.status).toBe(200);
    const rotated = (await refreshed.json()) as any;
    expect(rotated.expires_in).toBe(3600);
    expect(typeof rotated.refresh_token).toBe("string");
    await jwtVerify(rotated.access_token, publicKey, {
      issuer: ISSUER,
      audience: "compliance-mcp",
      algorithms: ["RS256"],
    });
  });
});
