import type { ClientRecord } from "../env.js";

/**
 * WHERE AN UNTRUSTED CLIENT MAY HAVE AN AUTHORIZATION CODE DELIVERED.
 *
 * `/register` is unauthenticated Dynamic Client Registration, and a client
 * supplies its own `redirect_uris` there. `/authorize` then checks the requested
 * redirect against that same self-supplied list, so on its own that check always
 * passes. There is no consent screen, and every screen the user sees during the
 * flow belongs to Google or to techimpossible.com. So anyone could register a
 * client pointing at their own server, send an /authorize link to an allowlisted
 * user, and receive an access token bearing that user's identity on one click.
 *
 * The structural fix is to stop an untrusted client nominating a destination the
 * attacker can READ. Two destination classes are permitted:
 *
 *   (a) LOOPBACK — RFC 8252 §7.3. The code is delivered to the user's own
 *       machine, so a remote attacker cannot read it. Any port, any path.
 *   (b) An OPERATOR-VETTED HTTPS HOST — a first-party vendor callback. The
 *       attacker controls no listed host, so the code never reaches them.
 *
 * DCR's legitimate users on this server are exactly those two kinds: vendor
 * connectors on known hosts, and loopback CLIs. Neither needs to nominate an
 * arbitrary internet host; the attack needs precisely that. The permitted set
 * and the attack requirement do not overlap, which is why this costs the
 * legitimate clients nothing.
 *
 * WHAT IT DOES NOT STOP, stated plainly: an open redirect or attacker-controlled
 * path ON an allowlisted host (host granularity is deliberate — pinning a
 * vendor's callback path would break on any change they make), and a local
 * process on the victim's own machine racing the loopback callback port.
 */

/** Hostname granularity, not path: a vendor may move its callback path. */
const DEFAULT_DCR_REDIRECT_HOSTS = ["claude.ai", "claude.com"];

/** Matches the URL bound in src/tenants/model.ts, for the same reason. */
export const MAX_REDIRECT_URI_LENGTH = 512;

const HOSTNAME_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;

/**
 * RFC 8252 §7.3: native/CLI apps (MCP clients, Claude Code, Claude Desktop) use
 * a loopback redirect with a runtime-assigned port. Treat 127.0.0.1 / ::1 /
 * localhost over http as loopback.
 *
 * BOTH IPv6 SPELLINGS ARE ACCEPTED, and that is the point of the list. The
 * WHATWG URL parser returns an IPv6 literal host in its BRACKETED form, so
 * `new URL("http://[::1]:8123/cb").hostname` is "[::1]" and never "::1". The
 * bare form was the only one compared here, so no IPv6 loopback redirect ever
 * matched — and because this predicate now gates /register, an RFC 8252 client
 * declaring only an IPv6 loopback could no longer register at all, which it
 * could before. Keeping the bare form costs nothing and documents the intent.
 *
 * The IPv4-mapped spelling (`[::ffff:127.0.0.1]`, which the parser rewrites to
 * `[::ffff:7f00:1]`) is deliberately NOT accepted: an explicit two-value list is
 * easier to reason about than an address-family normalizer, and a client with
 * that redirect can declare 127.0.0.1 instead.
 *
 * One definition for the whole server. It previously existed verbatim in both
 * authorize.ts and cimd.ts, which is how two copies of a security predicate
 * start to drift.
 */
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "[::1]", "localhost"]);

export function isLoopbackRedirect(uriStr: string): boolean {
  try {
    const u = new URL(uriStr);
    return u.protocol === "http:" && LOOPBACK_HOSTS.has(u.hostname);
  } catch {
    return false;
  }
}

/**
 * The https hosts an untrusted client may send an authorization code to:
 * built-in defaults UNION the operator's `DCR_REDIRECT_HOSTS`.
 *
 * Env EXTENDS the defaults rather than replacing them, so a forgotten or
 * mistyped variable cannot silently break the one vendor whose connector
 * registration has to keep working. Removing a default takes a code change,
 * which is a deliberate, stated limit.
 */
export function dcrRedirectHostAllowlist(env: { DCR_REDIRECT_HOSTS?: string }): string[] {
  const configured = (env.DCR_REDIRECT_HOSTS ?? "")
    .split(/[\s,]+/)
    .map((value) => value.trim().toLowerCase())
    .filter(isRedirectHostPattern);
  return [...new Set([...DEFAULT_DCR_REDIRECT_HOSTS, ...configured])];
}

/** A bare hostname, or `*.` plus a bare hostname. Anything else is dropped. */
function isRedirectHostPattern(value: string): boolean {
  if (!value || value.length > 253) return false;
  return HOSTNAME_RE.test(value.startsWith("*.") ? value.slice(2) : value);
}

function hostMatchesAllowlist(host: string, patterns: string[]): boolean {
  for (const pattern of patterns) {
    if (pattern.startsWith("*.")) {
      const suffix = pattern.slice(1); // ".example.com" — the dot must be present
      if (host.length > suffix.length && host.endsWith(suffix)) return true;
    } else if (host === pattern) {
      return true;
    }
  }
  return false;
}

/**
 * May an authorization code be delivered to this URI by a client nobody vetted?
 *
 * Deliberately NOT assertSafeHttpsUrl (src/tenants/model.ts): that is the SSRF
 * filter for URLs the Worker FETCHES, and it blocks every *.techimpossible.com
 * host and every non-443 port. A redirect destination is never fetched by us,
 * and a first-party techimpossible.com callback must stay registrable, so the
 * two rules are kept separate and separately named.
 */
export function redirectDestinationPermitted(
  env: { DCR_REDIRECT_HOSTS?: string },
  uriStr: string
): boolean {
  if (typeof uriStr !== "string" || !uriStr || uriStr.length > MAX_REDIRECT_URI_LENGTH) {
    return false;
  }
  if (isLoopbackRedirect(uriStr)) return true;

  let u: URL;
  try {
    u = new URL(uriStr);
  } catch {
    return false;
  }
  // https only. This also removes the javascript: and data: redirect URIs that
  // new URL() parses perfectly happily.
  if (u.protocol !== "https:") return false;
  if (u.username || u.password) return false;
  if (u.port && u.port !== "443") return false;

  // `u.hostname` is the bracketed form for an IPv6 literal here too, but the
  // allowlist patterns are bare hostnames (isRedirectHostPattern rejects
  // brackets), so an https IPv6-literal destination simply never matches. That
  // is the wanted answer: the https tier exists for vetted NAMED vendor hosts.
  return hostMatchesAllowlist(u.hostname.toLowerCase(), dcrRedirectHostAllowlist(env));
}

/**
 * A client an operator vetted, and therefore exempt from the destination rule.
 *
 * The same trust taxonomy the EMA grant already uses (src/oauth/jwt-bearer.ts):
 * `admin` came through the ADMIN_API_TOKEN-gated /admin/service-clients, and
 * `cimd` has a client_id URL the operator listed in CIMD_CLIENT_IDS whose
 * redirects src/oauth/cimd.ts already forces to be loopback or same-origin with
 * that URL. An absent value reads as "dcr", the fail-closed default documented
 * on ClientRecord.registrationSource.
 */
export function isOperatorVettedClient(client: ClientRecord): boolean {
  return client.registrationSource === "admin" || client.registrationSource === "cimd";
}

/**
 * The origin of a redirect URI, for logging and for the refusal page.
 *
 * ONLY the origin: the rest of an attacker-supplied URI is attacker-planted data
 * and has no business in a log line or on a page.
 */
export function redirectOrigin(uriStr: string): string {
  try {
    const u = new URL(uriStr);
    return u.origin && u.origin !== "null" ? u.origin : u.protocol;
  } catch {
    return "(unparseable)";
  }
}

/**
 * One structured line per refused redirect destination, in the same shape as the
 * EMA grant's `evt: "ema.token"`. This is how an operator learns that a phishing
 * attempt happened, and how they learn a vendor changed its callback host.
 */
export function logRedirectRefused(
  evt: "dcr.redirect_refused" | "authorize.redirect_refused",
  context: { clientId: string | null; origin: string; aud: string | null }
): void {
  console.log(
    JSON.stringify({
      evt,
      client_id: context.clientId,
      redirect_origin: context.origin,
      aud: context.aud,
    })
  );
}
