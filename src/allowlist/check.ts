import type { Allowlist, Env } from "../env.js";

/**
 * THE ONE NORMALIZATION. Every identity and every pattern — on the decision path
 * and on the admin path — passes through this single expression.
 *
 * It is a function rather than an inlined `.toLowerCase().trim()` because the
 * two sides drifting apart IS the defect this module exists to close: DELETE
 * /admin/allowlist/<aud> used to compare raw strings while this file compared
 * normalized ones, so revoking "Peter@Techimpossible.com" against a stored
 * "peter@techimpossible.com" returned 200 and removed nothing.
 */
export function normalizeIdentity(value: string): string {
  return value.toLowerCase().trim();
}

/**
 * Does ONE pattern cover an already-normalized address?
 *
 * The grammar, unchanged and shared by the allow list and the deny list: a
 * literal address, or `*@domain` for every address at that domain. A non-string,
 * an empty pattern and a bare `*@` never match anything.
 */
export function matchesPattern(normalizedEmail: string, rawPattern: unknown): boolean {
  if (typeof rawPattern !== "string") return false;
  const pattern = normalizeIdentity(rawPattern);
  if (!pattern) return false;
  if (pattern.startsWith("*@")) {
    const domain = pattern.slice(2);
    if (!domain) return false;
    return normalizedEmail.endsWith("@" + domain);
  }
  return pattern === normalizedEmail;
}

/** Every pattern in `patterns` that covers `email`, normalized. */
export function matchingPatterns(email: string, patterns: readonly unknown[]): string[] {
  if (!email || !Array.isArray(patterns)) return [];
  const normalized = normalizeIdentity(email);
  if (!normalized) return [];
  const hits: string[] = [];
  for (const pattern of patterns) {
    if (matchesPattern(normalized, pattern)) hits.push(normalizeIdentity(pattern as string));
  }
  return hits;
}

/**
 * ALLOW PATTERNS ONLY. This is NOT the authorization decision.
 *
 * It answers "does this list of patterns cover this address", which is also what
 * the EMA grant needs for a tenant's `email_domains` namespace binding
 * (src/oauth/jwt-bearer.ts) — a different list, with nothing to do with
 * per-audience authorization. The authorization decision is
 * evaluateAllowlistRecord / checkStillAuthorized below, which consult the deny
 * list first.
 *
 * Signature and behaviour are unchanged; only the body moved onto the shared
 * helpers above.
 */
export function isEmailAllowed(email: string, patterns: string[]): boolean {
  if (!email || !Array.isArray(patterns) || patterns.length === 0) return false;
  const normalized = normalizeIdentity(email);
  for (const pattern of patterns) {
    if (matchesPattern(normalized, pattern)) return true;
  }
  return false;
}

/** Is this address covered by a deny entry? Deny beats allow, always. */
export function isEmailDenied(email: string, denied: readonly unknown[] | undefined): boolean {
  if (!denied) return false;
  return matchingPatterns(email, denied).length > 0;
}

/**
 * Is a stored value a record this server can evaluate?
 *
 * ONE validity test, used by the decision path and by the admin endpoints, so
 * "what counts as a healthy record" cannot be answered two different ways.
 *
 * The two arrays are treated ASYMMETRICALLY, on purpose:
 *
 *   - `emails` needs only to BE an array, exactly as before. A junk member fails
 *     closed all by itself — it matches nobody — so rejecting the whole record
 *     over one would deprovision an audience to no benefit.
 *   - `denied`, when present, must be an array of strings. A junk member there
 *     fails OPEN: the deny entry an operator believes they wrote would silently
 *     not apply, resurrecting a revoked user. That is the same class of bug the
 *     deny list was added to fix, so the record is rejected instead and every
 *     grant for the audience reports "unavailable" until it is repaired.
 */
export function validateAllowlistRecord(value: unknown): Allowlist | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const candidate = value as { emails?: unknown; denied?: unknown };
  if (!Array.isArray(candidate.emails)) return null;
  if (candidate.denied !== undefined) {
    if (!Array.isArray(candidate.denied)) return null;
    if (!candidate.denied.every((entry) => typeof entry === "string")) return null;
  }
  return value as Allowlist;
}

/**
 * A read of `allowlist:<aud>`, keeping the three answers apart.
 *
 * "missing" and "malformed" are NOT the same fact and must not produce the same
 * response: a missing record means nobody is authorized for that audience, while
 * a malformed one means the decision could not be made at all. See
 * checkStillAuthorized.
 */
export type AllowlistRead =
  | { status: "ok"; record: Allowlist }
  | { status: "missing" }
  | { status: "malformed"; raw: unknown };

export async function readAllowlistRecord(env: Env, aud: string): Promise<AllowlistRead> {
  const value = await env.ALLOWLIST_KV.get(`allowlist:${aud}`, "json");
  if (value === null || value === undefined) return { status: "missing" };
  const record = validateAllowlistRecord(value);
  if (!record) return { status: "malformed", raw: value };
  return { status: "ok", record };
}

/**
 * The record, or null when there is no usable one.
 *
 * Kept because it is the documented loader, but it collapses "missing" and
 * "malformed" into one null and therefore cannot be the basis of an
 * authorization decision — use checkStillAuthorized, or readAllowlistRecord when
 * the difference matters.
 */
export async function loadAllowlist(env: Env, aud: string): Promise<Allowlist | null> {
  const read = await readAllowlistRecord(env, aud);
  return read.status === "ok" ? read.record : null;
}

/**
 * The verdict for one identity against one record. `matchedBy` names the pattern
 * that decided it, for the operator-facing admin responses and the structured
 * logs — never for an end-user-visible body.
 */
export type AllowlistVerdict =
  | { status: "allowed"; matchedBy: string }
  | { status: "denied"; reason: "deny_entry" | "no_match"; matchedBy?: string };

/**
 * DENY FIRST, THEN ALLOW. Any other order makes a deny entry a suggestion.
 *
 * Deny before allow is also the only order in which the operator's mental model
 * ("I revoked Bob") survives later edits to the allow list: re-adding Bob as a
 * literal does not resurrect him while the deny entry stands.
 */
export function evaluateAllowlistRecord(email: string, record: Allowlist): AllowlistVerdict {
  const normalized = email ? normalizeIdentity(email) : "";
  if (!normalized) return { status: "denied", reason: "no_match" };

  const denied = Array.isArray(record.denied) ? record.denied : [];
  for (const pattern of denied) {
    if (matchesPattern(normalized, pattern)) {
      return { status: "denied", reason: "deny_entry", matchedBy: normalizeIdentity(pattern) };
    }
  }

  const emails = Array.isArray(record.emails) ? record.emails : [];
  for (const pattern of emails) {
    if (matchesPattern(normalized, pattern)) {
      return { status: "allowed", matchedBy: normalizeIdentity(pattern as string) };
    }
  }

  return { status: "denied", reason: "no_match" };
}

/**
 * The outcome of re-deciding an identity's authorization on a grant that is
 * exercised repeatedly (the refresh_token grant), and now on every grant that
 * mints a user-identity token.
 *
 * Three states, not a boolean, because "the allowlist says no" and "the
 * allowlist could not be read" call for opposite responses. Both refuse to mint
 * — an authorization check that cannot run must never be treated as one that
 * passed — but only the first means the caller's credential is dead. Collapsing
 * a transient ALLOWLIST_KV failure into "denied" would make a client discard a
 * still-valid refresh token and demand an interactive re-authentication, which
 * for a headless caller means a human at a browser.
 *
 * A MALFORMED RECORD IS "unavailable", NOT "denied". It is an infrastructure
 * fault of exactly the same kind as a failed read: one corrupt value in
 * ALLOWLIST_KV would otherwise deprovision an entire audience permanently, with
 * a 400 invalid_grant that OAuth clients treat as final. It still mints nothing.
 */
export type AuthorizationDecision =
  | { status: "allowed"; matchedBy: string }
  | { status: "denied"; reason: "deny_entry" | "no_match" | "no_record" }
  | { status: "unavailable"; reason: "kv_error" | "record_malformed" };

/**
 * THE per-audience authorization decision. Every grant that mints a
 * user-identity token goes through this one function — the interactive Google
 * callback, the refresh_token grant and the EMA jwt-bearer grant — so a control
 * added here (the deny list was) reaches all three at once, and cannot be
 * enforced on one path while another quietly bypasses it.
 *
 * A missing `allowlist:<aud>` record is "denied", never "no restriction in
 * force".
 */
export async function checkStillAuthorized(
  env: Env,
  aud: string,
  email: string
): Promise<AuthorizationDecision> {
  let read: AllowlistRead;
  try {
    read = await readAllowlistRecord(env, aud);
  } catch {
    return { status: "unavailable", reason: "kv_error" };
  }
  if (read.status === "malformed") return { status: "unavailable", reason: "record_malformed" };
  if (read.status === "missing") return { status: "denied", reason: "no_record" };

  const verdict = evaluateAllowlistRecord(email, read.record);
  if (verdict.status === "allowed") return { status: "allowed", matchedBy: verdict.matchedBy };
  return { status: "denied", reason: verdict.reason };
}
