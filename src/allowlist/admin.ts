import type { Allowlist, Env } from "../env.js";
import { jsonError, jsonOk } from "../lib/errors.js";
import { requireAdminToken, safeJson } from "../lib/admin-auth.js";
import { sha256Base64Url } from "../lib/crypto.js";
import { SUPPORTED_AUDS } from "../oauth/audiences.js";
import {
  evaluateAllowlistRecord,
  matchingPatterns,
  normalizeIdentity,
  validateAllowlistRecord,
  type AllowlistVerdict,
} from "./check.js";

/**
 * THE REVOCATION ENDPOINT, and the two silent-failure mirrors beside it.
 *
 * DELETE used to remove an entry from `emails` by EXACT STRING equality and
 * return 200 whatever happened. The check that consumes the list normalizes case
 * and whitespace and honours `*@domain`, so two revocations that an operator was
 * told had succeeded had in fact done nothing:
 *
 *   (a) DELETE "Peter@Techimpossible.com" against a stored
 *       "peter@techimpossible.com" — no entry matched.
 *   (b) DELETE of any individual address against `["*@customer.example"]` — the
 *       likely production shape, and the one README's own seed command writes —
 *       removed nothing, so the user kept refreshing forever.
 *
 * Two things fix that, and neither is sufficient alone. Matching now goes
 * through the SAME normalizer as the decision path (normalizeIdentity, imported,
 * not re-implemented), which closes (a). And the record grows an optional
 * `denied` array, evaluated BEFORE `emails`, which is the only way to express
 * "everyone at customer.example except this one person" — deleting the wildcard
 * instead would deprovision the whole customer, which is an outage, not a
 * revocation.
 *
 * THE STANDING RULE FOR EVERY MUTATING RESPONSE HERE: no 2xx unless the end
 * state was verified. Each one re-runs `evaluateAllowlistRecord` over the record
 * that was actually written and returns the verdict as `decision_after`, so a
 * handler cannot claim an effect the decision function does not produce. Where
 * nothing took effect the answer is 404, 409 or 503 — never a 200 an unattended
 * runbook would read as success.
 */

/** Bounds a pattern before it is stored or echoed. RFC 5321 address limit. */
const MAX_PATTERN_LENGTH = 254;

/** Workers KV has no compare-and-swap; see the concurrency note on DELETE. */
const RETRY_AFTER = "5";

const EFFECTIVE_FOR = [
  "authorization_code (interactive Google login)",
  "refresh_token",
  "urn:ietf:params:oauth:grant-type:jwt-bearer",
];

/**
 * Stated in every revocation response rather than assumed. The
 * client_credentials grant mints its identity from the client record and never
 * reads ALLOWLIST_KV, so a deny entry there would be a control that does not
 * run. An operator must not mistake an allowlist deny for having stopped a
 * service client.
 */
const NOT_EFFECTIVE_FOR = [
  "client_credentials service clients, which do not consult the allowlist — revoke those by rotating the client secret",
];

const PROPAGATION =
  "Existing access tokens stay valid until they expire (max 3600s). No new access token can be " +
  "minted for this identity by any grant that reads the allowlist.";

const BODY_SHAPE = "Body must be { emails: string[], denied?: string[] }";

const PATTERN_RULE =
  "must be a literal address (name@example.com) or a domain pattern (*@example.com)";

const MALFORMED_MESSAGE =
  "This record cannot be evaluated. Every grant for this audience fails closed until it is " +
  "repaired with PUT.";

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

type StoredRead =
  | { status: "ok"; record: Allowlist }
  | { status: "missing" }
  | { status: "malformed"; raw: unknown }
  | { status: "unavailable" };

/** Bound operator-written text before it is echoed back into a response. */
function quoteForError(value: string): string {
  return value.length > 200 ? `${value.slice(0, 200)}…` : value;
}

/**
 * Read the record as TEXT and validate it here, so a value that is not even JSON
 * is reported as a malformed record an operator can inspect, rather than as an
 * exception. Validity itself is decided by validateAllowlistRecord — the same
 * single test the grant path uses, so admin and runtime can never disagree about
 * what a healthy record is.
 */
async function readStored(env: Env, aud: string): Promise<StoredRead> {
  let text: string | null;
  try {
    text = await env.ALLOWLIST_KV.get(`allowlist:${aud}`);
  } catch {
    return { status: "unavailable" };
  }
  if (text === null || text === undefined) return { status: "missing" };

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { status: "malformed", raw: { unparseable_text: quoteForError(text) } };
  }
  // A stored literal `null` is what KV's json mode also reports as absent.
  if (parsed === null) return { status: "missing" };

  const record = validateAllowlistRecord(parsed);
  if (!record) return { status: "malformed", raw: parsed };
  return { status: "ok", record };
}

/**
 * `denied` is written only when it has entries, so an audience that has never
 * had a revocation stays byte-identical to what is stored today.
 */
function serialize(record: Allowlist): string {
  const out: Allowlist = { emails: record.emails };
  if (record.denied && record.denied.length > 0) out.denied = record.denied;
  return JSON.stringify(out);
}

/**
 * Write, then READ BACK, and return what KV actually kept — never the in-memory
 * object we intended to write.
 *
 * The success gate on every mutating route re-evaluates the record to prove the
 * caller's change took effect. Evaluating the in-memory `next` proves nothing:
 * KV has no compare-and-swap, so under a concurrent write the last writer wins
 * and `next` becomes a claim about a record that does not exist. That is exactly
 * the "HTTP 200 for a revocation that did not take effect" failure this whole
 * contract exists to prevent, reintroduced inside the check meant to prevent it.
 *
 * Returns null when the write failed OR when the record cannot be read back as
 * valid. Callers must treat null as "the change did NOT take effect".
 *
 * KNOWN LIMIT — eventual consistency. KV reads are not guaranteed read-your-write,
 * so a read-back can return the previous value even though the put landed. That
 * surfaces as a non-2xx "not effective" response and the operator retries, which
 * then succeeds. The error is therefore always in the safe direction: this can
 * under-report a success, and it cannot over-report one.
 */
async function writeStored(
  env: Env,
  aud: string,
  record: Allowlist,
  ctx: { route: string; method: string; pattern?: string }
): Promise<Allowlist | null> {
  try {
    await env.ALLOWLIST_KV.put(`allowlist:${aud}`, serialize(record));
  } catch {
    // A write that did not land is exactly the event an operator must not have
    // to infer from silence.
    await audit({
      route: ctx.route,
      method: ctx.method,
      aud,
      action: "kv_write_failed",
      changed: false,
      status: 503,
      pattern: ctx.pattern ?? null,
    });
    return null;
  }

  const readBack = await readStored(env, aud);
  if (readBack.status !== "ok") {
    // The put reported success but the stored record is missing, unreadable or
    // malformed. Something else wrote over it, or KV is degraded. Either way the
    // operator must not be told the change is in force.
    await audit({
      route: ctx.route,
      method: ctx.method,
      aud,
      action: "read_back_failed",
      changed: true,
      status: 503,
      pattern: ctx.pattern ?? null,
    });
    return null;
  }
  return readBack.record;
}

// ---------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------

/**
 * Validate and normalize in one step, so a caller cannot accidentally hold a
 * validated-but-unnormalized value. Returns the stored form, or null.
 *
 * The grammar is exactly what the matcher understands: `*@domain`, or a literal
 * address with one `@` and something on each side of it. No dot is required in
 * the domain — this list has always accepted whatever an operator wrote, and
 * validation stricter than what can already be stored would block a revocation.
 */
function normalizePattern(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const v = normalizeIdentity(value);
  if (!v || v.length > MAX_PATTERN_LENGTH) return null;
  if (/[\s,;<>"'()[\]\\]/.test(v)) return null;
  if (v.startsWith("*@")) {
    const domain = v.slice(2);
    return domain.length > 0 && !domain.includes("@") && !domain.includes("*") ? v : null;
  }
  if (v.includes("*")) return null;
  const at = v.indexOf("@");
  if (at <= 0 || at !== v.lastIndexOf("@") || at === v.length - 1) return null;
  return v;
}

function isWildcard(pattern: string): boolean {
  return pattern.startsWith("*@");
}

/** Entries whose normalized form is exactly this pattern. Narrowing only. */
function withoutExact(entries: readonly unknown[], target: string): unknown[] {
  return entries.filter((entry) => !(typeof entry === "string" && normalizeIdentity(entry) === target));
}

function containsExact(entries: readonly unknown[], target: string): boolean {
  return entries.some((entry) => typeof entry === "string" && normalizeIdentity(entry) === target);
}

// ---------------------------------------------------------------------------
// Request arguments
// ---------------------------------------------------------------------------

type EmailArg =
  | { ok: true; pattern: string }
  | { ok: false; reason: "missing" | "invalid" | "conflict"; offending?: string };

/**
 * `email` from the JSON body, or from `?email=`. The query form exists because
 * several HTTP clients drop a DELETE body outright, and a revocation that
 * silently loses its argument is precisely the failure being fixed here.
 */
function readEmailArg(request: Request, body: Record<string, unknown> | null): EmailArg {
  const rawBody = body?.email;
  const rawQuery = new URL(request.url).searchParams.get("email");

  if (rawBody === undefined && rawQuery === null) return { ok: false, reason: "missing" };
  if (rawBody !== undefined && typeof rawBody !== "string") {
    return { ok: false, reason: "invalid", offending: String(rawBody) };
  }

  const fromBody = rawBody === undefined ? null : normalizePattern(rawBody);
  const fromQuery = rawQuery === null ? null : normalizePattern(rawQuery);

  if (rawBody !== undefined && fromBody === null) {
    return { ok: false, reason: "invalid", offending: rawBody as string };
  }
  if (rawQuery !== null && fromQuery === null) {
    return { ok: false, reason: "invalid", offending: rawQuery };
  }
  if (fromBody && fromQuery && fromBody !== fromQuery) return { ok: false, reason: "conflict" };
  return { ok: true, pattern: (fromBody ?? fromQuery) as string };
}

function invalidEmail(arg: Extract<EmailArg, { ok: false }>): Response {
  if (arg.reason === "conflict") {
    return jsonError(
      400,
      "invalid_body",
      "The body and the ?email= query parameter name different addresses. Send one. Nothing was changed.",
      { changed: false }
    );
  }
  if (arg.reason === "missing") {
    return jsonError(400, "invalid_body", `email is required and ${PATTERN_RULE}`, { changed: false });
  }
  return jsonError(
    400,
    "invalid_body",
    `'${quoteForError(arg.offending ?? "")}' is not a valid entry: it ${PATTERN_RULE}. Nothing was changed.`,
    { changed: false }
  );
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

function verdictJson(verdict: AllowlistVerdict): Record<string, unknown> {
  return verdict.status === "allowed"
    ? { status: "allowed", matched_by: verdict.matchedBy }
    : {
        status: "denied",
        reason: verdict.reason,
        ...(verdict.matchedBy ? { matched_by: verdict.matchedBy } : {}),
      };
}

function unavailable(aud: string, what: string): Response {
  const response = jsonError(
    503,
    "temporarily_unavailable",
    `The allowlist record for '${aud}' could not be ${what}. The change did NOT take effect. ` +
      `Retry; if it persists, GET the record to inspect it.`,
    { aud, changed: false }
  );
  response.headers.set("Retry-After", RETRY_AFTER);
  return response;
}

function unknownAudience(aud: string): Response {
  return jsonError(
    404,
    "unknown_audience",
    `No audience '${quoteForError(aud)}'. Supported: ${[...SUPPORTED_AUDS].join(", ")}. ` +
      `Nothing was changed.`,
    { supported_audiences: [...SUPPORTED_AUDS], changed: false }
  );
}

function allowlistNotFound(aud: string): Response {
  return jsonError(
    404,
    "allowlist_not_found",
    `No allowlist record for audience '${aud}'. No identity is authorized through it, so there is ` +
      `nothing to change. If you expected one, check the audience name; seed it with PUT.`,
    { aud, changed: false }
  );
}

/**
 * GET/PUT/POST stay permissive about the audience string for compatibility and
 * warn instead; DELETE and the /denied routes refuse outright, because a
 * revocation aimed at a misspelled audience must never look like it worked.
 */
function audienceWarnings(aud: string): string[] {
  return SUPPORTED_AUDS.has(aud)
    ? []
    : [`aud '${quoteForError(aud)}' is not a supported audience; no token will ever be minted for it`];
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/**
 * One structured line per mutating request, refusals included — a revocation
 * that did NOT take effect is the event most worth having in the record. Shaped
 * like `evt: "refresh.token"` in src/oauth/token.ts. The address is hashed here
 * and given in full only in the response to the authenticated operator.
 */
async function audit(fields: {
  route: string;
  method: string;
  aud: string;
  action: string;
  changed: boolean;
  status: number;
  pattern?: string | null;
  removedCount?: number;
  deniedAddedCount?: number;
}): Promise<void> {
  const pattern = fields.pattern ?? null;
  const at = pattern ? pattern.lastIndexOf("@") : -1;
  console.log(
    JSON.stringify({
      evt: "allowlist_admin",
      route: fields.route,
      method: fields.method,
      aud: fields.aud,
      action: fields.action,
      changed: fields.changed,
      status: fields.status,
      email_hash: pattern ? await sha256Base64Url(pattern) : null,
      email_domain: at >= 0 ? pattern!.slice(at + 1) : null,
      removed_count: fields.removedCount ?? 0,
      denied_added_count: fields.deniedAddedCount ?? 0,
    })
  );
}

// ---------------------------------------------------------------------------
// /admin/allowlist/<aud>
// ---------------------------------------------------------------------------

export async function adminAllowlistHandler(
  request: Request,
  env: Env,
  aud: string
): Promise<Response> {
  const guard = requireAdminToken(request, env);
  if (guard) return guard;

  if (request.method === "GET") return handleGet(env, aud);
  if (request.method === "PUT") return handlePut(request, env, aud);
  if (request.method === "POST") return handlePost(request, env, aud);
  if (request.method === "DELETE") return handleDelete(request, env, aud);

  return jsonError(405, "method_not_allowed", "GET/PUT/POST/DELETE supported");
}

async function handleGet(env: Env, aud: string): Promise<Response> {
  const read = await readStored(env, aud);
  const warnings = audienceWarnings(aud);

  if (read.status === "unavailable") return unavailable(aud, "read");
  if (read.status === "missing") {
    return jsonOk({ aud, allowlist: { emails: [], denied: [] }, exists: false, warnings });
  }
  if (read.status === "malformed") {
    // Deliberately 200 with the stored value: GET is the repair tool, and the
    // operator cannot fix what they cannot see. Precedent: readTenantRaw in
    // src/tenants/admin.ts returns malformed tenant records for the same reason.
    return jsonOk({ aud, malformed: true, raw: read.raw, message: MALFORMED_MESSAGE, warnings });
  }

  return jsonOk({
    aud,
    allowlist: {
      ...(read.record as unknown as Record<string, unknown>),
      emails: read.record.emails,
      denied: read.record.denied ?? [],
    },
    malformed: false,
    warnings,
  });
}

/**
 * PUT replaces `emails` and, unless told otherwise, PRESERVES `denied`.
 *
 * This breaks REST full-replace purity on purpose. README documents the seeding
 * command as `PUT {"emails":[...]}` with no `denied` member, so full-replace
 * semantics would turn the most-documented command on this endpoint into a
 * silent mass un-revocation. Clearing requires an explicit `"denied": []`, and
 * the response reports `denied_preserved` so the deviation is never invisible.
 */
async function handlePut(request: Request, env: Env, aud: string): Promise<Response> {
  const body = await safeJson(request);
  if (!body || !Array.isArray(body.emails)) {
    return jsonError(400, "invalid_body", BODY_SHAPE, { changed: false });
  }

  const emails = (body.emails as unknown[]).filter((e): e is string => typeof e === "string");

  const deniedProvided = body.denied !== undefined;
  let denied: string[] = [];
  if (deniedProvided) {
    if (!Array.isArray(body.denied)) {
      return jsonError(400, "invalid_body", BODY_SHAPE, { changed: false });
    }
    for (const entry of body.denied as unknown[]) {
      const pattern = normalizePattern(entry);
      if (!pattern) {
        return jsonError(
          400,
          "invalid_body",
          `denied entry '${quoteForError(String(entry))}' is not valid: it ${PATTERN_RULE}. ` +
            `Nothing was changed.`,
          { changed: false }
        );
      }
      if (!denied.includes(pattern)) denied.push(pattern);
    }
  }

  const read = await readStored(env, aud);
  if (read.status === "unavailable") return unavailable(aud, "read");

  if (!deniedProvided) {
    if (read.status === "malformed") {
      // PUT is the repair tool, so it is not refused outright — but the deny
      // list it would "preserve" cannot be read, and silently dropping it would
      // un-revoke whoever it named. Make the operator state it.
      return jsonError(
        409,
        "denied_unreadable",
        `The stored record for '${aud}' cannot be parsed, so its deny list cannot be preserved. ` +
          `Re-send this PUT with an explicit "denied": [...] (or [] to clear it). GET the record ` +
          `first to see what is there.`,
        { aud, changed: false }
      );
    }
    denied = [...(read.status === "ok" ? read.record.denied ?? [] : [])];
  }

  const next: Allowlist = { emails, ...(denied.length > 0 ? { denied } : {}) };
  const before = read.status === "ok" ? serialize(read.record) : null;
  const stored = await writeStored(env, aud, next, { route: "/admin/allowlist/:aud", method: "PUT" });
  if (!stored) {
    return unavailable(aud, "written");
  }

  const changed = before !== serialize(stored);
  const warnings = audienceWarnings(aud);
  for (const entry of emails) {
    if (matchingPatterns(entry, denied).length > 0) {
      warnings.push(`${entry} appears in both emails and denied; deny wins`);
    }
  }

  await audit({
    route: "/admin/allowlist/:aud",
    method: "PUT",
    aud,
    action: "replaced",
    changed,
    status: 200,
    deniedAddedCount: denied.length,
  });

  return jsonOk({
    aud,
    outcome: "replaced",
    changed,
    denied_preserved: !deniedProvided,
    allowlist: { emails, denied },
    warnings,
  });
}

/**
 * POST adds one allow entry. It refuses with 409 when a deny entry covers the
 * address, because otherwise an operator would get a success for a GRANT that
 * did not take effect — the original defect with its sign reversed.
 */
async function handlePost(request: Request, env: Env, aud: string): Promise<Response> {
  const body = await safeJson(request);
  const arg = readEmailArg(request, body);
  if (!arg.ok) return invalidEmail(arg);
  const target = arg.pattern;

  if (body?.clear_denied !== undefined && typeof body.clear_denied !== "boolean") {
    return jsonError(400, "invalid_body", "clear_denied must be a boolean", { changed: false });
  }
  const clearDenied = body?.clear_denied === true;

  const read = await readStored(env, aud);
  if (read.status === "unavailable" || read.status === "malformed") {
    await audit({
      route: "/admin/allowlist/:aud",
      method: "POST",
      aud,
      action: "record_unusable",
      changed: false,
      status: 503,
      pattern: target,
    });
    return unavailable(aud, "read");
  }
  if (read.status === "missing") {
    await audit({
      route: "/admin/allowlist/:aud",
      method: "POST",
      aud,
      action: "allowlist_not_found",
      changed: false,
      status: 404,
      pattern: target,
    });
    return allowlistNotFound(aud);
  }

  const record = read.record;
  const denied = record.denied ?? [];
  const coveringDeny = matchingPatterns(target, denied);
  const survivingDeny = clearDenied ? coveringDeny.filter((p) => p !== target) : coveringDeny;

  if (survivingDeny.length > 0) {
    await audit({
      route: "/admin/allowlist/:aud",
      method: "POST",
      aud,
      action: "denied_entry_conflict",
      changed: false,
      status: 409,
      pattern: target,
    });
    return jsonError(
      409,
      "denied_entry_conflict",
      `${target} is covered by deny ${survivingDeny.length === 1 ? "entry" : "entries"} ` +
        `'${survivingDeny.join("', '")}'. Adding it to emails would have no effect because deny is ` +
        `evaluated first. Remove the deny entry with DELETE /admin/allowlist/${aud}/denied` +
        `${coveringDeny.includes(target) ? ', or re-send with {"clear_denied": true}' : ""}.`,
      { aud, covering_deny_patterns: survivingDeny, changed: false }
    );
  }

  const nextDenied = clearDenied ? (withoutExact(denied, target) as string[]) : denied;
  const removedDenied = clearDenied && coveringDeny.includes(target) ? [target] : [];
  const alreadyCovered = matchingPatterns(target, record.emails);

  if (removedDenied.length === 0 && alreadyCovered.length > 0) {
    // The requested end state already holds, and it is verified below rather
    // than assumed.
    const verdict = evaluateAllowlistRecord(target, record);
    await audit({
      route: "/admin/allowlist/:aud",
      method: "POST",
      aud,
      action: "already_covered",
      changed: false,
      status: 200,
      pattern: target,
    });
    return jsonOk({
      aud,
      outcome: "already_covered",
      changed: false,
      added: [],
      already_covered_by: alreadyCovered,
      decision_after: verdictJson(verdict),
      allowlist: { emails: record.emails, denied: nextDenied },
      warnings: audienceWarnings(aud),
    });
  }

  const exactPresent = containsExact(record.emails, target);
  const nextEmails = exactPresent ? record.emails : [...record.emails, target];
  const next: Allowlist = { emails: nextEmails, ...(nextDenied.length > 0 ? { denied: nextDenied } : {}) };
  const postCtx = { route: "/admin/allowlist/:aud", method: "POST", pattern: target };
  const stored = await writeStored(env, aud, next, postCtx);
  if (!stored) return unavailable(aud, "written");

  const verdict = evaluateAllowlistRecord(target, stored);
  if (verdict.status !== "allowed") {
    await audit({ ...postCtx, aud, action: "grant_not_effective", changed: true, status: 500 });
    // Unreachable by construction; reported rather than dressed up as a 200.
    return jsonError(
      500,
      "grant_not_effective",
      `${target} was written to the allowlist for '${aud}' but is still not authorized. GET the ` +
        `record and inspect it.`,
      { aud, decision_after: verdictJson(verdict), changed: true }
    );
  }

  const outcome = removedDenied.length > 0 ? "added_and_deny_cleared" : "added";
  await audit({
    route: "/admin/allowlist/:aud",
    method: "POST",
    aud,
    action: outcome,
    changed: true,
    status: 200,
    pattern: target,
  });

  return jsonOk({
    aud,
    outcome,
    changed: true,
    added: exactPresent ? [] : [target],
    ...(removedDenied.length > 0 ? { removed_denied: removedDenied } : {}),
    decision_after: verdictJson(verdict),
    allowlist: { emails: nextEmails, denied: nextDenied },
    warnings: audienceWarnings(aud),
  });
}

/**
 * DELETE — THE REVOCATION.
 *
 * Resolution order, and why each refusal is a refusal:
 *
 *   1. An unsupported audience is 404. The route regex accepts any string, so
 *      `compliance_mcp` used to return 200 and write a dead KV key while the
 *      real audience kept working.
 *   2. A `*@domain` argument needs `confirm_wildcard_removal`, because removing
 *      a domain pattern deprovisions an entire customer and must not be
 *      reachable from a command whose whole purpose is to revoke ONE person.
 *   3. A malformed record is 503 and no write. Interpreting a record whose true
 *      content is unknown risks acting on a misparse; overwriting it destroys
 *      the evidence and can widen access. Refusing is the only safe third
 *      option, and GET still returns the raw value for repair.
 *   4. Literal entries matching the address are removed; every other entry,
 *      including non-string junk, is preserved verbatim. DELETE narrows, never
 *      widens.
 *   5. If a wildcard still covers the address, the normalized literal is added
 *      to `denied` IN THE SAME WRITE (`mode: "remove_only"` refuses with 409
 *      instead, for scripts that must not have a deny entry created on their
 *      behalf).
 *   6. Nothing matched and nothing covers it: 404. The dominant real cause is a
 *      typo, and a runbook step that returns 2xx on a typo is the failure mode
 *      being fixed. An address an existing deny entry already covers is
 *      different — that end state is real and verified, so it is a 200 and
 *      retries are idempotent.
 *
 * CONCURRENCY, stated rather than hidden: Workers KV has no compare-and-swap, so
 * this read-modify-write can lose a concurrent PUT. The deny addition is
 * additive-only, so the worst case is a deny entry that does not land — and the
 * operator sees it, because `decision_after` is computed from what was actually
 * written and the runbook step is to re-GET.
 */
async function handleDelete(request: Request, env: Env, aud: string): Promise<Response> {
  const body = await safeJson(request);
  const arg = readEmailArg(request, body);
  if (!arg.ok) return invalidEmail(arg);
  const target = arg.pattern;

  const route = "/admin/allowlist/:aud";
  const mode = body?.mode === undefined ? "auto" : body.mode;
  if (mode !== "auto" && mode !== "remove_only") {
    return jsonError(400, "invalid_body", 'mode must be "auto" or "remove_only"', { changed: false });
  }
  if (body?.confirm_wildcard_removal !== undefined && typeof body.confirm_wildcard_removal !== "boolean") {
    return jsonError(400, "invalid_body", "confirm_wildcard_removal must be a boolean", {
      changed: false,
    });
  }

  if (!SUPPORTED_AUDS.has(aud)) {
    await audit({ route, method: "DELETE", aud, action: "unknown_audience", changed: false, status: 404, pattern: target });
    return unknownAudience(aud);
  }

  if (isWildcard(target) && body?.confirm_wildcard_removal !== true) {
    await audit({ route, method: "DELETE", aud, action: "wildcard_removal_requires_confirmation", changed: false, status: 409, pattern: target });
    return jsonError(
      409,
      "wildcard_removal_requires_confirmation",
      `'${target}' is a domain pattern. Removing it revokes every identity at ${target.slice(2)}, ` +
        `not one user. To revoke one user, send that user's address. To proceed, re-send with ` +
        `{"confirm_wildcard_removal": true}.`,
      { aud, changed: false }
    );
  }

  const read = await readStored(env, aud);
  if (read.status === "unavailable" || read.status === "malformed") {
    await audit({ route, method: "DELETE", aud, action: "record_unusable", changed: false, status: 503, pattern: target });
    return unavailable(aud, "read");
  }
  if (read.status === "missing") {
    await audit({ route, method: "DELETE", aud, action: "allowlist_not_found", changed: false, status: 404, pattern: target });
    return allowlistNotFound(aud);
  }

  const record = read.record;
  const denied = record.denied ?? [];
  const removed = matchingPatterns(target, record.emails).filter((p) => p === target);
  const remainingEmails = withoutExact(record.emails, target) as string[];
  const coveringPatterns = matchingPatterns(target, remainingEmails);
  const coveringDeny = matchingPatterns(target, denied);

  // The confirmed removal of a domain pattern. It is not a single-user
  // revocation and is reported as its own outcome.
  if (isWildcard(target)) {
    if (removed.length === 0) {
      await audit({ route, method: "DELETE", aud, action: "not_allowlisted", changed: false, status: 404, pattern: target });
      return notAllowlisted(aud, target, record.emails.length);
    }
    const next: Allowlist = { emails: remainingEmails, ...(denied.length > 0 ? { denied } : {}) };
    const stored = await writeStored(env, aud, next, { route, method: "DELETE", pattern: target });
    if (!stored) {
      return unavailable(aud, "written");
    }
    if (containsExact(stored.emails, target)) {
      await audit({ route, method: "DELETE", aud, action: "revocation_not_effective", changed: true, status: 500, pattern: target });
      return revocationNotEffective(aud, target, evaluateAllowlistRecord(target, stored));
    }
    await audit({ route, method: "DELETE", aud, action: "wildcard_removed", changed: true, status: 200, pattern: target, removedCount: removed.length });
    return revocationOk({
      aud,
      outcome: "wildcard_removed",
      changed: true,
      removed,
      deniedAdded: [],
      coveringPatterns: [],
      record: stored,
      verdict: evaluateAllowlistRecord(target, stored),
      message:
        `'${target}' is removed from the allowlist for ${aud}. Every identity at ${target.slice(2)} ` +
        `that it authorized has lost access; any listed individually still has it.`,
    });
  }

  if (removed.length === 0 && coveringPatterns.length === 0 && coveringDeny.length === 0) {
    await audit({ route, method: "DELETE", aud, action: "not_allowlisted", changed: false, status: 404, pattern: target });
    return notAllowlisted(aud, target, record.emails.length);
  }

  // Already revoked: the end state holds, so a retry is idempotent. Verified,
  // not assumed — the verdict below comes from the stored record.
  if (removed.length === 0 && coveringDeny.length > 0) {
    await audit({ route, method: "DELETE", aud, action: "already_revoked", changed: false, status: 200, pattern: target });
    return revocationOk({
      aud,
      outcome: "already_revoked",
      changed: false,
      removed: [],
      deniedAdded: [],
      coveringPatterns,
      record,
      verdict: evaluateAllowlistRecord(target, record),
      message: `${target} was already revoked for ${aud} by deny entry '${coveringDeny[0]}'. Nothing changed.`,
    });
  }

  if (mode === "remove_only" && coveringPatterns.length > 0 && coveringDeny.length === 0) {
    await audit({ route, method: "DELETE", aud, action: "covered_by_wildcard", changed: false, status: 409, pattern: target });
    return jsonError(
      409,
      "covered_by_wildcard",
      `'${target}' is covered by '${coveringPatterns[0]}', so removing literal entries does not ` +
        `revoke it. Re-send without "mode":"remove_only" to add a deny entry, or remove the pattern ` +
        `with {"email":"${coveringPatterns[0]}","confirm_wildcard_removal":true} — which revokes ` +
        `every identity at ${coveringPatterns[0].slice(2)}.`,
      {
        aud,
        covering_patterns: coveringPatterns,
        removed_would_be: removed,
        changed: false,
      }
    );
  }

  const needsDeny = coveringPatterns.length > 0 && coveringDeny.length === 0;
  const nextDenied = needsDeny ? [...denied, target] : denied;
  const next: Allowlist = {
    emails: remainingEmails,
    ...(nextDenied.length > 0 ? { denied: nextDenied } : {}),
  };
  const stored = await writeStored(env, aud, next, { route, method: "DELETE", pattern: target });
  if (!stored) {
    return unavailable(aud, "written");
  }

  // THE GATE. A 200 is impossible unless the record that was actually written
  // denies this identity. `stored` is the read-back from KV, not the object we
  // intended to write — the distinction is the whole point of the gate.
  const verdict = evaluateAllowlistRecord(target, stored);
  if (verdict.status !== "denied") {
    await audit({ route, method: "DELETE", aud, action: "revocation_not_effective", changed: true, status: 500, pattern: target });
    return revocationNotEffective(aud, target, verdict);
  }

  const outcome = needsDeny ? (removed.length > 0 ? "removed_and_denied" : "denied") : "removed";
  await audit({
    route,
    method: "DELETE",
    aud,
    action: outcome,
    changed: true,
    status: 200,
    pattern: target,
    removedCount: removed.length,
    deniedAddedCount: needsDeny ? 1 : 0,
  });

  const message = needsDeny
    ? `${target} is revoked for ${aud}. '${coveringPatterns[0]}' is unchanged, so everyone else at ` +
      `${coveringPatterns[0].slice(2)} keeps access.`
    : `${target} is revoked for ${aud}.`;

  return revocationOk({
    aud,
    outcome,
    changed: true,
    removed,
    deniedAdded: needsDeny ? [target] : [],
    coveringPatterns,
    record: next,
    verdict,
    message,
  });
}

function notAllowlisted(aud: string, target: string, emailsCount: number): Response {
  return jsonError(
    404,
    "not_allowlisted",
    `'${target}' is not authorized for '${aud}': no literal entry matched and no domain pattern ` +
      `covers it. No change was made. Check the address and the audience.`,
    { aud, emails_count: emailsCount, changed: false }
  );
}

function revocationNotEffective(aud: string, target: string, verdict: AllowlistVerdict): Response {
  return jsonError(
    500,
    "revocation_not_effective",
    `The record for '${aud}' was written but ${target} is still authorized by it. Do not treat this ` +
      `as a revocation. GET the record and inspect it.`,
    { aud, decision_after: verdictJson(verdict), changed: true }
  );
}

function revocationOk(opts: {
  aud: string;
  outcome: string;
  changed: boolean;
  removed: string[];
  deniedAdded: string[];
  coveringPatterns: string[];
  record: Allowlist;
  verdict: AllowlistVerdict;
  message: string;
}): Response {
  return jsonOk({
    aud: opts.aud,
    outcome: opts.outcome,
    changed: opts.changed,
    removed: opts.removed,
    denied_added: opts.deniedAdded,
    covering_patterns: opts.coveringPatterns,
    decision_after: verdictJson(opts.verdict),
    effective_for: EFFECTIVE_FOR,
    not_effective_for: NOT_EFFECTIVE_FOR,
    propagation: PROPAGATION,
    allowlist: { emails: opts.record.emails, denied: opts.record.denied ?? [] },
    message: opts.message,
    warnings: audienceWarnings(opts.aud),
  });
}

// ---------------------------------------------------------------------------
// /admin/allowlist/<aud>/denied
// ---------------------------------------------------------------------------

/**
 * The deny list as a first-class object, because a revocation control with no
 * un-revoke is an operational trap: re-instating one person must not mean
 * re-typing an entire `emails` array through PUT and hoping nothing was lost.
 */
export async function adminAllowlistDeniedHandler(
  request: Request,
  env: Env,
  aud: string
): Promise<Response> {
  const guard = requireAdminToken(request, env);
  if (guard) return guard;

  const route = "/admin/allowlist/:aud/denied";
  if (!SUPPORTED_AUDS.has(aud)) return unknownAudience(aud);

  if (request.method === "GET") {
    const read = await readStored(env, aud);
    if (read.status === "unavailable" || read.status === "malformed") return unavailable(aud, "read");
    if (read.status === "missing") return allowlistNotFound(aud);
    const denied = read.record.denied ?? [];
    return jsonOk({ aud, denied, count: denied.length });
  }

  if (request.method !== "POST" && request.method !== "DELETE") {
    return jsonError(405, "method_not_allowed", "GET/POST/DELETE supported");
  }

  const body = await safeJson(request);
  const arg = readEmailArg(request, body);
  if (!arg.ok) return invalidEmail(arg);
  const target = arg.pattern;

  const read = await readStored(env, aud);
  if (read.status === "unavailable" || read.status === "malformed") {
    await audit({ route, method: request.method, aud, action: "record_unusable", changed: false, status: 503, pattern: target });
    return unavailable(aud, "read");
  }
  if (read.status === "missing") {
    await audit({ route, method: request.method, aud, action: "allowlist_not_found", changed: false, status: 404, pattern: target });
    return allowlistNotFound(aud);
  }

  const record = read.record;
  const denied = record.denied ?? [];

  if (request.method === "POST") {
    // A `*@domain` deny is accepted HERE and nowhere else: it is the deliberate
    // escape hatch for revoking a whole sub-domain, kept off the DELETE route so
    // a single-user revocation can never deprovision a customer by accident.
    if (containsExact(denied, target)) {
      await audit({ route, method: "POST", aud, action: "already_denied", changed: false, status: 200, pattern: target });
      return jsonOk({
        aud,
        outcome: "already_denied",
        changed: false,
        denied_added: [],
        decision_after: verdictJson(evaluateAllowlistRecord(target, record)),
        denied,
        warnings: [],
      });
    }
    const nextDenied = [...denied, target];
    const next: Allowlist = { emails: record.emails, denied: nextDenied };
    const stored = await writeStored(env, aud, next, { route, method: "POST", pattern: target });
    if (!stored) {
      return unavailable(aud, "written");
    }

    const verdict = evaluateAllowlistRecord(target, stored);
    if (verdict.status !== "denied") {
      await audit({ route, method: "POST", aud, action: "revocation_not_effective", changed: true, status: 500, pattern: target });
      return revocationNotEffective(aud, target, verdict);
    }

    const warnings =
      matchingPatterns(target, record.emails).length === 0
        ? [`${target} is not currently covered by any allow pattern; this deny entry is pre-emptive`]
        : [];
    await audit({ route, method: "POST", aud, action: "denied", changed: true, status: 200, pattern: target, deniedAddedCount: 1 });

    return jsonOk({
      aud,
      outcome: "denied",
      changed: true,
      denied_added: [target],
      decision_after: verdictJson(verdict),
      effective_for: EFFECTIVE_FOR,
      not_effective_for: NOT_EFFECTIVE_FOR,
      propagation: PROPAGATION,
      denied: nextDenied,
      warnings,
    });
  }

  // DELETE — re-instate.
  if (!containsExact(denied, target)) {
    await audit({ route, method: "DELETE", aud, action: "deny_entry_not_found", changed: false, status: 404, pattern: target });
    return jsonError(
      404,
      "deny_entry_not_found",
      `No deny entry '${target}' for '${aud}'. Nothing was changed. GET ` +
        `/admin/allowlist/${aud}/denied to see what is there; a broader pattern such as ` +
        `'*@${target.split("@").pop()}' has to be removed by name.`,
      { aud, changed: false }
    );
  }

  const nextDenied = withoutExact(denied, target) as string[];
  const next: Allowlist = {
    emails: record.emails,
    ...(nextDenied.length > 0 ? { denied: nextDenied } : {}),
  };
  const stored = await writeStored(env, aud, next, { route, method: "DELETE", pattern: target });
  if (!stored) {
    return unavailable(aud, "written");
  }

  const verdict = evaluateAllowlistRecord(target, stored);
  await audit({ route, method: "DELETE", aud, action: "deny_entry_removed", changed: true, status: 200, pattern: target });

  return jsonOk({
    aud,
    outcome: "deny_entry_removed",
    changed: true,
    removed_denied: [target],
    decision_after: verdictJson(verdict),
    denied: nextDenied,
    message:
      verdict.status === "allowed"
        ? `${target} is authorized again by '${verdict.matchedBy}'.`
        : `The deny entry is gone, but ${target} is still not authorized because no allow pattern ` +
          `matches. POST to /admin/allowlist/${aud} to grant access.`,
  });
}
