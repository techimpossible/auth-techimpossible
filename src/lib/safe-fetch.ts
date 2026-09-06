/**
 * Guarded outbound JSON fetch for URLs that are influenced by a customer or a
 * client: the OIDC discovery document of a tenant's registered issuer, and a
 * CIMD client_id metadata document.
 *
 * Guards: redirects are never followed (`redirect: "manual"`, so a 3xx is a hard
 * failure and cannot be used to pivot to an internal host), the request is
 * aborted after `timeoutMs`, the response must declare a JSON content type, and
 * the body is capped at `maxBytes`. Never throws — returns null on any failure.
 *
 * Host-level SSRF filtering (https only, no IP literals, no internal names) is
 * the caller's job via assertSafeHttpsUrl in src/tenants/model.ts; this function
 * is the transport half of the same control.
 */
export async function fetchJsonGuarded(
  url: string,
  opts: { timeoutMs?: number; maxBytes?: number } = {}
): Promise<Record<string, unknown> | null> {
  const outcome = await fetchJsonOutcome(url, opts);
  return outcome.status === "ok" ? outcome.doc : null;
}

/**
 * The same fetch, but saying WHY it failed.
 *
 * "unreachable" (the request never produced a usable HTTP response: DNS, TLS,
 * timeout, 5xx, a CDN redirect) and "invalid" (we read a response and the
 * document is not what it must be) call for opposite caching decisions. Folding
 * both into null turned one momentary blip into a long negative-cache entry and
 * a multi-minute authentication outage for a client whose upstream had already
 * recovered.
 */
export type JsonFetchOutcome =
  | { status: "ok"; doc: Record<string, unknown> }
  | { status: "unreachable" }
  | { status: "invalid" };

export async function fetchJsonOutcome(
  url: string,
  opts: { timeoutMs?: number; maxBytes?: number } = {}
): Promise<JsonFetchOutcome> {
  const timeoutMs = opts.timeoutMs ?? 3000;
  const maxBytes = opts.maxBytes ?? 262144;

  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
      headers: { accept: "application/json" },
    });
  } catch {
    return { status: "unreachable" };
  }

  // A 3xx is not followed (that is the SSRF guard), a 5xx is the origin failing,
  // and 429 is back-pressure: all three are conditions that clear on their own.
  if (response.status !== 200) {
    const transient = response.status >= 300 && response.status < 400;
    return transient || response.status >= 500 || response.status === 429
      ? { status: "unreachable" }
      : { status: "invalid" };
  }

  const contentType = response.headers.get("content-type") ?? "";
  if (!/^application\/(json|[a-z0-9.+-]*\+json)\b/i.test(contentType.trim())) {
    return { status: "invalid" };
  }

  const declared = response.headers.get("content-length");
  if (declared && Number(declared) > maxBytes) return { status: "invalid" };

  let text: string;
  try {
    text = await response.text();
  } catch {
    return { status: "unreachable" };
  }
  if (text.length > maxBytes) return { status: "invalid" };

  try {
    const parsed = JSON.parse(text) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return { status: "invalid" };
    return { status: "ok", doc: parsed as Record<string, unknown> };
  } catch {
    return { status: "invalid" };
  }
}
