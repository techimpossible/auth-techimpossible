/**
 * Client credential extraction shared by every /token grant.
 *
 * Prefers HTTP Basic (RFC 6749 §2.3.1) and falls back to the form-encoded
 * client_id / client_secret. Kept in a leaf module so grant handlers can share
 * it without importing one another.
 */
export function extractClientCredentials(
  request: Request,
  form: URLSearchParams
): { clientId: string | null; clientSecret: string | null } {
  const basic = request.headers.get("authorization");
  if (basic && /^basic\s+/i.test(basic)) {
    try {
      const decoded = atob(basic.replace(/^basic\s+/i, ""));
      const idx = decoded.indexOf(":");
      if (idx >= 0) {
        return {
          clientId: decodeURIComponent(decoded.slice(0, idx)),
          clientSecret: decodeURIComponent(decoded.slice(idx + 1)),
        };
      }
    } catch {
      // fall through
    }
  }
  return {
    clientId: form.get("client_id"),
    clientSecret: form.get("client_secret"),
  };
}
