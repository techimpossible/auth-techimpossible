/**
 * Shared HTML escaping for the pages this server renders to a browser.
 *
 * Extracted from src/pages/forbidden.ts rather than copied, for the same reason
 * src/lib/admin-auth.ts exists: a second copy means a future fix has two call
 * sites, and a third means it has three.
 */
export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => {
    if (c === "&") return "&amp;";
    if (c === "<") return "&lt;";
    if (c === ">") return "&gt;";
    if (c === '"') return "&quot;";
    return "&#39;";
  });
}
