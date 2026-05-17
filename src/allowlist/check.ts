import type { Allowlist, Env } from "../env.js";

export function isEmailAllowed(email: string, patterns: string[]): boolean {
  if (!email || patterns.length === 0) return false;
  const normalized = email.toLowerCase().trim();
  for (const raw of patterns) {
    if (typeof raw !== "string") continue;
    const pattern = raw.toLowerCase().trim();
    if (!pattern) continue;
    if (pattern.startsWith("*@")) {
      const domain = pattern.slice(2);
      if (!domain) continue;
      if (normalized.endsWith("@" + domain)) return true;
    } else if (pattern === normalized) {
      return true;
    }
  }
  return false;
}

export async function loadAllowlist(env: Env, aud: string): Promise<Allowlist | null> {
  const record = await env.ALLOWLIST_KV.get<Allowlist>(`allowlist:${aud}`, "json");
  if (!record) return null;
  if (!Array.isArray(record.emails)) return null;
  return record;
}
