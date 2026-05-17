export function renderForbiddenPage(opts: { email: string; aud: string }): Response {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Access denied — Techimpossible MCP</title>
<style>
  body { font-family: system-ui, sans-serif; background: #f8fafc; color: #0f172a; margin: 0; }
  main { max-width: 480px; margin: 12vh auto; padding: 32px 28px; background: white; border-radius: 12px; box-shadow: 0 4px 16px rgba(15,23,42,0.07); }
  h1 { font-size: 20px; margin: 0 0 12px; }
  p { font-size: 14px; line-height: 1.55; color: #475569; }
  .row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #e2e8f0; font-size: 13px; }
  .row:last-child { border-bottom: 0; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 12px; }
  .cta { margin-top: 20px; padding: 12px 14px; background: #f1f5f9; border-radius: 8px; font-size: 13px; color: #334155; }
</style>
</head>
<body>
<main>
  <h1>Access denied</h1>
  <p>Your Google account is not on the allowlist for this Techimpossible MCP audience.</p>
  <div class="row"><span>Account</span><code>${escapeHtml(opts.email)}</code></div>
  <div class="row"><span>Audience</span><code>${escapeHtml(opts.aud)}</code></div>
  <div class="cta">If you should have access, email <a href="mailto:peter.skaronis@techimpossible.com">peter.skaronis@techimpossible.com</a> with the account and audience above. No further action will succeed from this screen.</div>
</main>
</body>
</html>`;
  return new Response(html, {
    status: 403,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
  });
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => {
    if (c === "&") return "&amp;";
    if (c === "<") return "&lt;";
    if (c === ">") return "&gt;";
    if (c === '"') return "&quot;";
    return "&#39;";
  });
}
