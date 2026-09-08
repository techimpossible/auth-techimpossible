/**
 * The interactive counterpart of `503 temporarily_unavailable`.
 *
 * The Google callback is a BROWSER surface, so its answer to "the authorization
 * decision could not be made" has to be a page a person can act on. A JSON error
 * body is a dead end there, and the 403 "you are not on the allowlist" page
 * would be a lie: nothing was decided about this account. The distinction is the
 * same one src/allowlist/check.ts keeps on the token endpoint — denied means the
 * credential is dead, unavailable means try again.
 */
export function renderTemporarilyUnavailablePage(opts: { aud: string }): Response {
  const safeAud = opts.aud.replace(/[^a-zA-Z0-9_-]/g, "");
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Temporarily unavailable — Techimpossible MCP</title>
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
  <h1>Temporarily unavailable</h1>
  <p>Your sign-in could not be completed because this service could not check your authorization right now. This is a fault on our side, not a decision about your account.</p>
  <div class="row"><span>Audience</span><code>${safeAud}</code></div>
  <div class="cta">Wait a few seconds and start the sign-in again. If it keeps happening, email <a href="mailto:peter.skaronis@techimpossible.com">peter.skaronis@techimpossible.com</a> with the audience above.</div>
</main>
</body>
</html>`;
  return new Response(html, {
    status: 503,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Retry-After": "5",
    },
  });
}
