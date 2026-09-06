import { escapeHtml } from "./html.js";

/**
 * Shown when /authorize refuses a client that is not permitted to send an
 * authorization code to the destination it asked for.
 *
 * A COURTESY, NOT A CONTROL. The request is already refused before this renders,
 * no code exists, and no security decision depends on the reader believing it.
 * It is here so that a person who clicked a phishing link sees a warning instead
 * of raw JSON — and so that the client name, which is attacker-supplied at
 * registration, is shown as a claim rather than as a fact.
 */
export function renderClientRefusedPage(opts: {
  clientName?: string;
  redirectOrigin: string;
}): Response {
  const claimedName = opts.clientName?.trim() ? opts.clientName.trim() : "(no name given)";
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign-in refused — Techimpossible MCP</title>
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
  <h1>This application is not permitted to sign you in</h1>
  <p><strong>Do not continue.</strong> It asked to send your Techimpossible sign-in to a destination this server does not allow. Nothing was sent, and you were not signed in.</p>
  <div class="row"><span>Application claims to be</span><code>${escapeHtml(claimedName)}</code></div>
  <div class="row"><span>Destination it asked for</span><code>${escapeHtml(opts.redirectOrigin)}</code></div>
  <div class="cta">If you did not expect this, the link you followed was probably not from Techimpossible. Please forward it to <a href="mailto:peter.skaronis@techimpossible.com">peter.skaronis@techimpossible.com</a> rather than clicking it again. If this is a real integration, it needs its callback host approved first.</div>
</main>
</body>
</html>`;
  return new Response(html, {
    status: 400,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
  });
}
