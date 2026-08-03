# AGENTS.md

## Cursor Cloud specific instructions

Cloudflare Worker (TypeScript) — central OAuth/OIDC provider (`auth.techimpossible.com`). Standard commands are in `README.md`; the notes below are the non-obvious cloud caveats.

- Node 22 / npm. `npm install` works with no special flags; this repo is self-contained (no external repo dependencies).
- Test: `npm test` (vitest). Typecheck: `npm run typecheck`. Dev: `npm run dev` or `npx wrangler dev --local --port 8788`.
- `wrangler dev` runs fully locally via Miniflare — KV bindings are simulated and **no Cloudflare account/login is required**. Discovery endpoints (`/.well-known/openid-configuration`, `/.well-known/jwks.json`) respond immediately and are a quick smoke test.
- Other workers in this org (`compliance-mcp`, `BasecampClaudeMCP`) verify JWTs minted here via an `AUTH_SERVICE` service binding; those bindings are not wired across separate `wrangler dev` processes, so cross-worker auth is only exercised in deployed environments.
