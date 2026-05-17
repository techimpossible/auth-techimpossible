# auth.techimpossible.com

Central OAuth provider for Techimpossible MCP endpoints. Federates identity to
Google OIDC, enforces a per-audience email allowlist, and mints RS256-signed
JWTs that resource servers (`mcp.techimpossible.com`,
`basecamp-mcp.techimpossible.com`) verify offline against
`/.well-known/jwks.json`.

## Why this Worker exists

Spec'd in `~/tasks/prd-mcp-cloudflare-access-migration-v4.md` (PRD v4). One
central OAuth surface; each MCP becomes a thin resource server. Per-MCP access
is a single KV write (`PUT /admin/allowlist/<aud>`) — no Worker redeploys to
add or revoke users.

## Architecture

```
Claude.ai client
    │
    │  OAuth 2.1 + PKCE (DCR optional)
    ▼
auth.techimpossible.com
    │
    │  302 to Google with state nonce stored in OAUTH_KV
    ▼
accounts.google.com
    │
    │  302 back with Google authorization code
    ▼
auth.techimpossible.com /oauth/callback
    │  - exchange code with Google
    │  - verify Google ID token (RS256 vs Google JWKS)
    │  - allowlist check against ALLOWLIST_KV by aud
    │  - mint our own RS256 JWT
    ▼
client redirect_uri  ──►  token exchange  ──►  signed JWT
                                                  │
                                                  ▼
                                      mcp.techimpossible.com (resource server)
                                      basecamp-mcp.techimpossible.com (resource server)
                                          verify with our JWKS
```

## Routes

| Route | Method | Description |
|---|---|---|
| `/` | GET | Health JSON |
| `/.well-known/oauth-authorization-server` | GET | RFC 8414 discovery |
| `/.well-known/openid-configuration` | GET | OIDC discovery (alias of above) |
| `/.well-known/jwks.json` | GET | Public RS256 key, `kid`, `use: sig` |
| `/register` | POST | RFC 7591 dynamic client registration |
| `/authorize` | GET | Parses OAuth request, stores state, 302 to Google |
| `/oauth/callback` | GET | Receives Google code, verifies ID token, allowlist check, mints our auth code |
| `/token` | POST | Exchanges our auth code for an RS256 JWT access token |
| `/admin/allowlist/:aud` | GET/PUT/POST/DELETE | Bearer-protected allowlist CRUD |

## Audiences

The Worker today recognizes two audience identifiers:

- `mcp-techimpossible` — for `https://mcp.techimpossible.com/mcp`
- `basecamp-mcp` — for `https://basecamp-mcp.techimpossible.com/mcp`

Clients can request a target audience by passing `?resource=https://mcp.techimpossible.com/mcp`
(or the literal aud string) on `/authorize`. If absent, defaults to
`mcp-techimpossible`.

## JWT claim shape

```json
{
  "iss": "https://auth.techimpossible.com",
  "aud": "mcp-techimpossible",
  "sub": "<google-subject-id>",
  "email": "peter@techimpossible.com",
  "email_verified": true,
  "iat": 1778999999,
  "exp": 1779003599,
  "tenant_id": null,
  "roles": []
}
```

`tenant_id` and `roles` are reserved for the Phase 2 readiness-mcp work
(see PRD v4 §6); current values are always `null` / `[]`.

## Allowlist KV data model

Key: `allowlist:<aud>`
Value (JSON):

```json
{ "emails": ["*@techimpossible.com", "client-a@external.example"] }
```

Matching rules implemented in `src/allowlist/check.ts`:

- `*@domain` matches any email whose right-of-`@` equals `domain` (case-insensitive).
- Plain `user@domain` matches exactly (case-insensitive).
- Empty / missing record fails closed (403 forbidden page).

## Local development

```bash
npm install
npm run typecheck
npm test
```

## Deploy (first time)

```bash
# 1. Create KV namespaces and capture their IDs:
npx wrangler kv namespace create OAUTH_KV
npx wrangler kv namespace create ALLOWLIST_KV
npx wrangler kv namespace create TENANT_KV
# Paste each id into wrangler.toml (replace the REPLACE_* placeholders).

# 2. First deploy (vars only, no secrets yet):
npx wrangler deploy

# 3. Set secrets:
source ~/.google-oidc-creds
echo -n "$GOOGLE_OIDC_CLIENT_SECRET" | npx wrangler secret put GOOGLE_OIDC_CLIENT_SECRET
openssl rand -hex 32 | tee /tmp/admin.tok | npx wrangler secret put ADMIN_API_TOKEN
mv /tmp/admin.tok ~/auth-techimpossible/.local/admin-token.txt
chmod 600 ~/auth-techimpossible/.local/admin-token.txt
# Document the token in tasks/admin-api-token.md (gitignored under ~/ralph).

# 4. Seed allowlists:
ADMIN_TOKEN=$(cat ~/auth-techimpossible/.local/admin-token.txt)
curl -X PUT https://auth.techimpossible.com/admin/allowlist/mcp-techimpossible \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"emails":["*@techimpossible.com"]}'
curl -X PUT https://auth.techimpossible.com/admin/allowlist/basecamp-mcp \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"emails":["*@techimpossible.com"]}'
```

DNS for `auth.techimpossible.com` must already exist as a proxied record on the
`techimpossible.com` zone — the Worker route binding takes effect once the
record is present and orange-clouded.

## Smoke tests

```bash
# Discovery
curl -s https://auth.techimpossible.com/.well-known/oauth-authorization-server | jq

# JWKS
curl -s https://auth.techimpossible.com/.well-known/jwks.json | jq

# Dynamic client registration
curl -s -X POST https://auth.techimpossible.com/register \
  -H 'Content-Type: application/json' \
  -d '{"redirect_uris":["https://example.com/callback"],"client_name":"smoke"}' | jq

# Allowlist read
curl -s https://auth.techimpossible.com/admin/allowlist/mcp-techimpossible \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq
```

## Adding a paying client

1. Add their email (or `*@theirdomain.com` if the whole org pays) to the
   relevant allowlist via the admin API.
2. Add the same email to the Google OAuth consent screen **Test users** list
   at `https://console.cloud.google.com/apis/credentials/consent` (until the
   OAuth app is verified).

## Security notes

- All authorization codes, state nonces, and signing keys live in `OAUTH_KV`.
- Client secrets are stored only as SHA-256 hashes.
- The signing key (RSA-2048) is generated on first request and stored in
  `OAUTH_KV` at `signing-key:rs256:v1`. Rotation: write a new entry under
  `signing-key:rs256:v2`, expose both in `/.well-known/jwks.json` via a
  follow-up; resource-server JWKS caches are 1h, so brief overlap is fine.
- The admin API is Bearer-protected by `ADMIN_API_TOKEN`. Phase 2 swaps this
  for Google-sign-in admin scope when `clients.techimpossible.com` lands.

## Why we don't use `@cloudflare/workers-oauth-provider`

The PRD originally specified the library as the OAuth surface. In practice,
v0.4.0 issues opaque tokens of the shape `userId:grantId:<random>` and
verifies them by calling back into the same Worker (`env.OAUTH_PROVIDER`). It
exposes no JWKS endpoint and signs nothing with RS256.

This architecture has resource servers on *different* Workers
(`mcp.techimpossible.com`, `basecamp-mcp.techimpossible.com`) that need to
verify tokens **offline** against `/.well-known/jwks.json`. That requirement
is incompatible with the library's design, so this Worker implements the
DCR / authorize / callback / token flow directly using `jose` for RS256
signing and JWKS export.

If a future library version ever ships RS256 + JWKS, revisit this decision.
