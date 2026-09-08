# auth.techimpossible.com — how it all flows

Grounded in the code as it stands now, in the working tree at `/home/claude/auth-techimpossible`. Nothing here is deployed, committed or pushed.

Line references point at the current files, but they are an aid to finding the code, not a contract: the three security fixes described in section 5 (the refresh-grant revocation control, the DCR redirect-destination rule, and the `jwks_uri` binding tiers) moved a good deal of `src/oauth/token.ts`, `src/oauth/authorize.ts`, `src/oauth/register.ts` and `src/tenants/`. Where a number and a symbol name disagree, trust the name.

The Worker entry point is `src/index.ts:18`. It routes:

| Path | Handler |
|---|---|
| `/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration` | `src/index.ts:26,29` → `src/oauth/discovery.ts:4` |
| `/.well-known/jwks.json` | `src/index.ts:32` |
| `/register` (unauthenticated DCR) | `src/index.ts:36` → `src/oauth/register.ts:5` |
| `/authorize` | `src/index.ts:37` → `src/oauth/authorize.ts:27` |
| `/token` (all four grants) | `src/index.ts:38` → `src/oauth/token.ts:14` |
| `/oauth/callback` (Google) | `src/index.ts:39` → `src/google/callback.ts:11` |
| `/admin/allowlist/<aud>` | `src/index.ts` → `adminAllowlistHandler` (`src/allowlist/admin.ts`) |
| `/admin/allowlist/<aud>/denied` | `src/index.ts` → `adminAllowlistDeniedHandler` (`src/allowlist/admin.ts`) |
| `/admin/tenants`, `/admin/tenants/<id>`, `/admin/tenants/<id>/issuers` | `src/index.ts:49,53,58` → `src/tenants/admin.ts:452,467,683` |
| `/admin/service-clients` | `src/index.ts:63` → `src/oauth/service-clients.ts:53` |

Every `/admin/*` route is gated by one shared guard, `requireAdminToken` (`src/lib/admin-auth.ts:14`). It requires `Authorization: Bearer $ADMIN_API_TOKEN` and fails closed when the secret is unset.

All three ways in end at one function: `mintAccessToken` (`src/lib/jwt.ts:16`). It signs RS256 with the key in `OAUTH_KV`, and always emits `iss`, `aud`, `sub`, `email`, `email_verified`, `tenant_id`, `roles`, `iat`, `exp`. Only the EMA grant passes a non-null `tenant_id` (`src/lib/jwt.ts:36`).

---

## 1. The three ways in

### a. Interactive Google OIDC

**Who uses it.** Hermes (its own OAuth 2.1 PKCE client), Claude.ai and Claude Desktop connectors, Peter in a browser, and any client whose users have no supported enterprise IdP. This is the default path and the only path for a client without an IdP.

**Flow.**

1. The client calls `GET /authorize` (`src/oauth/authorize.ts:27`). The handler reads `response_type`, `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge`, `resource` (`:38-45`).
2. `resolveClient` finds the client record (`:53`, see `src/oauth/clients.ts:24`). A `ti-` id comes from `OAUTH_KV`; an `https://` id resolves as a CIMD document, but only when the operator lists the exact URL in `CIMD_CLIENT_IDS` (`src/oauth/cimd.ts:85`). That variable is commented out in `wrangler.toml`, so CIMD is off today.
3. **Redirect destination, two stages.** `redirectAllowed` (rule at `:21`) accepts an exact registered redirect, or any loopback URI when the client registered a loopback URI. That alone proves only that the client asked for a redirect it registered *itself*, so for a client nobody vetted it proves nothing: `/register` is unauthenticated and the client supplies its own `redirect_uris`. So a second check follows for any client whose `registrationSource` is not `admin` or `cimd` — `redirectDestinationPermitted` (`src/oauth/redirect-policy.ts`), which permits only an RFC 8252 loopback URI (`127.0.0.1`, `[::1]` or `localhost`, any port, any path) or an https URI on a vetted host (built-in `claude.ai`/`claude.com`, extended by `DCR_REDIRECT_HOSTS`). Anything else is refused with `400 unauthorized_client`, or an HTML warning page when the request accepts HTML (`src/pages/client-refused.ts`), and logged as `evt: "authorize.redirect_refused"` carrying the rejected ORIGIN only. Registration enforces the same rule (`src/oauth/register.ts`); the check here is what also neutralises any client record registered before the rule existed.
4. `inferAudience` (`:121`) maps `resource` to one of `compliance-mcp`, `basecamp-mcp`, `finance-mcp`. With no `resource` it returns `compliance-mcp`. It refuses `mcp.techimpossible.com`.
5. The handler writes an `authstate:<nonce>` record to `OAUTH_KV` with a 600 s TTL and redirects to Google with `scope=openid email` and `prompt=select_account`.
6. Google returns to `GET /oauth/callback` (`src/google/callback.ts:11`). The state record is read and deleted at once (`:28,:32`), so it is single use.
7. The code is exchanged at Google (`src/google/exchange.ts:23`) and the ID token is verified (`src/google/verify.ts:26`): Google JWKS, RS256, `aud` equal to our Google client id, `iss` in the Google set (`:32`), and `email_verified === true` (`:41`).
8. **Authorization.** `checkStillAuthorized(env, stateJson.aud, verified.email)` (`src/google/callback.ts`) — the same one function the refresh grant and the EMA grant use, so a control added to the decision reaches all three paths. It returns three states, not a boolean. `denied` renders the forbidden page (`src/pages/forbidden.ts`), byte-identical whether the address was never listed or was explicitly revoked; `unavailable` renders a 503 page with `Retry-After: 5` (`src/pages/unavailable.ts`), because a corrupt or unreadable record is an outage, not a decision about that person. Both mint nothing. Refusals are logged as `evt: "google.callback"` with the reason and a hashed subject.
9. An `authcode:<code>` record is written with a 60 s TTL (`:75`) and the browser is redirected to the client with `code` and `state` (`:79-83`).
10. The client posts the code to `/token` (`src/oauth/token.ts`, `tokenHandler`). The handler authenticates the client, reads and deletes the code, checks the code belongs to that client and that `redirect_uri` matches, and verifies PKCE **when the code record carries a challenge**.
11. `mintAccessToken` runs with a 3600 s TTL. A refresh token is written when the request scope contained `offline_access`: a 30-day IDLE window, rewritten in full on every rotation. There is no absolute chain lifetime — see section 4. An ID token is minted when scope contained `openid`.

**What proves identity.** Google's signed ID token, verified against Google's JWKS.

**What authorizes access.** `allowlist:<aud>` in `ALLOWLIST_KV`, checked through `checkStillAuthorized` at `src/google/callback.ts`. The record is `{ emails: [...], denied?: [...] }`, and `denied` is evaluated first.

**The token.**

```json
{ "iss": "https://auth.techimpossible.com", "aud": "compliance-mcp",
  "sub": "<google subject>", "email": "peter.skaronis@techimpossible.com",
  "email_verified": true, "tenant_id": null, "roles": [],
  "iat": 1787000000, "exp": 1787003600 }
```

**How you revoke.** `DELETE /admin/allowlist/<aud>` with `{"email": "..."}` (`src/allowlist/admin.ts`). New logins stop at once, and so does every refresh: `handleRefreshGrant` re-runs the allowlist decision on every single use, from the `aud` and `email` the refresh record already carries. Live access tokens last out their remaining TTL. **Worst case: about 1 hour** — up to ~60 s of Workers KV propagation before the refresh grant sees the new list, plus at most 3600 s of already-minted access token. See section 4.

### b. `client_credentials`

**Who uses it.** Machine callers with no human: the Basecamp → Claude-in-Slack service client, the vendor-review Managed Agent Worker, the runner's session wrapper. No Google login, no tenant, no assertion.

**Flow.** `POST /token` with `grant_type=client_credentials` reaches `handleClientCredentialsGrant` (`src/oauth/token.ts:402`).

1. Credentials are read from HTTP Basic or the form (`src/oauth/client-auth.ts:5`).
2. `resolveClient` then `verifyClientSecret`. `verifyClientSecret` compares a SHA-256 hash in constant time across equal lengths (`src/oauth/clients.ts:81-93`).
3. The record must permit the grant and must carry `serviceEmail` and a non-empty `allowedAudiences`.
4. The audience comes from `resource` or `audience` and must be inside `allowedAudiences`. A single-audience client may omit it.
5. `mintAccessToken` runs with `sub` equal to the `client_id` and `email` equal to the admin-written `serviceEmail`. No refresh token is issued.

**What proves identity.** The `client_secret`. It is the whole security boundary. The record is created only through `POST /admin/service-clients` (`src/oauth/service-clients.ts:53`), which refuses `token_endpoint_auth_method: "none"` together with `client_credentials` (`:98-106`) and requires `service_email` and `allowed_audiences` for that grant (`:111,:125`).

**What authorizes access.** The client record itself: `allowedAudiences`. `ALLOWLIST_KV` is **not** consulted on this grant, by design — the comment above `handleClientCredentialsGrant` states that scoping lives entirely on the client record.

**The token.** Same shape as above, with `sub: "ti-XXXXXXXXXXXX"`, `email: "vendor-review-agent@techimpossible.com"`, `tenant_id: null`.

**How you revoke.** There is no admin endpoint for this today. You delete the `client:<client_id>` key from `OAUTH_KV` with wrangler, or you rotate the secret by creating a new client and retiring the old one. Live tokens last up to 1 h. Adding the service email to an allowlist does not help, because this grant never reads one.

### c. EMA `jwt-bearer` (RFC 7523)

**Who uses it.** An enterprise customer whose users sign in to their own identity provider. Anthropic's Claude client obtains an ID-JAG from the customer IdP and presents it here. It is an additional grant. It never replaces path (a).

**Flow.** `POST /token` with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` reaches `handleJwtBearerGrant` (`src/oauth/jwt-bearer.ts:168`). The step order is itself the control (`:151-166`).

1. **Size bound.** The assertion must be present and at most 8192 bytes (`:182-188`).
2. **Client authentication first.** `resolveClient` + `verifyClientSecret` (`:197-201`). The client must permit the grant (`:203`) **and** its `registrationSource` must be `admin` or `cimd` (`:209`). A DCR client from `/register` can never use this grant.
3. **Unverified header inspection only.** `alg` must be in the asymmetric allowlist (`:229`, list at `:58-67`), which kills `alg:none` and every HS\* variant. `jku`, `jwk` and `x5u` are refused (`:233`), so the assertion cannot choose its own key source.
4. **Tenant resolution — two KV reads, no network.** `normalizeIssuer(iss)` (`:241`, `src/tenants/model.ts:149`) then `loadTenantByIssuer` (`:248`, `src/tenants/store.ts:57`). An unknown or disabled issuer is rejected before any outbound fetch. `loadTenantByIssuer` also rejects a stale index entry whose tenant no longer lists that issuer (`src/tenants/store.ts:68`).
5. **Client is in the tenant.** `tenant.allowedClientIds` must contain the authenticated client (`:257`).
6. **Namespace binding must exist.** `emailDomains` must be a non-empty array, otherwise the request fails closed with `tenant_email_domains_missing` (`:265`). This is the fix for the headline bypass. A legacy record written without the field cannot authenticate.
7. **Media type.** `typ` must be `oauth-id-jag+jwt`, unless the tenant carries `allow_legacy_typ`, which permits only that value or a plain `JWT` (`:271-277`, list at `:44`). The old behaviour switched jose's `typ` check off completely.
8. **Signature and claims.** `jwtVerify` against the tenant's registered `jwks_uri` (`:283-300`): `audience: env.ISSUER`, the algorithm allowlist, `requiredClaims: [iss, sub, aud, exp, iat, jti, client_id]` (`:69`), 60 s clock tolerance, and `maxTokenAge` from `tenant.maxAssertionAgeSeconds` (300 s by default, `:26`).
9. **Post-checks jose does not do.** `normalizeIssuer(payload.iss)` must equal the registered issuer (`:317`). `payload.client_id` must equal the presented client (`:320`). `exp - iat` must be at most 3600 (`:328`). `sub` must be a bounded string (`:332`). Any `issuerClaimBindings` must match (`:337`).
10. **Identity.** The address is read from `tenant.subjectEmailClaim` or `email` (`:356-360`), then trimmed, lowercased and shape-checked (`:361-364`).
11. **CONTROL 1 — namespace binding.** `isEmailAllowed(email, tenant.emailDomains)` (`:366`). The tenant may assert only identities inside its own domains.
12. **Audience.** The IdP-signed `resource` claim outranks the client's RFC 8707 `resource` parameter; the parameter may agree, never widen (`:373-433`). Several parameters must all name one audience (`:391-404`). With no indicator at all, `defaultAudienceFor` picks the admin's choice (`:432`, `:545`). The audience must be inside `tenant.allowedAudiences` intersected with any client bound (`:436`, `:573`).
13. **CONTROL 2 — per-user authorization.** `checkStillAuthorized(env, aud, email)`. This is the same `ALLOWLIST_KV` decision the Google path and the refresh grant run, through the same function. A missing allowlist for the audience is a rejection, not a pass; a deny entry is a rejection logged as `email_denied`; a malformed record or a failed read is `503 temporarily_unavailable`, and the assertion is not consumed.
14. **Replay dampening.** `idjag:<tenant>:<sha256(jti)>` is read then written (`:454-461`), and only now, after every authorization decision, so a rejected request never burns a still-valid assertion.
15. **Mint.** `sub` is namespaced as `ema:<tenant>:<idp sub>` (`:478`). The TTL is clamped to the assertion's remaining life, between 60 s and 3600 s (`:480`). `email_verified: true` is **our** assertion, set by this server (`:482`), not relayed from the customer. `tenant_id` carries the tenant (`:481`).
16. **Response.** Access token only. No refresh token, no ID token. The `scope` member is the request intersected with `{openid, email, profile}` and with the IdP-signed `scope` claim (`:494`, `:557`).

Every failure from step 3 onward returns one byte-identical body, `400 invalid_grant / "assertion could not be validated"` (`:83-86`), so a client cannot enumerate trusted issuers or allowlists. The real reason goes to one structured log line, `evt: "ema.token"` (`:115-130`). Audience failures return `400 invalid_target` (`:95`). An unreachable customer IdP returns `503 temporarily_unavailable` with `Retry-After: 5` (`:514-522`).

**What proves identity.** The customer IdP's signature over an ID-JAG whose `aud` is our issuer, whose `iss` is bound 1:1 to one tenant, and whose `client_id` matches the authenticated client.

**What authorizes access.** Both controls: `tenant.emailDomains` and `allowlist:<aud>`.

**The token.**

```json
{ "iss": "https://auth.techimpossible.com", "aud": "compliance-mcp",
  "sub": "ema:acme:idp-subject-0001", "email": "cfo@acme.example",
  "email_verified": true, "tenant_id": "acme", "roles": [],
  "iat": 1787000000, "exp": 1787003600 }
```

**How you revoke.** One person: remove them from `allowlist:<aud>`. The whole tenant: `DELETE /admin/tenants/<id>`. Both are covered in section 4.

---

## 2. The two controls, and why both exist

They answer different questions. The code applies both to the EMA grant, in this order: `src/oauth/jwt-bearer.ts:366` then `:444`.

**`email_domains` — namespace binding.** Stored on the tenant record (`src/env.ts:92`). Required and non-empty at write time (`src/tenants/admin.ts:371-386`), each entry validated as `*@domain.example` or one full address by `isEmailScopePattern` (`src/tenants/model.ts:129`). At token time a record that lacks it fails closed (`src/oauth/jwt-bearer.ts:265`).

**`allowlist:<aud>` — per-user authorization.** Stored in `ALLOWLIST_KV` under `allowlist:<aud>` (`src/allowlist/check.ts:21`). Managed with `PUT/POST/DELETE /admin/allowlist/<aud>` (`src/allowlist/admin.ts:20,30,41`). No redeploy is needed.

**What only `email_domains` stops.** Tenant `acme` signs a perfectly valid assertion that says `email: peter.skaronis@techimpossible.com`. That address is on `allowlist:compliance-mcp`, because Peter is a real user of that audience. The allowlist alone would pass the request. `isEmailAllowed(email, tenant.emailDomains)` at `:366` rejects it with `email_not_in_tenant_domains`, because `*@acme.example` does not match. Without this control a customer tenant mints tokens that impersonate Techimpossible staff. This was the HIGH-severity bypass.

**What only `allowlist:<aud>` stops.** Acme's CFO leaves the company but their IdP account is still live for a day, or Acme has 500 staff and only 3 are paying users of `compliance-mcp`. `email_domains: ["*@acme.example"]` matches every one of the 500. A domain pattern cannot express "everyone at Acme except this one person", and it cannot express "only these three". The allowlist can. It is also the control Peter operates unilaterally: he does not need Acme's IdP admin, and he does not need a tenant edit or a deploy.

**Why the first pass was wrong.** It replaced the allowlist with `email_domains`. That deleted the unilateral revocation control the MCP-Auth runbook documents, and it left the namespace binding optional, which is what created the bypass. Both controls now apply. The doc records the same rule at `docs/enterprise-managed-auth.md:25-51`.

---

## 3. Onboarding a new enterprise client

All admin calls use `Authorization: Bearer $ADMIN_API_TOKEN` against `https://auth.techimpossible.com`.

**Step 1 — Peter: create the EMA client.**

```
POST /admin/service-clients
{
  "client_name": "acme-ema",
  "grant_types": ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
  "token_endpoint_auth_method": "client_secret_basic"
}
```

Handler: `src/oauth/service-clients.ts:53`. The response returns `client_id` and `client_secret` once (`:151-162`). Store the secret immediately; only its hash is kept. Prefer a confidential method. `"none"` is accepted for a jwt-bearer-only client, but then the assertion is the only credential. `"none"` with `client_credentials` is refused (`:98`). `service_email` and `allowed_audiences` are not required for a jwt-bearer-only client (`:111,:125`). The record is stamped `registrationSource: "admin"`, which the grant handler requires (`src/oauth/jwt-bearer.ts:209`).

**Step 2 — the customer's IdP admin: configure the identity provider.** They must:

- Publish `https://idp.acme.example/.well-known/openid-configuration` whose `issuer` member equals the registered issuer and whose `jwks_uri` is same-origin with it and underneath its path. If they publish no discovery document, they give Peter the `jwks_uri` explicitly.
- Sign the ID-JAG with RS256/RS384/RS512, PS256/PS384/PS512, ES256 or ES384 (`src/oauth/jwt-bearer.ts:58`).
- Stamp the header `typ: "oauth-id-jag+jwt"`.
- Include `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `client_id` (`:69`), plus an email claim.
- Set `aud` to `https://auth.techimpossible.com` exactly (`:294`).
- Set `client_id` to the `client_id` from step 1 (`:320`).
- Keep `exp - iat` at 3600 s or less (`:328`) and issue the assertion fresh, inside `max_assertion_age_seconds`.
- Give Peter the address claim name if it is not `email` (for example `upn` or `preferred_username`).

**Step 3 — Peter: create the tenant.**

```
PUT /admin/tenants/acme
{
  "display_name": "Acme Corp",
  "status": "active",
  "allowed_audiences": ["compliance-mcp"],
  "default_audience": "compliance-mcp",
  "allowed_client_ids": ["ti-XXXXXXXXXXXXXXXX"],
  "trusted_issuers": [ { "issuer": "https://idp.acme.example" } ],
  "email_domains": ["*@acme.example"],
  "max_assertion_age_seconds": 300
}
```

Handler: `src/tenants/admin.ts:302-474`. What it enforces: audiences must be supported (`:309`); `default_audience` must be one of them (`:319`); every `allowed_client_ids` entry must exist, permit the grant, and be `admin` or `cimd` provenance (`validateClientIds`, `:154-182`); `email_domains` is required and pattern-validated (`:371-386`); `max_assertion_age_seconds` must be an integer between 30 and 3600 (`:388`); each issuer is normalized, and when `jwks_uri` is omitted the discovery document is read and checked at write time (`resolveTrustedIssuer`, `:75-148`). An issuer already bound to another tenant returns `409 issuer_conflict` (`assertNoIssuerConflict`, `:190`, re-checked over the whole record inside `commitTenant`, `:248`).

Add `"jwks_uri": "https://idp.acme.example/keys"` inside the `trusted_issuers` entry when the customer publishes no discovery document.

To add a second IdP later, without replacing the record:

```
POST /admin/tenants/acme/issuers   { "issuer": "https://idp2.acme.example" }
```

Handler: `src/tenants/admin.ts:500`.

**Step 4 — Peter: authorize the people. Do not skip this.**

```
PUT  /admin/allowlist/compliance-mcp   { "emails": ["cfo@acme.example", "ciso@acme.example"] }
POST /admin/allowlist/compliance-mcp   { "email": "new.person@acme.example" }
```

Handlers: `src/allowlist/admin.ts`. `PUT` replaces the whole `emails` list, so read it first with `GET`; it PRESERVES any `denied` entries unless you send an explicit `"denied": []`. The tenant says which organisation may assert an identity. The allowlist says which people may reach the audience. An EMA request whose identity is not on the list is rejected with `email_not_allowlisted` (`src/oauth/jwt-bearer.ts:446`).

**Step 5 — what Anthropic needs.** Give them:

- Token endpoint: `https://auth.techimpossible.com/token`
- `grant_type`: `urn:ietf:params:oauth:grant-type:jwt-bearer`
- The `client_id` from step 1, and the `client_secret` if you chose a confidential method
- The resource indicator: `https://compliance-mcp.techimpossible.com`
- The assertion requirements from step 2
- The issuer identifier you registered, so the IdP `iss` matches byte for byte after normalization

**Step 6 — Peter: verify before you hand over.** Run one real exchange. On success you receive `access_token`, `token_type`, `expires_in` and possibly `scope`. On failure read the Worker log line `evt: "ema.token"` and map `reason_code` with the table at `docs/enterprise-managed-auth.md:239-264`. The response body is deliberately uniform, so the log is the only diagnosis.

---

## 4. Revoking access

**One user, EMA.**

```
DELETE /admin/allowlist/compliance-mcp   { "email": "leaver@acme.example" }
```

Time to effect: immediate for every new token request (`src/oauth/jwt-bearer.ts:444`). Access tokens already minted stay valid for their remaining TTL, at most 1 h, and the EMA TTL is further clamped to the assertion's own remaining life (`:480`). The EMA grant issues no refresh token, so there is no long tail. **Worst case: 1 hour.**

**One user, interactive Google path.** The same `DELETE` blocks every new login at `src/google/callback.ts:53`, **and** every refresh. `handleRefreshGrant` (`src/oauth/token.ts`) re-runs `checkStillAuthorized(env, record.aud, record.email)` on every use and refuses to mint when the identity is no longer on `allowlist:<aud>`. **Worst case: about 1 hour** — up to ~60 s of KV propagation plus the remaining life of one already-minted access token. No `refresh:<token>` key has to be hand-deleted with wrangler, and there is still no revocation endpoint to build, because the check runs at the grant rather than in a second manual step.

Three details worth knowing before you rely on it:

- **No denial consumes the refresh token.** The record stays in KV, powerless for as long as the identity is off the list. So an address removed by mistake and re-added resumes working with no re-authentication.
- **An `ALLOWLIST_KV` read failure, or a malformed record, returns `503 temporarily_unavailable` with `Retry-After: 5`, not `400`.** No token is minted either way — the check fails closed — but a transient KV problem or one corrupt value must not make a headless client throw a still-valid credential away and demand a human at a browser. `400 invalid_grant` reads as permanent to every OAuth client, so collapsing "could not decide" into "denied" would deprovision an entire audience until someone noticed.
- **Refresh chains have NO absolute lifetime.** A 90-day cap was written and then removed: it was never part of the revocation fix, and it scheduled an outage, because completing `/authorize` needs a human at a browser and Hermes cannot do that for itself. A chain in continuous use stays alive for as long as its identity stays authorized, and each rotation writes the full 30-day idle window again. What it bought — re-proof of the states `ALLOWLIST_KV` cannot see, such as a Google account suspended while the address is still listed — is available on demand by revoking the identity, which is effective within ~1 h with no client-side action. **There is no quarterly re-authentication to calendar.**

Every refresh decision emits one structured line, `evt: "refresh.token"`, with `decision`, `reason_code` (`ok`, `not_allowlisted`, `email_denied`, `allowlist_unavailable`, `record_incomplete`, `client_mismatch`, `record_unknown`), `aud`, `client_id` and a hashed subject — never the email, never the token. Before this change the grant logged nothing at all, so "did that revocation take effect?" was unanswerable.

### Revoking one identity (the runbook)

`DELETE /admin/allowlist/<aud>` is the whole operation, and it now tells you what actually happened instead of returning `200` unconditionally.

```
DELETE /admin/allowlist/compliance-mcp   { "email": "bob@acme.example" }
```

```json
{ "outcome": "removed_and_denied", "changed": true,
  "removed": ["bob@acme.example"], "denied_added": ["bob@acme.example"],
  "covering_patterns": ["*@acme.example"],
  "decision_after": { "status": "denied", "reason": "deny_entry", "matched_by": "bob@acme.example" },
  "propagation": "Existing access tokens stay valid until they expire (max 3600s)." }
```

**Why a deny list exists.** The record is `{ emails: [...], denied?: [...] }`, and `denied` is evaluated BEFORE `emails`. On an audience scoped as `["*@acme.example"]` — the shape README's own seed command writes — removing an entry from `emails` cannot express "revoke Bob": there is no entry to remove. The only alternative was deleting the wildcard, which deprovisions the whole customer. That is an outage, not a revocation. `denied` is absent from every record until you revoke someone, so nothing on disk changes shape until then. `outcome` is `removed` when only literal entries had to go, `denied` when only a deny entry was needed, `removed_and_denied` when both.

**Matching is normalized.** DELETE compares through the same `normalizeIdentity` the decision path uses, so `"Peter@Techimpossible.com "` now removes a stored `peter@techimpossible.com`. It used to compare raw strings, return `200` and remove nothing.

**The refusals, and what each means.** Any script that ignored the status code was already silently broken; these make that visible.

| Status | `error` | What happened |
|---|---|---|
| 404 | `unknown_audience` | The audience is not one this server mints for (`compliance-mcp`, `basecamp-mcp`, `finance-mcp`). Almost always a typo. Nothing written. |
| 404 | `allowlist_not_found` | No record for that audience at all, so nothing authorizes the address. No record is created. |
| 404 | `not_allowlisted` | The record exists, but nothing in it covers the address and no deny entry does either. Check the spelling. Nothing written. |
| 409 | `wildcard_removal_requires_confirmation` | You sent `*@domain`. That revokes an entire customer, so it needs `{"confirm_wildcard_removal": true}`. |
| 409 | `covered_by_wildcard` | Only with `"mode": "remove_only"`, which forbids creating a deny entry. Nothing written. |
| 503 | `temporarily_unavailable` | The record is corrupt or KV failed. **The revocation did NOT happen.** `GET` the record to inspect it. |
| 200 | — `outcome: "already_revoked"` | A deny entry already covered the address. `changed: false`, so retries are idempotent. |

**Re-instating.** The deny list is a first-class sub-resource, so putting someone back does not mean re-typing the whole `emails` array:

```
GET    /admin/allowlist/compliance-mcp/denied
POST   /admin/allowlist/compliance-mcp/denied   { "email": "*@sub.acme.example" }
DELETE /admin/allowlist/compliance-mcp/denied   { "email": "bob@acme.example" }
```

`POST` here is the only route that will write a `*@domain` deny entry. `DELETE` re-instates and reports `decision_after`, which says plainly whether the person is authorized again or still has no allow pattern covering them.

**Two mirrors of the same defect, also closed.** `PUT` with no `denied` member preserves the existing deny list (`denied_preserved: true` in the response) — under full-replace semantics the documented seeding command would have been a silent mass un-revocation. And `POST /admin/allowlist/<aud>` returns `409 denied_entry_conflict` when a deny entry covers the address, instead of reporting success for a grant that would not have taken effect.

**What this does not reach.** `client_credentials` service clients never read the allowlist — their identity comes from the client record — so every revocation response carries `not_effective_for` saying so. Revoke those by rotating the client secret.

**One service client.** No admin endpoint exists. Delete the `client:<client_id>` key from `OAUTH_KV`, or create a replacement client and retire the old one. Time to effect after the key is gone: immediate for new tokens, 1 h for live ones.

**A whole tenant.**

```
DELETE /admin/tenants/acme
```

Handler: `adminTenantHandler`'s `DELETE` branch. It is non-destructive: `status` becomes `"disabled"`, every reverse-index entry this tenant still owns is removed (`unbindOwnedIssuer`), the cached JWKS is dropped, and the record is kept for audit. New assertions then fail at `src/oauth/jwt-bearer.ts:248` with `issuer_not_trusted`, because `loadTenantByIssuer` finds no index entry, and would also refuse the record for `status !== "active"` (`src/tenants/store.ts:66`). Time to effect: **immediate for new assertions, at most 1 hour for live tokens.**

To pause a tenant without unbinding its issuers, `PUT` the same record with `"status": "disabled"` instead.

**Why 1 hour is the floor.** Resource servers verify our tokens offline against our JWKS. Nothing calls back to this server per request. The access token TTL is therefore the revocation latency, and it is 3600 s (`src/oauth/token.ts:14`, `src/oauth/jwt-bearer.ts:22`).

---

## 5. What still needs a human

**Nothing was deployed. Nothing was committed. Nothing was pushed. No production KV was read or written.** The changes live only in the working tree at `/home/claude/auth-techimpossible`. `git status` shows 11 modified files and the new `src/tenants/`, `src/oauth/jwt-bearer.ts`, `src/oauth/cimd.ts`, `src/lib/*`, `docs/` and `tests/*` as untracked. `README.md` shows pre-existing uncommitted changes that I did not touch.

**What I ran here, read-only:**

- `npm test` → 246 tests in 15 files, all pass.
- `npm run typecheck` → clean.

**Required human steps before this ships:**

0. **BLOCKING, before the first deploy of the redirect-destination rule: inventory the live clients.** List the `client:` keys in the production `OAUTH_KV` namespace and read the `redirectUris` of every record. Any LEGITIMATE client whose redirect is neither loopback nor one of the built-in hosts (`claude.ai`, `claude.com`) must have its host appended to `DCR_REDIRECT_HOSTS` in `wrangler.toml` FIRST, or that integration fails at its next full interactive authorization. Existing access and refresh tokens keep working either way, so the failure is deferred rather than immediate — which is exactly why it is easy to miss. Derive the list from that inventory; do not guess it. Hermes's own client is the one to check first. This is a read of production KV and an operator decision; it was not performed as part of the change.

1. **Review the full diff.** Roughly 290 changed lines across tracked files, plus about 1900 new source lines and 4200 new test lines. Read `src/oauth/jwt-bearer.ts` in full: it is the new trust boundary.
2. **Run the tests yourself** and re-run the typecheck.
3. **Run the push gate.** Stage 1 gitleaks, Stage 2 `claude-secgate`, Stage 3 advisory `devin-gate`. The secgate ledger must be dispositioned, not left unread.
4. **Deploy**, with the practice-repo and route caveats in `wrangler.toml` in mind. Deploy is yours to run, not mine.
5. **Set `ADMIN_API_TOKEN`** if it is not already a live secret, and confirm the guard fails closed in the deployed environment.
6. **No quarterly re-authentication to calendar — this operator burden was removed.** An earlier pass added a 90-day absolute refresh-chain lifetime, which would have required one human-at-a-browser `/authorize` run per quarter for Hermes. It is gone: age alone no longer invalidates a chain. Nothing to schedule, nothing to remember.
7. **Check the three live allowlist records before you deploy, not when you next need to revoke someone.** `GET /admin/allowlist/{compliance-mcp,basecamp-mcp,finance-mcp}` and confirm none comes back `malformed: true`. Under the new rules a corrupt record makes both the grants and `DELETE` return 503 rather than a misleading answer — correct, but you want to know which records are healthy in advance.
8. **Update `~/ObsidianVault/Knowledge/MCP-Auth-Runbook.md`.** Its "revoke one named user, effective within ~1h" claim is now true on every grant, including on a domain-scoped audience, which it was not before. Add the deny-list flow and the refusal codes from section 4. `README.md` is deliberately untouched by this change, so its "Allowlist KV data model" section still describes only `emails` and does not mention that `PUT` preserves `denied` — that documentation debt is Peter's call.

**Three original findings remain open and need an explicit disposition, not a silent close:**

- **F4 — the assertion is a bearer credential, and the `jti` guard is not atomic.** `src/oauth/jwt-bearer.ts:454-461` is a KV read followed by a KV write. Two colos can both pass. `verifyClientSecret` returns true for a `"none"` client with no secret (`src/oauth/clients.ts:85`), so a public EMA client is redeemable by anyone holding a captured assertion for its `maxAssertionAge` window. Mitigations are in force and documented at `docs/enterprise-managed-auth.md:266-279`. Disposition: accept, with `client_secret_basic` as the onboarding default, or move the `jti` guard to a Durable Object.
- **F14 — a subject-only ID-JAG is always rejected** (`src/oauth/jwt-bearer.ts:356-364`, reason `identity_claim_missing`). This is your binding decision, because both controls key on an address. `subject_email_claim` covers IdPs that carry the address elsewhere. An IdP that emits no address at all cannot be onboarded. Disposition: accept as a documented limit (`docs/enterprise-managed-auth.md:281-286`).
- **F18 — `temporarily_unavailable` is not in the RFC 6749 §5.2 token-endpoint registry** (`src/oauth/jwt-bearer.ts:514`). `invalid_target` is now 400 as asked. Practical harm is low. Note that `client_credentials` still returns `403 invalid_target` in `handleClientCredentialsGrant`, which is now inconsistent with the EMA grant's 400. Disposition: accept, or align both.

**The re-verify pass found pre-existing defects outside the EMA code that you should decide on before you onboard a customer.** They are not regressions from this work, but they sit on the paths this work was meant to protect:

- **FIXED (was HIGH) — one phishing click on `/authorize` mints a staff token to an attacker's client.** Closed structurally: an unvetted client may now only nominate a destination the registrant cannot read — loopback, or an operator-vetted https host — enforced at BOTH `/register` and `/authorize` (`src/oauth/redirect-policy.ts`). `/register` stays open, because Claude.ai performs DCR at connect time and gating it would mean no connector could ever be added. Accepted residual risks, recorded rather than dropped: an open redirect or attacker-controlled path ON an allowlisted host (host granularity is deliberate — pinning a vendor's callback path would break on any change they make); a local process on the victim's own machine racing the loopback callback port (the MEDIUM below, unchanged); an attacker starting a connector-add in Claude.ai and phishing the victim to finish it, where the token lands in the victim's own Claude.ai session — an unwanted connector, not a stolen token; and the continued absence of a consent screen, which was rejected as the primary control because `client_name` is attacker-supplied at registration and would have read "Techimpossible Compliance MCP" on a page Techimpossible itself rendered.
- **FIXED (was HIGH/MEDIUM) — `refresh_token` never re-reads the allowlist.** It does now, on every use, described in section 4. The documented "revocation effective within ~1 h" is true for interactive identities for the first time.
- **FIXED (was HIGH) — the 90-day refresh-chain cap was unrequested scope that guaranteed an outage.** Removed entirely, with the `chainStartedAt` plumbing and the quarterly operator note. See section 4.
- **FIXED (was HIGH) — `DELETE /admin/allowlist/<aud>` returned 200 for revocations that did nothing.** Exact-string matching against a list read with normalization and wildcards; no way at all to revoke one person from a domain-scoped audience. Both closed, with a `denied` list and a verified `decision_after` on every mutating response. Section 4.
- **FIXED (was MEDIUM) — an IPv6 loopback redirect could no longer register.** `isLoopbackRedirect` compared `u.hostname` to `"::1"`, but the WHATWG URL parser returns `"[::1]"`, so no IPv6 loopback ever matched — and the predicate gates `/register`. Both spellings are accepted (`src/oauth/redirect-policy.ts`).
- **FIXED (was MEDIUM) — a corrupt allowlist record permanently deprovisioned an audience.** `checkStillAuthorized` collapsed "malformed" into "denied", so one bad KV value returned `400 invalid_grant` — permanent to every OAuth client. A malformed record is now `unavailable`: 503 on the token endpoints, a 503 page on the interactive path, and 503 on the admin routes that would otherwise write over the evidence.
- **MEDIUM — for a public client an authorization code is a pure bearer credential.** `/authorize` never requires a `code_challenge`, and `/token` enforces PKCE only when the code record carries one. Combined with loopback-port-agnostic redirect matching (`src/oauth/authorize.ts:23`), a local process that wins the callback port can redeem the code.
- **PARTLY ADDRESSED — the `jwks_uri` binding.** The old rule required the JWKS to live *underneath* the issuer's path, which is factually wrong for Microsoft Entra v2.0 (its keys sit beside the issuer path, under the same tenant GUID) and made every Entra tenant unregisterable through both branches. It is now a tiered decision — `classifyJwksBinding` in `src/tenants/model.ts` — and the loosest tier is bounded by host exclusivity in `src/tenants/admin.ts`. Accepted residual: on the sibling tier, an IdP that serves a discovery document at the issuer's OWN path naming another tenant's JWKS is honoured; the attacker must control both, which is strictly more than either rule alone demanded. See `docs/enterprise-managed-auth.md`.
- **MEDIUM — `email_domains` has no cross-tenant uniqueness and no reserved-domain guard** (in the `PUT` validation). Issuers are 1:1 (`assertNoIssuerConflict`), but two tenants may both claim `*@acme.example`, and `PUT` accepts `*@techimpossible.com` on a customer record. One wrong entry on one customer record is enough for that customer to mint staff identities. A reserved-domain deny list is the cheap fix.
- **LOW — `normalizeIssuer` is not idempotent**: it strips exactly one trailing slash, so `https://idp.example//` yields a second index key and defeats the 1:1 issuer invariant. It fails closed at token time, so the record is unusable rather than exploitable, but the guarantee is broken.
- **LOW — `client_credentials` does not re-check the auth method at the grant handler.** `src/oauth/service-clients.ts:98` refuses the `"none"` + `client_credentials` combination at creation, but `handleClientCredentialsGrant` would still mint for such a record if one reached KV by another route. The rule belongs at the grant handler too.
- **LOW, spec — three conformance gaps.** The EMA response omits `scope` when the granted set is empty (`src/oauth/jwt-bearer.ts:503`), which RFC 6749 §5.1 reads as "identical to the requested scope". The `resource` parameter is not validated as an absolute URI (`:385`, `:593`). `401 invalid_client` carries no `WWW-Authenticate` header (`:198`, `src/lib/errors.ts:14`), and token responses omit `Pragma: no-cache` (`src/lib/errors.ts:18`).

**Files changed or added in this pass:** `src/env.ts`, `src/index.ts`, `src/lib/jwt.ts`, `src/lib/admin-auth.ts`, `src/lib/safe-fetch.ts`, `src/lib/tenant-jwks.ts`, `src/allowlist/admin.ts`, `src/oauth/authorize.ts`, `src/oauth/audiences.ts`, `src/oauth/cimd.ts`, `src/oauth/client-auth.ts`, `src/oauth/clients.ts`, `src/oauth/discovery.ts`, `src/oauth/grants.ts`, `src/oauth/jwt-bearer.ts`, `src/oauth/service-clients.ts`, `src/oauth/token.ts`, `src/tenants/admin.ts`, `src/tenants/model.ts`, `src/tenants/store.ts`, `wrangler.toml`, `docs/enterprise-managed-auth.md`, and the test files under `/home/claude/auth-techimpossible/tests/`.