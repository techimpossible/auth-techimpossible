# Enterprise Managed Auth (EMA)

`auth.techimpossible.com` accepts an RFC 7523 JWT bearer assertion — an ID-JAG
signed by a **customer's own identity provider** — and exchanges it for a
standard Techimpossible RS256 access token for `compliance-mcp`,
`basecamp-mcp` or `finance-mcp`.

    POST /token
    Content-Type: application/x-www-form-urlencoded

    grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
    &assertion=<JWT signed by the customer IdP>
    &client_id=ti-...
    &scope=...
    &resource=https://compliance-mcp.techimpossible.com   (optional)

The response is an access token only. There is **no refresh token and no ID
token**: the customer's IdP holds the long-lived credential, so minting one here
would create a credential that outlives IdP-side revocation.

EMA is an **additional** grant. It never replaces the interactive Google path
(`/authorize` → Google → `/oauth/callback`), which remains the route for Hermes
and for every client whose users do not have a supported enterprise IdP.

## The three controls, and what each one is for

| Control | Where | Answers |
|---|---|---|
| Trusted-issuer index | `TENANT_KV`, 1:1 issuer → tenant | *Which tenant is this assertion from?* |
| `email_domains` on the tenant | `TENANT_KV`, **required, non-empty** | *May this tenant assert this identity?* (namespace binding) |
| `allowlist:<aud>` | `ALLOWLIST_KV` | *May this person reach this audience?* (per-user authorization) |

**All three apply to every EMA token.** They are not alternatives:

- An assertion's `iss` is looked up in the reverse index *before* the signature
  is checked and before any network request is made. An issuer no tenant has
  registered is rejected no matter how valid its signature is. Because the index
  is 1:1 and enforced with a 409 at write time — over **every** issuer on the
  record, on every write path — there is no mapping by which tenant A's issuer
  resolves to tenant B.
- `email_domains` proves the tenant is asserting an identity inside its own
  domain. Without it a customer IdP could sign
  `email: peter.skaronis@techimpossible.com` and mint a token that impersonates
  Techimpossible staff. It is mandatory at write time, and a record that somehow
  lacks it (written before the field became mandatory) **fails closed** at token
  time rather than being read as "no scoping in effect".
- `allowlist:<aud>` is the control an operator revokes unilaterally, effective
  within the access token TTL (≤ 1 h) with no client-side action. It is also the
  only control that can express *"everyone at Acme except this one person"* — a
  domain pattern cannot. It is the same check the interactive Google path runs
  at `src/google/callback.ts`, and all three grants now reach it through one
  function, `checkStillAuthorized`.

  The record is `{ emails: [...], denied?: [...] }`. `denied` is evaluated
  BEFORE `emails`, which is what makes that "except this one person" claim true
  on an audience scoped as `["*@acme.example"]` — there, removing an entry from
  `emails` cannot express it, and deleting the wildcard would deprovision the
  whole customer. A record whose `denied` value is present but is not an array
  of strings is treated as MALFORMED, and every grant for the audience then
  returns `503 temporarily_unavailable` rather than a decision: reading it as
  "no denies" would silently un-revoke someone.

## Onboarding a tenant

Everything below is admin-gated with `Authorization: Bearer $ADMIN_API_TOKEN`.

### 1. Create the client

Either register the credentials Anthropic holds, or mint one:

    POST /admin/service-clients
    {
      "client_name": "acme-ema",
      "grant_types": ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
      "token_endpoint_auth_method": "client_secret_basic"
    }

Prefer a confidential auth method wherever the client can hold a secret: it adds
a second factor on top of the assertion. `"none"` is accepted **only** for a
jwt-bearer-only client, where the signed, audience-bound, short-lived assertion
is itself the client credential (RFC 7523 §3.1).

`"none"` together with `client_credentials` is **refused**. For that grant the
secret is the entire security boundary, and the `client_id` is not a secret — it
is the `sub` claim of every token that client mints, so a public
`client_credentials` client can be driven by anyone who has seen one of its
tokens. `service_email` and `allowed_audiences` are required for
`client_credentials` and are not required for a jwt-bearer-only client, which
takes its identity from the assertion and its audiences from the tenant record.

Clients minted here are stamped `registrationSource: "admin"`. **A DCR client
(`POST /register`) can never be an EMA client**: `/register` is unauthenticated
and echoes back whatever `grant_types` the caller asks for, so the grant handler
rejects any client whose provenance is not `admin` or `cimd`.

### 2. Create the tenant

    PUT /admin/tenants/acme
    {
      "display_name": "Acme Corp",
      "status": "active",
      "allowed_audiences": ["compliance-mcp"],
      "default_audience": "compliance-mcp",
      "allowed_client_ids": ["ti-XXXXXXXXXXXXXXXX"],
      "trusted_issuers": [
        { "issuer": "https://idp.acme.example" }
      ],
      "email_domains": ["*@acme.example"],
      "max_assertion_age_seconds": 300
    }

`email_domains` is **required and non-empty**. Each entry is either
`"*@domain.example"` or one full address, and is validated at write time so a
typo cannot be stored as a pattern that silently matches nothing.

`default_audience` decides which audience a request with no RFC 8707 resource
indicator receives; it must be one of `allowed_audiences`, and defaults to the
first entry. Some IdP configurations cannot forward a resource indicator at all,
and the request is served either way.

#### Binding `jwks_uri` to the issuer

The control exists to stop one thing: on a shared multi-tenant IdP host, tenant A
nominating tenant B's key endpoint as A's key source, after which key material
from B's trust domain decides what is accepted as A. On such hosts the customer
discriminator is a **path segment**, so the real invariant is "the same
trust-domain segment". "Underneath the issuer's path" was only ever a special
case of that, and stating it as the general rule was factually wrong — see the
Entra row below.

`jwks_uri` must always be https, on a public host, port 443, and **same-origin
with the issuer**. Cross-origin is refused absolutely. Beyond that,
`classifyJwksBinding` (`src/tenants/model.ts`) decides one of four tiers by
comparing PATH SEGMENT ARRAYS, byte-exact:

| Tier | When | What is required |
|---|---|---|
| `subtree` | the JWKS path starts with the issuer's full segment list | Accepted, **no network call**. It is inside the issuer's own namespace by construction. |
| `sibling` | only the FIRST segment matches — the tenant discriminator on a shared host | Accepted **only if** `<issuer>/.well-known/openid-configuration` echoes the issuer (RFC 8414 §3.3) and names that exact `jwks_uri`. One fetch. |
| `origin-only` | the issuer carries no path at all, so it owns the whole host | Accepted, no network call. Bounded by host exclusivity, below. |
| `reject` | the first segments differ | Refused before any fetch. This is the cross-tenant attack. |

Segment-array comparison, rather than a string prefix, is what makes
`/customer-a` and `/customer-abc` different structurally rather than by
appending a separator; a percent-encoded separator never splits, so it fails
closed.

If `jwks_uri` is omitted, `<issuer>/.well-known/openid-configuration` is read at
write time, its `issuer` member must equal the registered issuer, and its
`jwks_uri` gets the same tiering — but no second fetch, because that document is
itself the confirmation the `sibling` tier asks for. **This is the recommended
way to onboard Entra:** the URL then comes from Microsoft rather than from a
human paste. Supply `jwks_uri` explicitly for an IdP that publishes no discovery
document.

#### Supported issuer shapes

| IdP | issuer | jwks_uri | Tier |
|---|---|---|---|
| Microsoft Entra v2.0 | `https://login.microsoftonline.com/<tenant-guid>/v2.0` | `https://login.microsoftonline.com/<tenant-guid>/discovery/v2.0/keys` | `sibling` — the keys sit BESIDE the issuer path, under the same tenant GUID |
| Okta org server | `https://acme.okta.com` | `https://acme.okta.com/oauth2/v1/keys` | `origin-only` |
| Okta custom authorization server | `https://acme.okta.com/oauth2/ausAbC123` | `https://acme.okta.com/oauth2/ausAbC123/v1/keys` | `subtree` |
| Auth0 | `https://acme.eu.auth0.com` | `https://acme.eu.auth0.com/.well-known/jwks.json` | `origin-only` |
| Keycloak realm | `https://sso.acme.example/realms/acme` | `https://sso.acme.example/realms/acme/protocol/openid-connect/certs` | `subtree` |
| PingOne | `https://auth.pingone.com/<envId>/as` | `https://auth.pingone.com/<envId>/as/jwks` | `subtree` |

Two deliberate exclusions. **Entra v1.0** (`https://sts.windows.net/<guid>`) is
unsupported: its JWKS lives on `login.microsoftonline.com`, which is
cross-origin, and cross-origin is the one thing this control exists to forbid.
Register the v2.0 endpoint. **Google** is likewise cross-origin
(`accounts.google.com` → `www.googleapis.com`) and does not need EMA at all:
Google identities reach this server through the interactive federation path in
`src/google`.

Add or remove one issuer without replacing the record:

    POST   /admin/tenants/acme/issuers   { "issuer": "https://idp2.acme.example" }
    DELETE /admin/tenants/acme/issuers   { "issuer": "https://idp2.acme.example" }

### 3. Authorize the people (do not skip this)

The tenant record says which *organisation* may assert an identity. It does not
say which *people* may use an audience. Add them to the audience allowlist, the
same one the interactive flow uses:

    PUT /admin/allowlist/compliance-mcp   { "emails": ["*@acme.example", "peter.skaronis@techimpossible.com"] }
    POST /admin/allowlist/compliance-mcp  { "email": "new.person@acme.example" }

`PUT` replaces `emails` and PRESERVES `denied` unless you send an explicit
`"denied": []`. `POST` returns `409 denied_entry_conflict` when a deny entry
covers the address, rather than reporting success for a grant that would have
had no effect.

An EMA request whose resolved identity is not on `allowlist:<aud>` — including
the case where the audience has no allowlist at all — is rejected with the
uniform `invalid_grant` body and `reason_code email_not_allowlisted`.

### 4. Revoking

Per person, effective within the token TTL, no tenant change:

    DELETE /admin/allowlist/compliance-mcp   { "email": "leaver@acme.example" }

This works on a domain-scoped audience: when `*@acme.example` still covers the
address, the same call adds a deny entry in the same write and reports
`outcome: "removed_and_denied"` (or `"denied"` when there was no literal entry
to remove) with a `decision_after` verdict computed from the record it actually
wrote. It returns `404` for an unknown audience or an address nothing covers,
`409` when you send a `*@domain` pattern without
`{"confirm_wildcard_removal": true}`, and `503` when the record is corrupt —
never a `200` for a revocation that did not happen. Re-instate with
`DELETE /admin/allowlist/compliance-mcp/denied { "email": "..." }`. Full runbook:
`docs/auth-flows.md` section 4.

The whole tenant:

    DELETE /admin/tenants/acme

This is **non-destructive**: the tenant is set to `status: "disabled"` and every
reverse-index entry is removed, but the record is kept for audit. New assertions
are rejected immediately. Access tokens already issued remain valid for the rest
of their TTL, which is at most one hour and is clamped to the assertion's own
remaining lifetime.

## Validation order (and why it is that order)

| # | Step | Why here |
|---|------|----------|
| 1 | `assertion` present, <= 8 KB | The only body bound in the Worker; precedes all parsing |
| 2 | Client authenticated (`resolveClient` + `verifyClientSecret`) | An unauthenticated caller must never be able to probe `TENANT_KV` |
| 3 | Client permits the grant AND `registrationSource` is `admin`/`cimd` | DCR is caller-controlled; grant_types alone is never sufficient |
| 4 | Unverified header: `alg` in the allowlist, no `jku`/`jwk`/`x5u` | Kills `alg:none` and HS* before any key resolution |
| 5 | `iss` normalized, looked up in the tenant reverse index | **Control 1.** Two KV reads, zero outbound requests |
| 6 | `client_id` in `tenant.allowedClientIds`; tenant has `email_domains` | Admin-written fields are the authorization gate; a record with no namespace binding fails closed |
| 7 | `typ` is the ID-JAG media type (or, per tenant, a plain/absent `JWT` typ) | An IdP access token or logout token is not an authorization grant |
| 8 | `jwtVerify` against the tenant's registered `jwks_uri` | First and only outbound fetch, to an admin-vetted URL |
| 9 | `normalizeIssuer(payload.iss) === registered issuer` | The iss binding, on the VERIFIED payload, normalized on both sides |
| 10 | `payload.client_id === client_id`, `exp - iat <= 3600`, `sub`, claim bindings | Checks jose does not perform |
| 11 | Identity claim present, well formed, inside `email_domains` | **Control 2**, the namespace binding |
| 12 | Audience: assertion `resource` **claim** outranks the `resource` param | The claim is IdP-signed policy; the param may agree, never widen |
| 13 | Audience within `tenant.allowed_audiences` ∩ the client's own bound | |
| 14 | Identity on `allowlist:<aud>`, deny entries first | **Control 3**, per-user authorization for the audience actually requested |
| 15 | `jti` not seen before (hashed, per tenant), then marked | Replay dampening — **after** every authorization decision, so a rejected request never burns a still-valid assertion |
| 16 | Mint with `sub = ema:<tenant>:<sub>`, TTL clamped to the assertion | Namespacing stops subject collisions with Google subjects |

`jwtVerify` is pinned to `algorithms`, `audience: env.ISSUER`,
`requiredClaims: [iss, sub, aud, exp, iat, jti, client_id]`,
`typ: "oauth-id-jag+jwt"` (relaxable per tenant with `allow_legacy_typ`),
`clockTolerance: 60` and `maxTokenAge`.

`audience: env.ISSUER` is the second cross-tenant control: per the ID-JAG draft
`aud` is the resource authorization server's issuer identifier, so an assertion
minted for a different relying party cannot be replayed here.

The `iss` binding is enforced at step 9 rather than through jose's `issuer`
option, because that option compares byte-exact against the raw claim while the
index lookup compares the normalized form. An IdP whose issuer identifier ends
in `/` (Auth0's default) would otherwise register successfully and then fail
every exchange forever. Both sides now go through `normalizeIssuer`. **Do not
"simplify" this by dropping step 9** — it is the whole binding.

## Claims in the minted token

    { "iss": "https://auth.techimpossible.com",
      "aud": "compliance-mcp",
      "sub": "ema:acme:<idp subject>",
      "email": "person@acme.example",     // normalized: trimmed, lowercased
      "email_verified": true,
      "tenant_id": "acme",
      "roles": [], "iat": ..., "exp": ... }

`email_verified` is **this server's** assertion, not the customer's. The ID-JAG
draft does not define the claim, and relaying it would let the party being vetted
set a trust signal that resource servers gate on. We emit `true` because we
verified the address ourselves: signed by an issuer an admin bound to this
tenant, inside `email_domains`, and present on `allowlist:<aud>`.

The response `scope` is the requested scope intersected with what this server
grants and with the assertion's own IdP-signed `scope` claim, never the raw
request parameter. `offline_access` is never granted here: no refresh token is
ever minted.

## Error surface

Every assertion-validation failure from step 4 onwards returns the byte-identical
body:

    HTTP 400
    {"error":"invalid_grant","error_description":"assertion could not be validated"}

This is deliberate: a differentiated error would let an authenticated client
enumerate which issuers are trusted, which tenants a client belongs to, and who
is on an allowlist. The real reason is in the structured log line instead.

Exceptions: steps 2 and 3 keep `401 invalid_client` / `400 unauthorized_client`
(the caller is not yet authenticated, or is authenticated and simply not
enrolled), audience failures return **`400 invalid_target`** (RFC 6749 §5.2:
token endpoint errors are 400 unless a spec says otherwise, and RFC 8707 does
not), and a customer IdP that is unreachable returns **`503
temporarily_unavailable`** with `Retry-After`, so Claude retries instead of
treating a network blip as a permanent authentication failure.

### Diagnosing a failure

One JSON line per decision reaches the Worker log:

    {"evt":"ema.token","decision":"deny","reason_code":"issuer_not_trusted",
     "tenant_id":null,"issuer":"https://idp.acme.example","client_id":"ti-...",
     "aud":null,"sub_hash":null,"jti_hash":null,"kid":"..."}

| `reason_code` | Operator action |
|---|---|
| `assertion_too_large` | Client bug: the assertion exceeds 8 KB |
| `assertion_malformed` | Not a JWS compact serialization |
| `alg_not_allowed` | IdP is signing with an unsupported (or symmetric) algorithm |
| `header_key_injection` | Assertion carried `jku`/`jwk`/`x5u` — treat as an attack |
| `iss_missing` / `iss_not_normalizable` | IdP issuer is not a plain https URL |
| `issuer_not_trusted` | The issuer is not registered for any active tenant. Check `GET /admin/tenants/<id>` |
| `client_not_in_tenant` | Add the client_id to `allowed_client_ids` |
| `tenant_email_domains_missing` | Legacy record with no namespace binding. Re-PUT the tenant with `email_domains` |
| `typ_not_allowed` | The IdP is not stamping `oauth-id-jag+jwt`. Fix the IdP, or set `allow_legacy_typ` after confirming what else it signs for our `aud` |
| `assertion_verification_failed` | Signature, `aud`, `exp`, or `maxTokenAge` failure |
| `iss_mismatch` | `iss` does not normalize to the registered issuer |
| `idp_unreachable` | Customer JWKS endpoint down or slow (>3 s). Returns 503 |
| `client_id_mismatch` | Assertion's `client_id` claim differs from the presented client_id |
| `assertion_lifetime_too_long` | IdP is issuing assertions longer than one hour |
| `identity_claim_missing` | The IdP sends no email claim. Set `subject_email_claim` to the claim that carries the address (`upn`, `preferred_username`, …) |
| `identity_claim_malformed` | The claim is not a single well-formed address |
| `email_not_in_tenant_domains` | Address is outside the tenant's `email_domains` — a tenant asserting an identity it does not own |
| `email_not_allowlisted` | The person is not on `allowlist:<aud>` (or the audience has no allowlist). See onboarding step 3 |
| `email_denied` | The person IS covered by an allow pattern but a `denied` entry revokes them. The response body is identical to `email_not_allowlisted`; only this log line separates them |
| `allowlist_unavailable` | `ALLOWLIST_KV` could not be read, or the record is malformed. Returns 503, and the assertion is NOT consumed |
| `assertion_replayed` | The same `jti` was already exchanged |
| `resource_unknown` / `resource_claim_unknown` | The resource indicator does not name a resource server we mint for |
| `resource_indicators_conflict` | Several `resource` parameters named different resource servers |
| `resource_param_conflicts_with_claim` | Client asked for an audience the IdP did not authorize |
| `audience_not_permitted` | Audience is outside `tenant.allowed_audiences` (or the client's) |
| `mint_failed` | Our signing path failed. Returns 503; check the signing key in `OAUTH_KV` |

## Documented limits

- **The assertion is a bearer credential.** RFC 7523 §3.1 allows exactly that,
  and it is what makes a public EMA client possible. An assertion that leaks
  (proxy log, crash dump, client bug) is redeemable by anyone holding it, as
  that client, until it expires or its `jti` is consumed. Mitigations in force:
  `maxAssertionAgeSeconds` (300 s by default — lower it for a tenant that can),
  the `client_id` binding, `aud` pinned to our issuer, and `jti` dampening. Use a
  confidential auth method for the EMA client wherever the client can hold a
  secret.
- **Replay protection is dampening, not strict single use.** The `jti` record
  lives in eventually-consistent KV, so a request racing itself across colos can
  slip through. If strict single use is ever required, the correct primitive is
  a Durable Object keyed on `<tenant>:<jti hash>`.
- **An identity claim is required, even though the ID-JAG draft marks `email`
  OPTIONAL.** Both identity controls and every resource server downstream are
  keyed on an address; there is no way to authorize, revoke or audit a
  subject-only assertion without inventing a second identity namespace that
  nothing understands. An IdP that carries the address under another claim is
  handled with `subject_email_claim`. An IdP that emits no address at all cannot
  be onboarded — that is a deliberate limit, not an oversight.
- **One issuer maps to exactly one tenant**, and a shared multi-tenant IdP
  endpoint is refused outright. Entra's `/common`, `/organizations` and
  `/consumers` aliases are now rejected at REGISTRATION, with `400
  invalid_body`, because the first path segment on
  `login.microsoftonline.com` / `sts.windows.net` must be a tenant GUID. That
  matters: the 1:1 issuer index alone only produced `409 issuer_conflict` for
  the SECOND tenant to claim such an issuer, having already granted the first
  one an issuer that can assert anybody. Register the tenant-specific issuer URL
  instead.
- **HOST EXCLUSIVITY: a host carries either ONE whole-host issuer, or a SET of
  path-scoped issuers — never both across two different tenants.** An issuer
  with no path owns its whole origin, so its key source may be any path on that
  host; that is only safe while no other tenant has a trust domain there. The
  rule is enforced on every tenant write by a scan of the `issuer:` index and
  returns `409 issuer_conflict` naming the host and the conflicting tenant.
  Path-scoped issuers from different tenants share a host freely (Entra,
  PingOne): each is already bound to its own first segment.
- **Residual, accepted: a whole-host issuer may nominate any key path on the
  host it claims.** There is no tighter binding available for an issuer with no
  path. Host exclusivity means nobody else can be a tenant there, so the blast
  radius stops inside that tenant's own trust domain.
- **Residual, accepted: on the `sibling` tier, an IdP that serves a discovery
  document at the ISSUER'S OWN path naming another tenant's JWKS is honoured.**
  An attacker must control both the document at the issuer's path and stay
  inside the issuer's own first segment — strictly more than either half of the
  rule demanded on its own.
- **Revocation latency equals the access token TTL** (at most one hour), because
  resource servers verify the token offline against our JWKS.
- **Outbound fetches are restricted** to https, public hostnames, port 443, no
  redirects, a 3 s timeout and a 256 KB cap. `*.techimpossible.com` is blocked
  outright so the tenant admin cannot be used to aim the Worker at our own
  Workers.
- **CIMD is off unless an operator turns it on.** Resolving an `https://`
  client_id costs an outbound fetch and a KV write driven by an *unauthenticated*
  request parameter, so only the exact URLs listed in the `CIMD_CLIENT_IDS` var
  are resolved at all, and `client_id_metadata_document_supported` is advertised
  only while that list is non-empty. Before enabling it: fetch the document,
  confirm its `client_id` equals the URL and that every `redirect_uri` is
  same-origin with it, and note that clients which switch from a `ti-` client_id
  to a URL client_id lose their existing refresh tokens.
