export type Env = {
  OAUTH_KV: KVNamespace;
  ALLOWLIST_KV: KVNamespace;
  TENANT_KV: KVNamespace;
  GOOGLE_OIDC_CLIENT_ID: string;
  GOOGLE_OIDC_CLIENT_SECRET: string;
  ISSUER: string;
  ALLOWED_ADMIN_EMAILS: string;
  ADMIN_API_TOKEN: string;
  /**
   * Client ID Metadata Document allowlist: whitespace/comma separated, exact
   * https client_id URLs. CIMD resolution performs an outbound fetch driven by
   * an UNAUTHENTICATED request parameter, so it is refused for every client_id
   * that is not listed here. Unset (the default) disables CIMD entirely, and
   * the discovery document then stops advertising it.
   */
  CIMD_CLIENT_IDS?: string;
  /**
   * Extra https hosts an unvetted (DCR-registered) client may have an
   * authorization code delivered to: whitespace/comma separated bare hostnames,
   * each optionally prefixed with "*." for a subdomain suffix. Invalid entries
   * are dropped.
   *
   * It EXTENDS the built-in defaults in src/oauth/redirect-policy.ts rather than
   * replacing them, so a forgotten or mistyped variable cannot silently stop
   * connector registration working. Loopback redirects never need listing.
   */
  DCR_REDIRECT_HOSTS?: string;
};

export type JwtProps = {
  email: string;
  sub: string;
  tenant_id: string | null;
  roles: never[];
};

export type AuthStateRecord = {
  responseType: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string | null;
  codeChallenge: string | null;
  codeChallengeMethod: string | null;
  aud: string;
  createdAt: number;
};

export type ClientRecord = {
  clientId: string;
  clientSecretHash: string | null;
  redirectUris: string[];
  clientName?: string;
  tokenEndpointAuthMethod: "client_secret_post" | "client_secret_basic" | "none";
  grantTypes: string[];
  responseTypes: string[];
  scope?: string;
  registrationDate: number;
  // Machine-to-machine (client_credentials) service clients only. Absent on
  // normal OAuth clients. serviceEmail is minted into the token's `email` claim;
  // allowedAudiences bounds which aud values the client may request.
  serviceEmail?: string;
  allowedAudiences?: string[];
  // How this client record came into existence. Absent is treated as "dcr"
  // (fail closed): /register is unauthenticated, so a DCR-born client must never
  // be trusted for Enterprise Managed Auth.
  registrationSource?: "dcr" | "admin" | "cimd";
};

/**
 * One customer identity provider trusted by a tenant. `issuer` is the normalized
 * (lowercased scheme+host, no trailing slash) issuer identifier that must appear
 * as the assertion's `iss`. `jwksUri` is where its public keys are fetched from.
 */
export type TrustedIssuer = {
  issuer: string;
  jwksUri: string;
  addedAt: number;
};

/**
 * Enterprise Managed Auth tenant. Written only through the ADMIN_API_TOKEN-gated
 * /admin/tenants endpoints — never through /register — because this record, not
 * the client's self-asserted grant_types, is the authorization gate for the
 * urn:ietf:params:oauth:grant-type:jwt-bearer grant.
 */
export type TenantRecord = {
  tenantId: string;
  displayName?: string;
  status: "active" | "disabled";
  trustedIssuers: TrustedIssuer[];
  allowedAudiences: string[];
  allowedClientIds: string[];
  /**
   * NAMESPACE BINDING — mandatory, non-empty. The patterns ("*@acme.example" or
   * a full address) bound which identities this tenant's IdP may assert. It is
   * NOT the authorization decision: allowlist:<aud> in ALLOWLIST_KV is, and the
   * jwt-bearer grant applies both. KV holds untyped JSON, so a record written
   * before this field became mandatory can still lack it at runtime; the grant
   * handler fails closed on that case rather than trusting the type.
   */
  emailDomains: string[];
  /**
   * Audience minted when the request carries no RFC 8707 resource indicator and
   * the assertion carries no `resource` claim. Must be a member of
   * allowedAudiences. Defaults to allowedAudiences[0]: some IdP configurations
   * cannot forward a resource indicator at all, so the request is still served.
   */
  defaultAudience?: string;
  subjectEmailClaim?: string;
  maxAssertionAgeSeconds?: number;
  allowLegacyTyp?: boolean;
  issuerClaimBindings?: Record<string, string>;
  createdAt: number;
  updatedAt: number;
};

export type AuthCodeRecord = {
  clientId: string;
  userId: string;
  redirectUri: string;
  scope: string;
  codeChallenge: string | null;
  codeChallengeMethod: string | null;
  props: JwtProps;
  aud: string;
  createdAt: number;
};

/**
 * `allowlist:<aud>` in ALLOWLIST_KV — the per-audience authorization record.
 *
 * `denied` is OPTIONAL and absent from every record written before revocation of
 * a single identity existed, so a stored record keeps its exact current meaning
 * until an operator revokes someone. It uses the SAME pattern grammar as
 * `emails` (a literal address, or `*@domain`) and the same matcher, and it is
 * evaluated BEFORE `emails`: it is what makes "revoke one named person" possible
 * on an audience scoped as `["*@customer.example"]`, where removing an entry
 * from `emails` cannot express it.
 *
 * A `denied` value that is present but is not an array of strings makes the
 * WHOLE RECORD malformed rather than reading as "no denies". Degrading to "no
 * denies" would silently un-revoke someone — the same class of silent failure
 * the deny list exists to fix. See validateAllowlistRecord.
 */
export type Allowlist = {
  emails: string[];
  denied?: string[];
};
