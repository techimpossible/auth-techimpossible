export type Env = {
  OAUTH_KV: KVNamespace;
  ALLOWLIST_KV: KVNamespace;
  TENANT_KV: KVNamespace;
  GOOGLE_OIDC_CLIENT_ID: string;
  GOOGLE_OIDC_CLIENT_SECRET: string;
  ISSUER: string;
  ALLOWED_ADMIN_EMAILS: string;
  ADMIN_API_TOKEN: string;
};

export type JwtProps = {
  email: string;
  sub: string;
  tenant_id: null;
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

export type Allowlist = {
  emails: string[];
};
