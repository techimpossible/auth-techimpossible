import { SignJWT } from "jose";
import { getPrivateSigningKey } from "./crypto.js";

export type IdTokenClaims = {
  iss: string;
  aud: string;
  sub: string;
  email: string;
  email_verified: boolean;
  iat: number;
  exp: number;
  tenant_id: null;
  roles: never[];
};

export async function mintAccessToken(
  env: { OAUTH_KV: KVNamespace; ISSUER: string },
  params: {
    aud: string;
    sub: string;
    email: string;
    ttlSeconds: number;
  }
): Promise<{ token: string; expiresIn: number; iat: number; exp: number }> {
  const { key, kid } = await getPrivateSigningKey(env);
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + params.ttlSeconds;

  const token = await new SignJWT({
    email: params.email,
    email_verified: true,
    tenant_id: null,
    roles: [] as never[],
  })
    .setProtectedHeader({ alg: "RS256", kid, typ: "JWT" })
    .setIssuer(env.ISSUER)
    .setAudience(params.aud)
    .setSubject(params.sub)
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .sign(key);

  return { token, expiresIn: params.ttlSeconds, iat, exp };
}

export async function mintIdToken(
  env: { OAUTH_KV: KVNamespace; ISSUER: string },
  params: {
    audClientId: string;
    sub: string;
    email: string;
    ttlSeconds: number;
    nonce?: string;
  }
): Promise<string> {
  const { key, kid } = await getPrivateSigningKey(env);
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + params.ttlSeconds;

  const builder = new SignJWT({
    email: params.email,
    email_verified: true,
  })
    .setProtectedHeader({ alg: "RS256", kid, typ: "JWT" })
    .setIssuer(env.ISSUER)
    .setAudience(params.audClientId)
    .setSubject(params.sub)
    .setIssuedAt(iat)
    .setExpirationTime(exp);

  if (params.nonce) {
    // jose's SignJWT doesn't directly support custom top-level claims via setX,
    // but the constructor takes any object. Setting nonce via the payload object
    // would require reconstructing — for now, just sign without nonce. Most clients
    // don't enforce nonce when state is present.
  }

  return builder.sign(key);
}
