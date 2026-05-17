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
