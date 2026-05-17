import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
const VALID_GOOGLE_ISSUERS = new Set(["accounts.google.com", "https://accounts.google.com"]);

let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;

function getJwks() {
  if (jwks) return jwks;
  jwks = createRemoteJWKSet(new URL(GOOGLE_JWKS_URL), {
    cacheMaxAge: 3600 * 1000,
    cooldownDuration: 30 * 1000,
  });
  return jwks;
}

export async function verifyGoogleIdToken(
  idToken: string,
  expectedAudience: string
): Promise<{
  email: string;
  sub: string;
  emailVerified: boolean;
  payload: JWTPayload;
}> {
  const { payload } = await jwtVerify(idToken, getJwks(), {
    audience: expectedAudience,
    algorithms: ["RS256"],
  });

  const iss = payload.iss;
  if (typeof iss !== "string" || !VALID_GOOGLE_ISSUERS.has(iss)) {
    throw new Error(`Invalid Google ID token issuer: ${iss}`);
  }

  const email = payload.email;
  if (typeof email !== "string" || email.length === 0) {
    throw new Error("Google ID token missing email claim");
  }

  const emailVerified = payload.email_verified === true;
  if (!emailVerified) {
    throw new Error("Google ID token email_verified is not true");
  }

  const sub = payload.sub;
  if (typeof sub !== "string" || sub.length === 0) {
    throw new Error("Google ID token missing sub claim");
  }

  return { email, sub, emailVerified, payload };
}
