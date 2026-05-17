import type { Env } from "../env.js";
import { jsonOk } from "../lib/errors.js";
import { getPublicJwk } from "../lib/crypto.js";

export async function jwksHandler(env: Env): Promise<Response> {
  const publicJwk = await getPublicJwk(env);
  return jsonOk({ keys: [publicJwk] });
}
