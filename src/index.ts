import type { Env } from "./env.js";
import { jsonError, jsonOk } from "./lib/errors.js";
import { discoveryHandler } from "./oauth/discovery.js";
import { jwksHandler } from "./oauth/jwks.js";
import { registerHandler } from "./oauth/register.js";
import { authorizeHandler } from "./oauth/authorize.js";
import { tokenHandler } from "./oauth/token.js";
import { googleCallbackHandler } from "./google/callback.js";
import { adminAllowlistHandler } from "./allowlist/admin.js";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/" || path === "/health") {
      return jsonOk({ name: "auth-techimpossible", version: "0.1.0", status: "ok" });
    }

    if (path === "/.well-known/oauth-authorization-server") {
      return discoveryHandler(env);
    }
    if (path === "/.well-known/openid-configuration") {
      return discoveryHandler(env);
    }
    if (path === "/.well-known/jwks.json") {
      return jwksHandler(env);
    }

    if (path === "/register") return registerHandler(request, env);
    if (path === "/authorize") return authorizeHandler(request, env);
    if (path === "/token") return tokenHandler(request, env);
    if (path === "/oauth/callback") return googleCallbackHandler(request, env);

    const adminMatch = path.match(/^\/admin\/allowlist\/([a-zA-Z0-9_-]+)\/?$/);
    if (adminMatch) {
      return adminAllowlistHandler(request, env, adminMatch[1]);
    }

    return jsonError(404, "not_found", `No handler for ${path}`);
  },
} satisfies ExportedHandler<Env>;
