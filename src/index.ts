import type { Env } from "./env.js";
import { jsonError, jsonOk } from "./lib/errors.js";
import { discoveryHandler } from "./oauth/discovery.js";
import { jwksHandler } from "./oauth/jwks.js";
import { registerHandler } from "./oauth/register.js";
import { authorizeHandler } from "./oauth/authorize.js";
import { tokenHandler } from "./oauth/token.js";
import { googleCallbackHandler } from "./google/callback.js";
import { adminAllowlistDeniedHandler, adminAllowlistHandler } from "./allowlist/admin.js";
import { adminServiceClientHandler } from "./oauth/service-clients.js";
import {
  adminTenantHandler,
  adminTenantIssuersHandler,
  adminTenantListHandler,
} from "./tenants/admin.js";

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

    // The deny sub-resource is matched first, on the same convention as
    // /admin/tenants/<id>/issuers below. The audience regex is anchored and
    // cannot swallow this path, so the ordering is defensive rather than
    // load-bearing.
    const deniedMatch = path.match(/^\/admin\/allowlist\/([a-zA-Z0-9_-]+)\/denied\/?$/);
    if (deniedMatch) {
      return adminAllowlistDeniedHandler(request, env, deniedMatch[1]);
    }

    const adminMatch = path.match(/^\/admin\/allowlist\/([a-zA-Z0-9_-]+)\/?$/);
    if (adminMatch) {
      return adminAllowlistHandler(request, env, adminMatch[1]);
    }

    // Enterprise Managed Auth tenants. Longer paths are matched first so
    // /admin/tenants/<id>/issuers cannot be swallowed by the tenant regex. The
    // id charset excludes dots and colons (see TENANT_ID_RE).
    if (path === "/admin/tenants" || path === "/admin/tenants/") {
      return adminTenantListHandler(request, env);
    }

    const tenantIssuersMatch = path.match(/^\/admin\/tenants\/([a-z0-9][a-z0-9_-]{1,62})\/issuers\/?$/);
    if (tenantIssuersMatch) {
      return adminTenantIssuersHandler(request, env, tenantIssuersMatch[1]);
    }

    const tenantMatch = path.match(/^\/admin\/tenants\/([a-z0-9][a-z0-9_-]{1,62})\/?$/);
    if (tenantMatch) {
      return adminTenantHandler(request, env, tenantMatch[1]);
    }

    if (path === "/admin/service-clients") {
      return adminServiceClientHandler(request, env);
    }

    return jsonError(404, "not_found", `No handler for ${path}`);
  },
} satisfies ExportedHandler<Env>;
