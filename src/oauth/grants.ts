/**
 * RFC 7523 §2.1 JWT bearer assertion grant. Used by the Enterprise Managed Auth
 * flow, where Claude presents an ID-JAG assertion signed by the customer's own
 * identity provider instead of a user-interactive authorization code.
 *
 * Declared in its own module so the tenant admin endpoint can validate a
 * client's grant_types without importing the grant handler.
 */
export const JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
