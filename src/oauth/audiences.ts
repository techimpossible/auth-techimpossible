/**
 * The canonical set of audiences this authorization server will mint tokens for.
 *
 * Lives in its own leaf module so both the interactive /authorize resolver and
 * the tenant admin can consult one definition without importing each other.
 */
export const SUPPORTED_AUDS = new Set(["compliance-mcp", "basecamp-mcp", "vanta-audit-mcp"]);
