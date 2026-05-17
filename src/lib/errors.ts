export function jsonError(
  status: number,
  error: string,
  description?: string,
  extra?: Record<string, unknown>
): Response {
  const body = JSON.stringify({
    error,
    ...(description ? { error_description: description } : {}),
    ...(extra ?? {}),
  });
  return new Response(body, {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

export function jsonOk(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}
