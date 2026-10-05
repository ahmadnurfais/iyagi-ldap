const SECRET_KEY_PATTERN = /(password|passwd|secret|token|credential|apikey|api_key|hashed)/i;

/**
 * Recursively redact any key that looks secret-bearing. Values are replaced with
 * a fixed marker so their presence remains visible in the audit event.
 */
export function redact(value: unknown, path: string[] = []): unknown {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) {
    return value.map((v, i) => redact(v, [...path, String(i)]));
  }
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (SECRET_KEY_PATTERN.test(k)) {
        out[k] = "[REDACTED]";
      } else {
        out[k] = redact(v, [...path, k]);
      }
    }
    return out;
  }
  return value;
}

export function redactHeaders(headers: Record<string, string | string[] | undefined>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (v === undefined) continue;
    const lower = k.toLowerCase();
    const flat = Array.isArray(v) ? v.join(",") : v;
    if (lower === "authorization" || lower === "cookie" || lower === "set-cookie") {
      out[k] = "[REDACTED]";
    } else {
      out[k] = flat;
    }
  }
  return out;
}
