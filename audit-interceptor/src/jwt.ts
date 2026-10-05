export interface JwtClaims {
  sub?: string;
  groups?: string[];
  exp?: number;
  iat?: number;
  [key: string]: unknown;
}

/**
 * Decode a JWT without signature verification. lldap has already verified the token
 * before this proxy sees the request. We only need the claims for actor attribution.
 */
export function decodeJwt(header: string | undefined): { claims: JwtClaims | null; error?: string } {
  if (!header) return { claims: null };
  const match = /^Bearer\s+([A-Za-z0-9\-_.]+)$/.exec(header.trim());
  if (!match) return { claims: null, error: "invalid-authorization-header" };
  const parts = match[1].split(".");
  if (parts.length !== 3) return { claims: null, error: "not-a-jwt" };
  try {
    const payload = Buffer.from(parts[1], "base64url").toString("utf8");
    const claims = JSON.parse(payload) as JwtClaims;
    return { claims };
  } catch (e) {
    return { claims: null, error: `decode-failed: ${(e as Error).message}` };
  }
}

export function extractActor(claims: JwtClaims | null): { userId: string | null; groups: string[] } {
  if (!claims) return { userId: null, groups: [] };
  const userId = typeof claims.sub === "string" ? claims.sub : null;
  const groups = Array.isArray(claims.groups)
    ? claims.groups.filter((g): g is string => typeof g === "string")
    : [];
  return { userId, groups };
}
