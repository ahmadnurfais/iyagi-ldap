import crypto from "node:crypto";

export interface JwtClaims {
  sub?: string;
  user?: string;
  groups?: string[];
  exp?: number;
  iat?: number;
  [key: string]: unknown;
}

const ALGORITHMS: Record<string, string> = {
  HS256: "sha256",
  HS384: "sha384",
  HS512: "sha512",
};

export function verifyJwt(
  header: string | undefined,
  secret: string,
): { claims: JwtClaims | null; verified: boolean; error?: string } {
  if (!header) return { claims: null, verified: false };
  const match = /^Bearer\s+([A-Za-z0-9\-_.]+)$/.exec(header.trim());
  if (!match) return { claims: null, verified: false, error: "invalid-authorization-header" };
  const parts = match[1].split(".");
  if (parts.length !== 3) return { claims: null, verified: false, error: "not-a-jwt" };
  try {
    const jwtHeader = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")) as {
      alg?: string;
    };
    const digest = jwtHeader.alg ? ALGORITHMS[jwtHeader.alg] : undefined;
    if (!digest || !secret) {
      return { claims: null, verified: false, error: "unsupported-or-unconfigured-signature" };
    }
    const expected = crypto
      .createHmac(digest, secret)
      .update(`${parts[0]}.${parts[1]}`)
      .digest();
    const actual = Buffer.from(parts[2], "base64url");
    if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
      return { claims: null, verified: false, error: "invalid-signature" };
    }
    const payload = Buffer.from(parts[1], "base64url").toString("utf8");
    const claims = JSON.parse(payload) as JwtClaims;
    if (typeof claims.exp === "number" && claims.exp <= Date.now() / 1000) {
      return { claims: null, verified: false, error: "expired-token" };
    }
    return { claims, verified: true };
  } catch (e) {
    return { claims: null, verified: false, error: `verification-failed: ${(e as Error).message}` };
  }
}

export function extractActor(claims: JwtClaims | null): { userId: string | null; groups: string[] } {
  if (!claims) return { userId: null, groups: [] };
  const userId =
    typeof claims.user === "string"
      ? claims.user
      : typeof claims.sub === "string"
        ? claims.sub
        : null;
  const groups = Array.isArray(claims.groups)
    ? claims.groups.filter((g): g is string => typeof g === "string")
    : [];
  return { userId, groups };
}
