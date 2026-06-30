import jwt from "jsonwebtoken";
import { env } from "../config/env";

// =============================================================================
// JWT tokens — access (short-lived) and refresh (long-lived)
// =============================================================================

export interface BaseJwtPayload {
  sub: string;       // subject — userId or adminId
  type: "user" | "admin";
  jti: string;       // unique token id (for blacklisting)
  iat: number;       // issued at (seconds)
  exp: number;       // expires at (seconds)
}

export interface UserJwtPayload extends BaseJwtPayload {
  type: "user";
  email?: string;
  mobile?: string;
}

export interface AdminJwtPayload extends BaseJwtPayload {
  type: "admin";
  email: string;
  assignedExams: string[];
  isSuperAdmin: boolean;
}

export type AnyJwtPayload = UserJwtPayload | AdminJwtPayload;

// =============================================================================
// Type helpers for properly distributing Omit over union types
// =============================================================================
type UserJwtSignPayload = Omit<UserJwtPayload, "jti" | "iat" | "exp">;
type AdminJwtSignPayload = Omit<AdminJwtPayload, "jti" | "iat" | "exp">;

const { JWT_ACCESS_SECRET, JWT_REFRESH_SECRET } = env;

// ---------------------------------------------------------------------------
// ACCESS TOKEN — 15 minutes
// ---------------------------------------------------------------------------
export function signAccessToken(payload: UserJwtSignPayload | AdminJwtSignPayload): string {
  return jwt.sign(
    { ...payload },
    JWT_ACCESS_SECRET,
    { expiresIn: "15m" } // 900 seconds
  );
}

// ---------------------------------------------------------------------------
// REFRESH TOKEN — 30 days
// ---------------------------------------------------------------------------
export function signRefreshToken(payload: UserJwtSignPayload | AdminJwtSignPayload): string {
  return jwt.sign(
    { ...payload },
    JWT_REFRESH_SECRET,
    { expiresIn: "30d" }
  );
}

// ---------------------------------------------------------------------------
// VERIFY
// ---------------------------------------------------------------------------
export function verifyAccessToken(token: string): AnyJwtPayload {
  return jwt.verify(token, JWT_ACCESS_SECRET) as AnyJwtPayload;
}

export function verifyRefreshToken(token: string): AnyJwtPayload {
  return jwt.verify(token, JWT_REFRESH_SECRET) as AnyJwtPayload;
}

// ---------------------------------------------------------------------------
// DECODE (no signature verification)
// ---------------------------------------------------------------------------
export function decodeToken(token: string): AnyJwtPayload | null {
  const decoded = jwt.decode(token);
  if (!decoded || typeof decoded !== "object") return null;
  return decoded as AnyJwtPayload;
}

// ---------------------------------------------------------------------------
// UTILITIES
// ---------------------------------------------------------------------------

/** How many seconds until this token expires? (0 if already expired / malformed) */
export function getTokenRemainingTtl(token: string): number {
  try {
    const decoded = jwt.decode(token) as { exp?: number } | null;
    if (!decoded?.exp) return 0;
    return Math.max(0, decoded.exp - Math.floor(Date.now() / 1000));
  } catch {
    return 0;
  }
}

/** Has this token already expired? */
export function isTokenExpired(token: string): boolean {
  return getTokenRemainingTtl(token) <= 0;
}

// =============================================================================
// Middleware helpers
// =============================================================================

/** Create a payload for the given entity type */
export function makeTokenPayload(
  entityType: "user" | "admin",
  entityId: string,
  extras?: Omit<Partial<AnyJwtPayload>, "sub" | "type">
): UserJwtSignPayload | AdminJwtSignPayload {
  const base = { sub: entityId, type: entityType };
  if (entityType === "admin") {
    return {
      ...base,
      type: "admin",
      email: (extras as any)?.email ?? "",
      assignedExams: (extras as any)?.assignedExams ?? [],
      isSuperAdmin: (extras as any)?.isSuperAdmin ?? false,
    };
  }
  return {
    ...base,
    type: "user",
    email: (extras as any)?.email ?? undefined,
    mobile: (extras as any)?.mobile ?? undefined,
  };
}
