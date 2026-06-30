import type { UserJwtPayload, AdminJwtPayload } from "../lib/jwt";
import type { Logger } from "pino";

declare module "fastify" {
  interface FastifyRequest {
    /** Trace ID set by the request context plugin (separate from Fastify's built-in id) */
    traceId: string;
    /** Start time for request performance tracking */
    _startTime?: bigint;
    /** Authenticated user (set by authenticate middleware) */
    user?: UserJwtPayload;
    /** Authenticated admin (set by authenticateAdmin middleware) */
    admin?: AdminJwtPayload;
  }
}
