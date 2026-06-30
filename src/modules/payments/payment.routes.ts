import { FastifyInstance } from "fastify";
import { authenticate } from "../../middleware/authenticate";
import { asyncHandler } from "../../utils/async-handler";
import {
  sendSuccess,
  sendCreated,
  sendPaginated,
  buildPaginationMeta,
} from "../../utils/response";
import {
  createTestOrderSchema,
  createSubscriptionOrderSchema,
  verifyPaymentSchema,
  orderHistoryQuerySchema,
} from "./schemas/payment.schema";
import {
  createTestOrder,
  createSubscriptionOrder,
  verifyPayment,
  handleWebhook,
  getOrderHistory,
  getOrderById,
} from "./services/payment.service";
import { createLogger } from "../../lib/logger";

const log = createLogger("payment-routes");

// =============================================================================
// Payment Routes
//
// Student routes (require auth):
//   POST   /payments/orders/test              Create order for a test purchase
//   POST   /payments/orders/subscription      Create order for a subscription
//   POST   /payments/verify                   Verify payment after checkout
//   GET    /payments/orders                   Order history
//   GET    /payments/orders/:orderId          Single order detail
//
// Public (webhook — verified by HMAC, NOT by JWT):
//   POST   /payments/webhook                  Razorpay webhook receiver
// =============================================================================

export async function paymentRoutes(app: FastifyInstance): Promise<void> {

  // ── POST /orders/test ───────────────────────────────────────────────────────
  app.post(
    "/orders/test",
    { preHandler: [authenticate] },
    asyncHandler(async (request, reply) => {
      const input = createTestOrderSchema.parse(request.body);
      const result = await createTestOrder(request.user!.id, input);
      return sendCreated(reply, result);
    })
  );

  // ── POST /orders/subscription ───────────────────────────────────────────────
  app.post(
    "/orders/subscription",
    { preHandler: [authenticate] },
    asyncHandler(async (request, reply) => {
      const input = createSubscriptionOrderSchema.parse(request.body);
      const result = await createSubscriptionOrder(request.user!.id, input);
      return sendCreated(reply, result);
    })
  );

  // ── POST /verify ────────────────────────────────────────────────────────────
  // Called by the frontend immediately after Razorpay checkout success.
  // Verifies the payment signature and fulfills the order.
  app.post(
    "/verify",
    { preHandler: [authenticate] },
    asyncHandler(async (request, reply) => {
      const input = verifyPaymentSchema.parse(request.body);
      const result = await verifyPayment(request.user!.id, input);
      return sendSuccess(reply, result);
    })
  );

  // ── GET /orders ─────────────────────────────────────────────────────────────
  app.get(
    "/orders",
    { preHandler: [authenticate] },
    asyncHandler(async (request, reply) => {
      const { page, pageSize } = orderHistoryQuerySchema.parse(request.query);
      const { orders, total } = await getOrderHistory(
        request.user!.id,
        page,
        pageSize
      );
      const pagination = buildPaginationMeta(total, page, pageSize);
      return sendPaginated(reply, orders, pagination);
    })
  );

  // ── GET /orders/:orderId ────────────────────────────────────────────────────
  app.get(
    "/orders/:orderId",
    { preHandler: [authenticate] },
    asyncHandler(async (request, reply) => {
      const { orderId } = request.params as { orderId: string };
      const order = await getOrderById(request.user!.id, orderId);
      return sendSuccess(reply, order);
    })
  );

  // ── POST /webhook ───────────────────────────────────────────────────────────
  // Razorpay calls this server-to-server.
  // Auth: HMAC-SHA256 of raw body against RAZORPAY_WEBHOOK_SECRET.
  // IMPORTANT: We register a custom content-type parser scoped ONLY to the
  // webhook route via Fastify's route-level parser.  The default JSON parser
  // used by all other payment routes above is left untouched.
  app.post(
    "/webhook",
    {
      // Use Fastify's preParsing hook to capture raw body for this route only
      preParsing: async (request, reply, payload) => {
        const chunks: Buffer[] = [];
        for await (const chunk of payload) {
          chunks.push(chunk);
        }
        // Attach raw buffer to request for use in handler
        (request as any).rawBody = Buffer.concat(chunks);
        // Return a new stream so Fastify doesn't complain
        const { Readable } = await import("stream");
        return Readable.from([Buffer.concat(chunks)]);
      },
    },
    asyncHandler(async (request, reply) => {
      const signature = request.headers["x-razorpay-signature"] as string;

      if (!signature) {
        log.warn("Webhook received without signature header");
        return reply.code(400).send({ error: "Missing signature" });
      }

      const rawBody = (request as any).rawBody as Buffer;
      if (!rawBody) {
        log.warn("Webhook received without raw body");
        return reply.code(400).send({ error: "Missing body" });
      }

      await handleWebhook(rawBody, signature);

      // Always 200 OK — Razorpay retries on non-2xx
      return reply.code(200).send({ received: true });
    })
  );
}
