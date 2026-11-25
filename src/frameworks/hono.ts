// No import of Hono's `Context` type in this file, and that is deliberate rather than an
// oversight.
//
// The SDK is published with one runtime dependency, `jose` (AGENTS.md). A shortcut that imported
// Hono would put a framework in a package meant to run anywhere, and would make the published types
// unresolvable for a Relying Party who installed the SDK on the server side and something else on the
// client side. The two things this binding touches — the header lookup and the handler's return —
// are typed structurally instead, so Hono's own `Context` satisfies them with nothing installed
// here.
//
// If you are here to add the real import: that is the moment this package needs a second dependency
// and a peer-dependency policy. Everything below the type does not change.

import {
  requireAgentAccount as requireWebAgentAccount,
  type RequireAgentAccountOptions,
  type RequireAgentAccountResult,
} from "./web.js";

export type {
  AgentAccountFailure,
  AgentRequest,
  RequireAgentAccountOptions,
  RequireAgentAccountResult,
} from "./web.js";

/**
 * The slice of a Hono `Context` this binding reads: the request header lookup, and nothing else.
 *
 * `c.req.header(name)` is case-insensitive and returns `undefined` when the header is absent, which
 * is why the shared request type accepts `undefined` as well as `null`.
 */
export type HonoContext = {
  readonly req: { header(name: string): string | undefined };
};

/**
 * Verifies the Agent Identity Token on a Hono request, then hands your handler the Relying Party's own user id.
 *
 * ```ts
 * import { requireAgentAccount } from "@agentonboard/sdk/hono";
 *
 * app.post("/notes", async (c) => {
 *   const session = await requireAgentAccount(c, {
 *     audience: "notes.com",
 *     // `email` is the claim verbatim — never lowercased for you — so the case policy is yours and
 *     // it belongs in here rather than in a comparison against a column you normalized elsewhere.
 *     resolveAccount: async ({ email }) =>
 *       (await db.user.findUnique({ where: { email: email.trim().toLowerCase() } }))?.id ?? null,
 *   });
 *
 *   if (!session.ok) return session.response; // 401, 403 or 500, already built
 *
 *   return c.json(await db.note.findMany({ where: { userId: session.user } }));
 * });
 * ```
 *
 * The failure is a WHATWG `Response`, so returning it from a Hono handler sends exactly the status
 * and body the adapter built — Hono does not re-wrap it.
 *
 * `audience` and `issuer` are literals you write in the source. Neither is ever taken from a header
 * or a body field: an audience the caller controls is not a check, and `issuer` is the host the
 * keys are fetched from as well as the claim the token is compared against.
 *
 * Your resolver receives the verified email and nothing else — no token, no claims, no `Request`.
 * Its result is never cached here, and this layer never catches what your handler throws.
 *
 * @param context The Hono context, `c`. `c.req.raw` also works and satisfies the shared type.
 * @param options Every `verifyAgentAccount` option except `token` and the key source, plus
 *   `onFailure`. A key source the caller could supply is not in the type at all; call
 *   `verifyAgentAccount` directly if you need one.
 * @returns `{ ok: true, user }` with your own user id, or `{ ok: false, response }` to return as-is.
 */
export function requireAgentAccount<TUser>(
  context: HonoContext,
  options: RequireAgentAccountOptions<TUser>
): Promise<RequireAgentAccountResult<TUser>> {
  return requireWebAgentAccount(
    { headers: { get: (name) => context.req.header(name) } },
    options
  );
}
