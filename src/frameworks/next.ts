// No Next import in this file, and that is deliberate rather than an oversight.
//
// The SDK is published with one runtime dependency, `jose` (AGENTS.md). A shortcut that imports
// Next would drag Next's own module graph into every install — Edge, `next/server`, the React
// server runtime — and pin a published package to someone else's release train. The request shape
// this binding actually touches is one method, so it is typed structurally instead: `NextRequest`
// and the WHATWG `Request` a route handler receives already satisfy `AgentRequest`, with nothing
// installed here and nothing declared.
//
// If you are here to add the real import: the structural type is the whole reason this file is a
// binding rather than a port. Nothing in the body below it changes.

import {
  checkAgentAccount,
  type AgentRequest,
  type RequireAgentAccountOptions,
  type RequireAgentAccountResult,
} from "./adapter.js";

export type {
  AgentAccountFailure,
  AgentRequest,
  RequireAgentAccountOptions,
  RequireAgentAccountResult,
} from "./adapter.js";

/**
 * Verifies the Agent Identity Token on a Next.js request, then hands your route the Relying Party's own user id.
 *
 * ```ts
 * import { requireAgentAccount } from "@agentonboard/sdk/next";
 *
 * export async function POST(request: Request) {
 *   const session = await requireAgentAccount(request, {
 *     audience: "notes.com",
 *     // `email` is the claim verbatim — never lowercased for you — so the case policy is yours and
 *     // it belongs in here rather than in a comparison against a column you normalized elsewhere.
 *     resolveAccount: async ({ email }) =>
 *       (await db.user.findUnique({ where: { email: email.trim().toLowerCase() } }))?.id ?? null,
 *   });
 *
 *   if (!session.ok) return session.response; // 401, 403 or 500, already built
 *
 *   return Response.json(await db.note.findMany({ where: { userId: session.user } }));
 * }
 * ```
 *
 * Call it in the route handler, not in `middleware`. Middleware cannot pass the resolved user on to
 * the handler without writing it somewhere a client can influence, and this id is the authorization
 * the handler scopes its query by — a middleware check followed by a re-check here is two
 * verifications, and a middleware check alone is no verification at all.
 *
 * `audience` and `issuer` are literals you write in the source. Neither is ever taken from a header
 * or a body field: an audience the caller controls is not a check, and `issuer` is the host the
 * keys are fetched from as well as the claim the token is compared against.
 *
 * Your resolver receives the verified email and nothing else — no token, no claims, no `Request`.
 * Its result is never cached here, and this layer never catches what your handler throws.
 *
 * @param request The request as Next hands it to a route handler or middleware. `NextRequest`
 *   satisfies {@link AgentRequest} unchanged.
 * @param options Every `verifyAgentAccount` option except `token` and the key source, plus
 *   `onFailure`. A key source the caller could supply is not in the type at all; call
 *   `verifyAgentAccount` directly if you need one.
 * @returns `{ ok: true, user }` with your own user id, or `{ ok: false, response }` to return as-is.
 */
export function requireAgentAccount<TUser>(
  request: AgentRequest,
  options: RequireAgentAccountOptions<TUser>
): Promise<RequireAgentAccountResult<TUser>> {
  return checkAgentAccount(request, options);
}
