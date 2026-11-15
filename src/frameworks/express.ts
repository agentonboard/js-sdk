// No import of Express's request or response types in this file, and that is deliberate rather
// than an oversight.
//
// The SDK is published with one runtime dependency, `jose` (AGENTS.md). A shortcut that imported
// Express would put a framework in a package meant to run anywhere, and would force `@types/express`
// onto every consumer's type graph. The four members this binding touches are typed structurally
// instead, so `express.Request` and `express.Response` satisfy them with nothing installed here and
// nothing declared.
//
// If you are here to add the real import: that is the moment this package needs a second dependency
// and a `@types/express` peer dependency. Nothing in the body below the types changes.

import {
  checkAgentAccount,
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
 * The slice of an Express request this binding reads: the header lookup, and nothing else.
 *
 * `req.get(name)` is case-insensitive and returns `undefined` when the header is absent. A raw
 * `IncomingMessage` has no `get`, so passing one instead of an Express request is a type error
 * rather than a runtime surprise.
 */
export type ExpressRequest = {
  get(name: string): string | undefined;
};

/** The slice of an Express response this binding writes. */
export type ExpressResponse = {
  status(code: number): ExpressResponse;
  setHeader(name: string, value: string): unknown;
  send(body?: unknown): unknown;
};

/**
 * Verifies the Agent Identity Token on an Express request, then hands your handler the Relying Party's own user id.
 *
 * ```ts
 * import { requireAgentAccount } from "@agentonboard/sdk/express";
 *
 * app.post("/notes", async (req, res) => {
 *   const session = await requireAgentAccount(req, res, {
 *     audience: "notes.com",
 *     // `email` is the claim verbatim — never lowercased for you — so the case policy is yours and
 *     // it belongs in here rather than in a comparison against a column you normalized elsewhere.
 *     resolveAccount: async ({ email }) =>
 *       (await db.user.findUnique({ where: { email: email.trim().toLowerCase() } }))?.id ?? null,
 *   });
 *
 *   if (!session.ok) return; // the 401, 403 or 500 is already on the wire
 *
 *   res.json(await db.note.findMany({ where: { userId: session.user } }));
 * });
 * ```
 *
 * Express is the one binding that takes `res`, because an Express handler's return value is
 * discarded: there is no way to hand a `Response` back, and a Relying Party who wrote
 * `res.json(await session.response.json())` would have to remember the status and could easily
 * answer 200 for a failed check. Here the status, the headers, and the body are the adapter's, and
 * only your own `res.json(...)` on the success path is left to you.
 *
 * Nothing is written to `res` on success, and nothing is written to it twice.
 *
 * `audience` and `issuer` are literals you write in the source. Neither is ever taken from a header
 * or a body field: an audience the caller controls is not a check, and `issuer` is the host the
 * keys are fetched from as well as the claim the token is compared against.
 *
 * Your resolver receives the verified email and nothing else — no token, no claims, no `Request`.
 * Its result is never cached here, and this layer never catches what your handler throws.
 *
 * @param request The Express `Request`.
 * @param response The Express `Response`. A rejection is written to it — status, headers, and body
 *   relayed from the response the adapter built — before this promise resolves.
 * @param options Every `verifyAgentAccount` option except `token` and the key source, plus
 *   `onFailure`. A key source the caller could supply is not in the type at all; call
 *   `verifyAgentAccount` directly if you need one.
 * @returns `{ ok: true, user }` with your own user id, or `{ ok: false, response }` when the
 *   rejection has already been sent.
 */
export async function requireAgentAccount<TUser>(
  request: ExpressRequest,
  response: ExpressResponse,
  options: RequireAgentAccountOptions<TUser>
): Promise<RequireAgentAccountResult<TUser>> {
  const result = await checkAgentAccount(
    { headers: { get: (name) => request.get(name) } },
    options
  );

  if (result.ok) return result;

  // Relayed whole: status, every header (a redirect's `Location`, a cookie, a `Retry-After` your
  // `onFailure` set), then the body. A bridge to `res.json` would drop all of that and would also
  // fail on any body that is not JSON.
  result.response.headers.forEach((value, name) => response.setHeader(name, value));
  response.status(result.response.status).send(await result.response.text());
  return result;
}
