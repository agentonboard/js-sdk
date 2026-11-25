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
 * Verifies the Agent Identity Token on any Web-Standard / Fetch `Request` (Next.js App Router,
 * Cloudflare Workers, Deno, Bun, Remix, SvelteKit), then hands your handler the Relying Party's own user id.
 *
 * @param request Any object with a WHATWG-compatible `headers.get(name)` method.
 * @param options Every `verifyAgentAccount` option except `token` and the key source, plus `onFailure`.
 * @returns `{ ok: true, user }` with your own user id, or `{ ok: false, response }` to return as-is.
 */
export function requireAgentAccount<TUser>(
  request: AgentRequest,
  options: RequireAgentAccountOptions<TUser>
): Promise<RequireAgentAccountResult<TUser>> {
  return checkAgentAccount(request, options);
}
