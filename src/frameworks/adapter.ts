import {
  verifyAgentAccount,
  type AccountErrorCode,
  type VerifyAgentAccountOptions,
} from "../account.js";

/**
 * The whole request an adapter can see: a header bag, and nothing else.
 *
 * Deliberately not `url`. A token read from a query string is a token in every access log and every
 * `Referer` header on the internet, so the field is not in the type — and it cannot be added
 * without someone editing this file on purpose.
 *
 * `get` may return `null` (a WHATWG `Headers`, which is what Next and Hono hand you) or `undefined`
 * (Express's `req.get`). Both satisfy the signature as written, which is the point of typing this
 * boundary structurally instead of importing three request classes.
 */
export type AgentRequest = {
  readonly headers: { get(name: string): string | null | undefined };
};

/**
 * A failure, as `onFailure` receives it and as the default response body is built from it.
 *
 * Two strings, and neither of them the token or the email. `code` is the stable branch to write
 * against; `error` is the one sentence an agent can hand to a human.
 */
export type AgentAccountFailure = {
  readonly code: AccountErrorCode;
  readonly error: string;
};

/**
 * Every {@link verifyAgentAccount} option except `token` and the key source, plus an optional
 * failure response.
 *
 * `token` is omitted from the type, so an adapter can only ever verify the token it read off the
 * request's own `Authorization` header. There is no option through which a token could arrive from
 * a header, a query string, or a cookie: closing that needs an edit to this file, not a call site.
 *
 * `jwks`, `jwksUrl` and `fetchJwks` are omitted for the same reason and the same force. A key
 * source taken from the request is not a key check, it is the other end of the authentication
 * handshake: the caller supplies both the keys and the signature, and `jwksUrl` read from a query
 * string is a request forger's SSRF primitive. The adapter's value is that there is nothing to
 * point, so the type has nothing to offer. A Relying Party who really does need a non-default key source
 * — an air-gapped issuer, pinned keys in a test — calls {@link verifyAgentAccount} directly, which
 * takes all of them. The omission is a type-level refusal, not a runtime one: `checkAgentAccount`
 * forwards whatever properties it is handed, so a JavaScript caller can still pass one.
 *
 * `audience` is required, and both it and `issuer` are yours to write in your source as literals.
 * Neither is ever read from the request. An audience the caller controls is not a check, it is an
 * instruction, and obeying it is how a token minted for someone else's service gets accepted here.
 * `issuer` is the same argument one step further: it is compared against the token's `iss` claim
 * *and* it is the host the keys are fetched from, so an issuer the caller controls chooses both
 * halves of the check and the endpoint the check is made against.
 */
export type RequireAgentAccountOptions<TUser> = Omit<
  VerifyAgentAccountOptions<TUser>,
  "token" | "jwks" | "jwksUrl" | "fetchJwks"
> & {
  /**
   * Your own response for a rejected request — for an existing error shape, a redirect to a login
   * page, a metric, a translated message. Returned verbatim, so the status you write is the status
   * the caller sees; the adapter's defaults are not used and not merged in.
   *
   * Called only on failure, and never on the handler's own exceptions: verification failure and
   * handler failure are different events, and collapsing them hides bugs.
   */
  onFailure?: (failure: AgentAccountFailure) => Response | Promise<Response>;
};

/**
 * Either your own user id, or a finished failure response to return as-is.
 *
 * On success there is one key of data, `user`, and it is yours: the id your own resolver returned.
 * The email, the token, its `jti`, its audience, the `Request`, and our internal user id are all
 * withheld, so the query a handler can write against a row it does not own is a query that does not
 * include this id in it.
 *
 * `ok` is a literal on both arms, so `if (!result.ok) return result.response` narrows with no cast.
 */
export type RequireAgentAccountResult<TUser> =
  | { readonly ok: true; readonly user: TUser }
  | { readonly ok: false; readonly response: Response };

const DEFAULT_CONTENT_TYPE = "application/json; charset=utf-8";

/**
 * The status a rejection is answered with.
 *
 * **401** for every rejection that is about the caller's token. "We do not know who you are" is the
 * same answer for a missing header, an expired token, a bad signature, the wrong audience, an
 * unknown key, and a JWKS endpoint that is down. Splitting those into 400, 401, 419, and 503 would
 * hand anyone probing this endpoint a map of which part of the forgery attempt failed.
 *
 * **403** for `ACCOUNT_REQUIRED`, and nothing else. The identity is genuine — the token verified —
 * and the account is not, which is why it is not an authentication failure
 * (`docs/adr/0002-sdk-runtime-contract-and-framework-subpaths.md`, Decision 3). Answering 401 sends the human to re-authenticate, which cannot
 * work, and hides the one action that can: connect their account, then retry.
 *
 * **500** for the two codes that are nobody's request being wrong. `RESOLVER_ERROR`: we know
 * exactly who this is, your own lookup threw. `CONFIG_ERROR`: this SDK was called without an
 * audience it can check against, or with a JWKS URL it cannot parse. A 401 on either tells the
 * agent its token is bad and invites a re-authentication loop against a token that is fine, and it
 * buries a server fault where nobody looks for 500s. Neither is fixable by the caller, so neither
 * is an authentication failure.
 */
function statusFor(code: AccountErrorCode): number {
  if (code === "ACCOUNT_REQUIRED") return 403;
  if (code === "RESOLVER_ERROR") return 500;
  if (code === "CONFIG_ERROR") return 500;
  return 401;
}

function defaultFailureResponse(failure: AgentAccountFailure): Response {
  return new Response(JSON.stringify({ code: failure.code, error: failure.error }), {
    status: statusFor(failure.code),
    headers: { "content-type": DEFAULT_CONTENT_TYPE },
  });
}

/**
 * The token in an `Authorization` header, or `""` when there is not one.
 *
 * Strips a leading `Bearer` case-insensitively and trims, in that order, so a token a Relying Party's own
 * middleware already stripped still verifies. The `(\s+|$)` is what makes a bare `Bearer` header
 * come back empty instead of handing the word "Bearer" to the parser as though it were a token.
 *
 * Empty is not an error here. The core already answers `MALFORMED_TOKEN` for it, and this layer does
 * not keep a second opinion about what a bad token is.
 */
function readBearerToken(header: string | null | undefined): string {
  if (typeof header !== "string") return "";
  return header.trim().replace(/^bearer(\s+|$)/i, "").trim();
}

/**
 * The whole implementation. Every framework binding in this folder ends in this call, so token
 * extraction, verification, the resolver round trip, and the code → status → body mapping are
 * written once and cannot drift between frameworks.
 *
 * The header name is a literal here, so "where does the token come from" has exactly one answer
 * across all three bindings.
 */
export async function checkAgentAccount<TUser>(
  request: AgentRequest,
  options: RequireAgentAccountOptions<TUser>
): Promise<RequireAgentAccountResult<TUser>> {
  const { onFailure, ...verifyOptions } = options;
  const token = readBearerToken(request.headers.get("Authorization"));

  const outcome = await verifyAgentAccount({ ...verifyOptions, token });

  if (outcome.ok) return { ok: true, user: outcome.user };

  const failure: AgentAccountFailure = { code: outcome.code, error: outcome.error };
  return {
    ok: false,
    response: onFailure ? await onFailure(failure) : defaultFailureResponse(failure),
  };
}
