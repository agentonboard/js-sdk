import type { VerifyErrorCode } from "./codes.js";
import { verifyAgentToken, type VerifyAgentTokenOptions } from "./verify.js";

/**
 * The verified identity, and the only thing that crosses into your resolver.
 *
 * Our internal user id is deliberately absent. It means nothing outside AgentOnboard and would end
 * up in the wrong column of your database.
 *
 * `email` is the claim verbatim: not lowercased, not trimmed, not normalized. Email→user is your
 * lookup, so the case policy is yours — normalize once, inside your own resolver, rather than
 * comparing an unnormalized claim against a normalized column.
 */
export type AgentIdentity = {
  readonly email: string;
};

/**
 * Normalizes an email address for database lookups by trimming whitespace and converting to lowercase.
 */
export function normalizeEmail(email: string): string {
  if (!email || typeof email !== "string") return "";
  return email.trim().toLowerCase();
}

/**
 * Your account lookup. Called once per request, after the token has verified, and never cached by
 * this layer.
 *
 * Return your user id, or `undefined`/`null` to say "no account here" — that is the only thing this
 * layer reads as an absence. `0` and `""` are user ids and resolve successfully; only the two
 * documented emptiness values are `ACCOUNT_REQUIRED`.
 *
 * Return a promise for a database call. Throwing is safe: it becomes `RESOLVER_ERROR`, never an
 * exception and never `ACCOUNT_REQUIRED`.
 */
export type AccountResolver<TUser> = (
  identity: AgentIdentity
) => TUser | null | undefined | Promise<TUser | null | undefined>;

/**
 * Your account creation, called only on a miss and only by {@link createAgentAccount}. Called once
 * per request, never cached, and only ever after the token has verified and your resolver has
 * returned nothing.
 *
 * It receives the same identity your resolver did: the verified email, and nothing else. There is
 * no parameter to pass an email in, so there is no way to write the account-takeover version of
 * this — the address can only come from the token that was just proved.
 *
 * Whatever you return is the user. Return a promise for a database call; throwing is safe and
 * becomes `RESOLVER_ERROR`.
 */
export type AccountCreator<TUser> = (identity: AgentIdentity) => TUser | Promise<TUser>;

/**
 * Every outcome this layer can report.
 *
 * `VerifyErrorCode` is the core's frozen vocabulary — the token itself was unacceptable.
 * `ACCOUNT_REQUIRED` is the one case where the token was *fine* and the account does not exist, so
 * it is not an auth failure and must never be reported as one. `RESOLVER_ERROR` is the Relying Party's
 * own code failing.
 */
export type AccountErrorCode = VerifyErrorCode | "ACCOUNT_REQUIRED" | "RESOLVER_ERROR";

/**
 * `ok: true` carries your user id and nothing else — no `userId`, no token, no claims. `ok: false`
 * carries a code you can branch on and one sentence you can show a human.
 */
export type AccountOutcome<TUser> =
  | { ok: true; email: string; user: TUser }
  | { ok: false; code: AccountErrorCode; error: string };

export interface VerifyAgentAccountOptions<TUser> extends VerifyAgentTokenOptions {
  /**
   * Your email → user lookup. Return nothing for an email with no account, and do not create one
   * here — this function never creates. {@link createAgentAccount} is the one that does.
   */
  resolveAccount: AccountResolver<TUser>;
}

/**
 * Verifies an Agent Identity Token, then maps the verified email to your own user.
 *
 * An agent can work inside an account. This function proves *who* the human is; your resolver
 * decides, server-side, whether that human has an account at your service.
 *
 * **A verified email asserts almost nothing.** It means the inbox was verified at AgentOnboard. It
 * does not mean the person is your customer, is not banned, and is not already a different account
 * in your database. We have no consent model, so any AgentOnboard user can present a genuine
 * identity to your service whether or not they have ever heard of it
 * (`docs/adr/0004-no-consent-model.md`).
 *
 * **This function never creates an account.** Return nothing for an unknown email and the caller
 * gets `ACCOUNT_REQUIRED`, which is the right answer for a service that serves only its existing
 * customers — and for every Relying Party who has not opted in. Whether an agent may create an account is
 * a separate, named decision: {@link createAgentAccount} is the function that does it, and importing
 * it is the whole opt-in (`docs/adr/0009-agents-can-create-partner-accounts.md`).
 *
 * Your resolver receives identity only: the verified email, and nothing else. It never receives the
 * `Request`, the headers, the cookies, the IP, or our user id — so an authorization decision made
 * here stays visible in your own auth layer instead of disappearing into a callback. Identity
 * answers *who*; it never answers *what they may do*.
 *
 * Resolver results are never cached, and this layer will not start. A stale "this user exists" is
 * how a deleted or banned account keeps working. Every call invokes your resolver; if you want a
 * cache, it is yours, in your layer, where you can see it and reason about it.
 *
 * Never throws. A resolver that throws is reported as `RESOLVER_ERROR` — the same code any other
 * break in your own code would be — because a throw can mean "my database is down" and reporting
 * that as `ACCOUNT_REQUIRED` would send a human to fix an account that is fine.
 *
 * @param options Every {@link verifyAgentToken} option, plus `resolveAccount`. The token, audience,
 *   issuer and key source are the core's; this layer adds one callback and changes nothing else.
 * @returns `{ ok: true, email, user }` on a match, or a rejection carrying an {@link AccountErrorCode}.
 */
export async function verifyAgentAccount<TUser>(
  options: VerifyAgentAccountOptions<TUser>
): Promise<AccountOutcome<TUser>> {
  const { resolveAccount, ...verifyOptions } = options;

  const result = await verifyAgentToken(verifyOptions);
  if (!result.ok) {
    return {
      ok: false,
      code: result.code,
      error: result.error,
    };
  }

  // One key, built literally. Spreading the core result would hand the resolver our user id, the
  // token's jti and its audience — the exact data this boundary exists to withhold.
  const identity: AgentIdentity = { email: result.email };

  let user: TUser | null | undefined;
  try {
    user = await resolveAccount(identity);
  } catch {
    // The thrown value is not echoed: it is untrusted text that usually carries a connection
    // string, and it lands in an error aggregator. Log it inside your own resolver.
    return {
      ok: false,
      code: "RESOLVER_ERROR",
      error: "The account resolver threw. This is a fault in the resolver, not the token.",
    };
  }

  if (user === null || user === undefined) {
    return {
      ok: false,
      code: "ACCOUNT_REQUIRED",
      error:
        "This identity has no account at your service; send the human to connect their account, then retry.",
    };
  }

  return { ok: true, email: result.email, user };
}

export interface CreateAgentAccountOptions<TUser> extends VerifyAgentTokenOptions {
  /**
   * Your email → user lookup, called first and called once. Return nothing for an email with no
   * account, and your `createAccount` runs; return a user and it does not.
   */
  resolveAccount: AccountResolver<TUser>;
  /**
   * Your insert. Called only after the token has verified and your resolver returned nothing, and
   * only with the verified email.
   */
  createAccount: AccountCreator<TUser>;
}

/**
 * What {@link createAgentAccount} reports on success.
 *
 * `created` is the load-bearing field: it distinguishes "signed in" from "made an account", which
 * is what your audit log needs and what the agent needs to be able to report. It is also what makes
 * a repeat call visible instead of silent.
 */
export type CreateAccountOutcome<TUser> =
  | { ok: true; email: string; user: TUser; created: boolean }
  | { ok: false; code: AccountErrorCode; error: string };

/**
 * Verifies an Agent Identity Token, maps the verified email to your user, and — only if there is no
 * user — calls your `createAccount` once.
 *
 * This is the opt-in, and it belongs in exactly one place: your signup/registration handler.
 * Everything else — every other route — stays on {@link verifyAgentAccount}, so an unknown identity
 * meets `ACCOUNT_REQUIRED` ("you have no account") before anything is created, and your `auth.md`
 * points that error at this handler. That is the human flow, mirrored: log in first, and only then
 * register. Wrapping every route in this function instead would mint an account as a side effect of
 * whatever request the agent happened to make, including a read that was never trying to create one
 * (`docs/adr/0009-agents-can-create-partner-accounts.md`, amendment 2026-10-06).
 *
 * A Relying Party that imports and calls it here lets an agent create an account for the human it
 * represents. A Relying Party that does not still cannot create anything, and still gets
 * `ACCOUNT_REQUIRED` from {@link verifyAgentAccount}.
 *
 * **The order is not negotiable, and each step depends on the one before it.**
 *
 * 1. The token is verified first. If it fails, neither callback runs: an email that was never proved
 *    is not an identity, and creating from one is how an unproved address becomes a real account.
 * 2. `resolveAccount` runs once. A hit returns `{ ok: true, created: false }` — your creator is not
 *    called, so calling twice with the same token finds the account it just made.
 * 3. A miss calls `createAccount`. Whatever it returns is the user, and the outcome carries
 *    `created: true`.
 *
 * **Both callbacks receive identity only** — the verified email, and nothing else. Not the
 * `Request`, the headers, the cookies, the IP, the token, or our internal user id. Matching that
 * email against your users table is the join key, not a linking violation: a hit signs in, and only
 * a miss creates. There is no parameter to pass an email *into* your creator, so the address can
 * only come from the token that was just verified. That is what makes the account-takeover version
 * of this unwritable rather than merely discouraged.
 *
 * The account is a normal, fully usable account — the default. If you want one restricted, that is a
 * column on your own table, checked inside your own creator or your own auth layer; we ship no flag
 * for it, because a restriction only you can weigh should not be a default imposed on every Relying Party.
 * The created account has no password, and no notification is sent: the receipt is yours to send, in
 * your product, with data this token does not carry.
 *
 * Never throws, like {@link verifyAgentAccount}. A `createAccount` that throws is `RESOLVER_ERROR`,
 * never `ACCOUNT_REQUIRED` — reporting a database fault as a missing account sends a human to fix
 * an account that is fine. The thrown value is not echoed.
 *
 * @param options Every {@link verifyAgentToken} option, plus `resolveAccount` and `createAccount`.
 * @returns `{ ok: true, email, user, created }`, or a rejection carrying an
 *   {@link AccountErrorCode}.
 */
export async function createAgentAccount<TUser>(
  options: CreateAgentAccountOptions<TUser>
): Promise<CreateAccountOutcome<TUser>> {
  const { resolveAccount, createAccount, ...verifyOptions } = options;

  const result = await verifyAgentToken(verifyOptions);
  if (!result.ok) {
    return {
      ok: false,
      code: result.code,
      error: result.error,
    };
  }

  // One key, built literally, for both callbacks. Spreading the core result would hand them our
  // user id, the token's jti and its audience — the exact data this boundary exists to withhold.
  const identity: AgentIdentity = { email: result.email };

  let user: TUser | null | undefined;
  try {
    user = await resolveAccount(identity);
  } catch {
    return {
      ok: false,
      code: "RESOLVER_ERROR",
      error: "The account resolver threw. This is a fault in the resolver, not the token.",
    };
  }

  if (user !== null && user !== undefined) {
    return { ok: true, email: result.email, user, created: false };
  }

  let created: TUser;
  try {
    created = await createAccount(identity);
  } catch {
    // The thrown value is not echoed, for the same reason and with the same consequence as above:
    // it is untrusted text that usually carries a connection string.
    return {
      ok: false,
      code: "RESOLVER_ERROR",
      error: "The account creator threw. This is a fault in your createAccount, not the token.",
    };
  }

  return { ok: true, email: result.email, user: created, created: true };
}
