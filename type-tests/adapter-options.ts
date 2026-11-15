/**
 * A type-level fixture, not a runtime one. It exists because the repo has no `tsc` gate anywhere,
 * which means nothing stops someone adding `jwksUrl` back to the `Omit` list in `adapter.ts` and
 * silently handing every Relying Party a total authentication bypass plus an SSRF primitive.
 *
 * Every call below the first MUST compile is expected to fail, each marked
 * `// EXPECTED ERROR: <option>`. `scripts/test-types.mjs` runs this through `tsc` and checks the
 * shape of the result: one excess-property error on the line that writes each withheld option, and
 * nothing else anywhere in the file — which is what makes the last call still compile.
 *
 * The exclusion is compile-time only, and the runtime leg of that split is a check in the harness.
 */
import { requireAgentAccount } from "../dist/frameworks/next.js";

declare const request: { headers: { get(name: string): string | null | undefined } };

// EXPECTED ERROR: jwks
requireAgentAccount(request, {
  audience: "notes.com",
  resolveAccount: () => "u",
  jwks: { keys: [] },
});

// EXPECTED ERROR: jwksUrl
requireAgentAccount(request, {
  audience: "notes.com",
  resolveAccount: () => "u",
  jwksUrl: "https://attacker.example/keys",
});

// EXPECTED ERROR: fetchJwks
requireAgentAccount(request, {
  audience: "notes.com",
  resolveAccount: () => "u",
  fetchJwks: async () => ({ keys: [] }),
});

// EXPECTED ERROR: token
requireAgentAccount(request, {
  audience: "notes.com",
  token: "whatever",
  resolveAccount: () => "u",
});

// MUST COMPILE — the shortcut still works, and `issuer` is still available for a self-hosted
// issuer, which is a permanent requirement rather than an option to close off.
requireAgentAccount(request, {
  audience: "notes.com",
  issuer: "https://sso.acme.example",
  resolveAccount: ({ email }) => ({ id: email }),
  onFailure: (failure) =>
    new Response(failure.code, { status: failure.code === "ACCOUNT_REQUIRED" ? 403 : 401 }),
});
