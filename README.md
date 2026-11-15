# @agentonboard/sdk

Verify AI agent requests locally in your Next.js, Hono, or Express backend in three lines of TypeScript, without proxying traffic or locking your uptime to another auth server.

`@agentonboard/sdk` checks short-lived RS256 Agent Identity Tokens (`Authorization: Bearer <token>`) right inside your process against AgentOnboard's public JWKS, then passes the verified email to your own database lookup.

## Why teams verify locally with `@agentonboard/sdk`

Asking AI agents to click through OAuth screens or manage per-app API keys stalls automation before the first request. Hand-rolling JWT checks or delegating request routing to a proxy trades that friction for security bugs or vendor lock-in.

`@agentonboard/sdk` keeps verification inside your own boundary:

- **Your API stays online during our outages.** Public signing keys are cached in memory for up to 1 hour (`MAX_CACHED_KEY_SOURCES = 8`, 30s unknown-`kid` cooldown). If the JWKS endpoint goes unreachable on a warm process, the SDK keeps verifying against the last known good key set.
- **Runs anywhere `fetch` exists.** Built with one runtime dependency (`jose`) and zero Node.js built-ins (`node:fs`, `node:net`, `node:http`). The same artifact runs on Node.js, Bun, Deno, and Cloudflare Workers.
- **Your database owns permissions and signup.** `verifyAgentAccount` and the framework helpers are read-only by default: if `resolveAccount({ email })` returns `null` or `undefined`, the request stops with `403 ACCOUNT_REQUIRED`. Account creation happens only where you explicitly call `createAgentAccount`.
- **Compile-time and runtime guardrails.** Framework adapters strip `jwks`, `jwksUrl`, `fetchJwks`, and `token` from options at the TypeScript type level (`type-tests/adapter-options.ts`), pin `RS256` verification regardless of JWT header, and match `aud` by normalized hostname equality (`notes.com.evil.com` never matches `notes.com`).
- **Auditable behavior.** Every release passes 61 cross-language conformance vectors (`tests/fixtures/agent-token-v1.json`) across Node and Bun, plus an automated scan of `dist/` proving zero Node built-ins or framework imports.

## Install

```bash
npm install @agentonboard/sdk
```

```bash
pnpm add @agentonboard/sdk
```

## Add agent authentication in 2 minutes

### Next.js App Router (`@agentonboard/sdk/next`)

```ts
import { requireAgentAccount } from "@agentonboard/sdk/next";

export async function POST(request: Request) {
  const auth = await requireAgentAccount(request, {
    audience: "notes.com",
    resolveAccount: async ({ email }) =>
      (await db.user.findUnique({ where: { email: email.trim().toLowerCase() } }))?.id ?? null,
  });

  if (!auth.ok) return auth.response;

  return Response.json(await db.note.findMany({ where: { userId: auth.user } }));
}
```

### Hono (`@agentonboard/sdk/hono`)

```ts
import { requireAgentAccount } from "@agentonboard/sdk/hono";

app.post("/notes", async (c) => {
  const auth = await requireAgentAccount(c, {
    audience: "notes.com",
    resolveAccount: async ({ email }) =>
      (await db.user.findUnique({ where: { email: email.trim().toLowerCase() } }))?.id ?? null,
  });

  if (!auth.ok) return auth.response;

  return c.json(await db.note.findMany({ where: { userId: auth.user } }));
});
```

### Express (`@agentonboard/sdk/express`)

```ts
import { requireAgentAccount } from "@agentonboard/sdk/express";

app.post("/notes", async (req, res) => {
  const auth = await requireAgentAccount(req, res, {
    audience: "notes.com",
    resolveAccount: async ({ email }) =>
      (await db.user.findUnique({ where: { email: email.trim().toLowerCase() } }))?.id ?? null,
  });

  if (!auth.ok) return;

  res.json(await db.note.findMany({ where: { userId: auth.user } }));
});
```

Every binding maps rejections automatically: `401` for invalid/expired/mismatched tokens, `403 ACCOUNT_REQUIRED` when the human has no local account yet, and `500` when your `resolveAccount` callback throws or configuration is invalid.

## Core API (`@agentonboard/sdk`)

When you need custom key sources (`jwks` for tests/air-gapped environments, `fetchJwks` for custom proxies) or explicit account creation:

- `verifyAgentToken({ token, audience, issuer?, jwks?, fetchJwks?, clockToleranceSeconds? })`: non-throwing verifier returning `{ ok: true, email, sub, audience, expiresAt, jti }` or `{ ok: false, code, error }`.
- `verifyAgentAccount({ ...verifyOptions, resolveAccount })`: verifies the token first, then passes `{ email }` verbatim to `resolveAccount`.
- `createAgentAccount({ ...verifyOptions, resolveAccount, createAccount })`: explicit opt-in helper for your signup route; runs `createAccount({ email })` only after token verification succeeds and `resolveAccount` returns `null` or `undefined`.
- `normalizeEmail(email)`: trims and lowercases emails for case-insensitive database lookups.
- `normalizeAudience(input)`: extracts the normalized lowercase hostname (preserving port only for `localhost` and `127.0.0.1`).
- `VERIFY_ERROR_DESCRIPTIONS`: human-readable descriptions for all 9 core failure codes.

Read the full integration guides and API reference at [agentonboard.xyz/docs](https://agentonboard.xyz/docs).

## Verify the guarantees yourself

```bash
git clone https://github.com/agentonboard/js-sdk.git
cd js-sdk
pnpm install
pnpm build
pnpm test
pnpm test:vectors:bun
```

- `pnpm test:vectors` runs all 61 conformance cases against the built `dist/` bundle in Node.
- `pnpm test:vectors:bun` runs the same conformance suite in Bun.
- `pnpm test:types` compiles `type-tests/adapter-options.ts` with `tsc --strict` to confirm withheld adapter options fail to compile.
- `pnpm test:dist` scans every `.js`/`.cjs`/`.mjs` file in `dist/` (including `dist/frameworks/`) and asserts zero Node built-ins and zero framework imports.
- `pnpm sync:vectors:check` compares `tests/fixtures/agent-token-v1.json` against the canonical fixture in `agentonboard` when both repos sit side by side.

## Security

See [SECURITY.md](./SECURITY.md) for private vulnerability reporting.

## License

[MIT](./LICENSE)
