# @agentonboard/sdk

TypeScript/JavaScript Relying Party SDK for [AgentOnboard](https://agentonboard.xyz) — verify 5-minute RS256 Agent Identity Tokens locally against public JWKS, resolve App Accounts, and protect Next.js, Hono, or Express routes.

Runtime-neutral (`Node.js`, `Bun`, `Deno`, `Cloudflare Workers`). Zero Node.js built-ins; single runtime dependency (`jose`).

## Install

```bash
npm install @agentonboard/sdk
```

```bash
pnpm add @agentonboard/sdk
```

## Quickstart

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
  return c.json({ user: auth.user });
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
  res.json({ user: auth.user });
});
```

### Core Functions (`@agentonboard/sdk`)

- `verifyAgentToken({ token, audience, issuer? })` — non-throwing JWT verification returning `{ ok: true, email, sub, audience, expiresAt, jti }` or `{ ok: false, code, error }`.
- `verifyAgentAccount({ token, audience, resolveAccount })` — verifies the token, then calls `resolveAccount({ email })`; returns `ACCOUNT_REQUIRED` (403) when missing.
- `createAgentAccount({ token, audience, resolveAccount, createAccount })` — explicit opt-in signup helper that calls `createAccount({ email })` only when `resolveAccount` returns `null` or `undefined`.
- `normalizeEmail(email)` / `normalizeAudience(input)` / `VERIFY_ERROR_DESCRIPTIONS`.

Full documentation: [agentonboard.xyz/docs](https://agentonboard.xyz/docs)

## Development & Conformance

```bash
pnpm install
pnpm build
pnpm test
pnpm test:vectors:bun
```

- `tests/fixtures/agent-token-v1.json` is synced from the canonical `agentonboard` conformance fixture (`pnpm sync:vectors:check`).
- `pnpm test:dist` verifies the built `dist/` files import zero Node.js built-ins and zero framework packages.
- `pnpm test:types` verifies withheld adapter options (`jwks`, `jwksUrl`, `fetchJwks`, `token`) fail at compile time.

## Security

See [SECURITY.md](./SECURITY.md) for private vulnerability reporting.

## License

[MIT](./LICENSE)
