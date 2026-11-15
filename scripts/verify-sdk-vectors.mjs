// The reference gate for cross-language AgentOnboard SDK ports.
//
//   node scripts/verify-sdk-vectors.mjs [--vectors <path>] [--json]
//   bun scripts/verify-sdk-vectors.mjs
//
// The repo has no test runner, so this is plain node:assert, like scripts/test-spine-e2e.mjs.
// It exits non-zero on the first failing vector: this file is the acceptance gate for every
// language we or anyone else ships, so it must be trustworthy in CI, and a gate that reports
// "some passed" is not a gate.
//
// The key sets are served over loopback HTTP rather than handed to the verifier directly, because
// the SDK fetches its keys over the network in production and a fixture must exercise that path.
// scripts/test-spine-e2e.mjs passes a data: URI instead, which relies on undocumented platform
// behaviour; nothing here may do that.

import assert from "node:assert";
import fs from "node:fs";
import http from "node:http";
import { builtinModules } from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const DEFAULT_VECTORS = path.resolve(__dirname, "../tests/fixtures/agent-token-v1.json");
const SDK_PACKAGE = path.resolve(__dirname, "..");
const SDK_ENTRY = path.resolve(SDK_PACKAGE, "dist/index.js");

/**
 * The artifact under test has to be the one the source produces.
 *
 * `pnpm test:spine` builds first, so it cannot read a previous commit's `dist`. These two entry
 * points do not, and three builds in one command is slow, so this is not a build — it is a refusal
 * to test a build that predates its own source. `src/` is the whole of that comparison: the fixture
 * is read from disk rather than compiled, so a newer fixture needs no rebuild and is not part of it.
 *
 * The direction this can be wrong in is deliberate. Telling a developer to rebuild when a rebuild
 * was not needed costs a second. Testing a stale build costs a green gate over an implementation
 * that no longer exists, which is how this gate came to report passes about code it was no longer
 * running.
 */
function refuseStaleDist() {
  if (!fs.existsSync(SDK_ENTRY)) {
    console.error(
      `${path.relative(process.cwd(), SDK_ENTRY)} does not exist. dist/ is not committed, so the ` +
        `gate would be testing a previous build: run pnpm build first.`
    );
    process.exit(1);
  }

  const built = fs.statSync(SDK_ENTRY).mtimeMs;
  const stale = fs
    .readdirSync(path.join(SDK_PACKAGE, "src"), { withFileTypes: true, recursive: true })
    .filter((entry) => entry.isFile() && /\.tsx?$/.test(entry.name))
    .filter((entry) => fs.statSync(path.join(entry.parentPath ?? entry.path, entry.name)).mtimeMs > built)
    .map((entry) =>
      path.relative(process.cwd(), path.join(entry.parentPath ?? entry.path, entry.name)).split(path.sep).join("/")
    );

  if (stale.length > 0) {
    console.error(
      `dist/index.js is older than its own source (${stale.length} newer file(s), ` +
        `first: ${stale[0]}). This gate reads the built artifact, so it would be testing a ` +
        `previous build: run pnpm build first.`
    );
    process.exit(1);
  }
}

const argv = process.argv.slice(2);
let vectorsPath = DEFAULT_VECTORS;
let asJson = false;
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === "--vectors") {
    assert.ok(argv[i + 1], "--vectors needs a path");
    vectorsPath = path.resolve(argv[++i]);
  } else if (argv[i] === "--json") {
    asJson = true;
  } else {
    console.error(
      `unknown argument: ${argv[i]}\nusage: verify-sdk-vectors.mjs [--vectors <path>] [--json]`
    );
    process.exit(2);
  }
}

refuseStaleDist();

const { VERIFY_ERROR_DESCRIPTIONS, createAgentAccount, normalizeAudience, verifyAgentAccount, verifyAgentToken } =
  await import(pathToFileURL(SDK_ENTRY).href);
const { requireAgentAccount } = await import(
  pathToFileURL(path.join(path.dirname(SDK_ENTRY), "frameworks", "next.js")).href
);

class GateFailure extends Error {}

const runtime = typeof Bun === "undefined" ? `node ${process.version}` : `bun ${Bun.version}`;

let nameWidth = 0;
let current = null;
const groups = [];
const entries = [];

function startGroup(name) {
  current = { name, total: 0, passed: 0, fileChecks: 0 };
  groups.push(current);
  if (!asJson) console.log(`\n  ${name}`);
}

function row(label, name, detail) {
  current.total += 1;
  if (label === "ok") current.passed += 1;
  entries.push({ group: current.name, name, status: label, detail });
  if (!asJson) {
    console.log(`  ${label === "ok" ? "ok  " : "FAIL"}  ${name.padEnd(nameWidth)}  ${detail}`);
  }
}

/** One check, reported as a single row. `fileCheck` marks the whole-file checks in the summary. */
async function check(name, fn, fileCheck = false) {
  if (fileCheck) current.fileChecks += 1;
  try {
    row("ok", name, await fn());
  } catch (err) {
    row("FAIL", name, messageOf(err));
    throw new GateFailure(name);
  }
}

/** node:assert appends a multi-line diff to the message it was given; a table row wants one line. */
function messageOf(err) {
  return err instanceof Error ? err.message.split("\n")[0] : String(err);
}

/** Serves every key set in the fixture at /<keySet>/.well-known/jwks.json. */
async function serveKeySets(keySets) {
  const server = http.createServer((req, res) => {
    const [, keySet] = (req.url || "").split("/");
    const document = keySets[keySet];
    const body = document
      ? JSON.stringify(document)
      : JSON.stringify({ error: `this fixture carries no key set named "${keySet}"` });
    res.writeHead(document ? 200 : 404, {
      "content-type": "application/json",
      "content-length": Buffer.byteLength(body),
    });
    res.end(body);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    baseUrl: `http://127.0.0.1:${server.address().port}`,
    close: () =>
      new Promise((resolve) => {
        server.close(resolve);
        server.closeAllConnections?.();
      }),
  };
}

/**
 * The fixture has to be internally coherent before any of it means anything: every case must name
 * a key set that exists, every key set must publish the kid it claims, and every expected code must
 * be one the SDK actually defines. A fixture carrying a code no runtime defines would otherwise
 * "pass" a port that quietly invented a tenth code of its own.
 */
function checkFixtureCoherence(suite) {
  const keySetNames = Object.keys(suite.keys);
  assert.ok(keySetNames.length > 0, "this fixture carries no key sets");

  for (const [name, key] of Object.entries(suite.keys)) {
    const published = (key.jwks?.keys ?? []).filter((jwk) => jwk.kid === key.kid);
    assert.ok(published.length > 0, `key set "${name}" publishes no key with kid "${key.kid}"`);
    assert.strictEqual(
      published[0].alg,
      "RS256",
      `key set "${name}" publishes kid "${key.kid}" with alg "${published[0].alg}"`
    );
  }

  const names = new Set();
  for (const testCase of suite.verification) {
    assert.ok(
      keySetNames.includes(testCase.keySet),
      `case "${testCase.name}" names key set "${testCase.keySet}", which this fixture does not carry`
    );
    assert.ok(!names.has(testCase.name), `duplicate case name "${testCase.name}"`);
    names.add(testCase.name);
    if (testCase.expect.ok) {
      assert.strictEqual(
        typeof testCase.expect.email,
        "string",
        `case "${testCase.name}" expects a success but names no email to compare against`
      );
      continue;
    }
    assert.ok(
      Object.prototype.hasOwnProperty.call(VERIFY_ERROR_DESCRIPTIONS, testCase.expect.code),
      `case "${testCase.name}" expects code "${testCase.expect.code}", which is not one of the ` +
        `codes this SDK defines: ${Object.keys(VERIFY_ERROR_DESCRIPTIONS).join(", ")}`
    );
  }

  return (
    `${suite.verification.length} expected codes, all published; ` +
    `${keySetNames.length} key sets, each publishing its own kid`
  );
}

/**
 * The two codes the account layer adds, which are not token codes and are published separately. Both
 * account functions report these and the core's nine — the creating one adds no code of its own, so
 * opting in to account creation is not a new vocabulary.
 */
const ACCOUNT_CODES = ["ACCOUNT_REQUIRED", "RESOLVER_ERROR"];

/** The status the fixture's own rule assigns to a code, which is what every case is checked against. */
function statusForCode(mapping, code) {
  const override = mapping.overrides.find((entry) => entry.code === code);
  return override ? override.status : mapping.default;
}

/**
 * The account layer and the status mapping have to be internally coherent too, and for the same
 * reason: a fixture that named a status no rule produces, or a resolver shape a port cannot execute,
 * would let a port that answered 401 for ACCOUNT_REQUIRED pass every other case and this one.
 */
function checkAccountCoherence(suite) {
  const mapping = suite.statusMapping;
  assert.ok(mapping, "this fixture carries no statusMapping");
  assert.strictEqual(mapping.default, 401, "the uniform status is 401, or the map is not this SDK's");
  assert.ok(Array.isArray(mapping.overrides) && mapping.overrides.length > 0, "no status overrides");

  const overridden = new Set();
  for (const entry of mapping.overrides) {
    assert.ok(
      !overridden.has(entry.code),
      `statusMapping overrides "${entry.code}" twice; which one applies is unanswerable`
    );
    overridden.add(entry.code);
    assert.ok(
      Object.prototype.hasOwnProperty.call(VERIFY_ERROR_DESCRIPTIONS, entry.code) ||
        ACCOUNT_CODES.includes(entry.code),
      `statusMapping overrides "${entry.code}", which is not a code this SDK publishes`
    );
    assert.ok(
      Number.isInteger(entry.status) && entry.status >= 400 && entry.status < 600,
      `statusMapping gives "${entry.code}" the status ${entry.status}`
    );
  }
  // The rule is the whole mapping, so it has to cover every code this runtime knows. A port that
  // adds a tenth code is told to answer the default; a fixture that quietly left a code out of the
  // rule would leave it to the port's own guess.
  for (const code of Object.keys(VERIFY_ERROR_DESCRIPTIONS)) {
    assert.ok(
      statusForCode(mapping, code) >= 400,
      `the mapping assigns no status to published code "${code}"`
    );
  }

  assert.ok(Array.isArray(suite.account) && suite.account.length > 0, "this fixture carries no account cases");
  assert.ok(
    Array.isArray(suite.accountCreate) && suite.accountCreate.length > 0,
    "this fixture carries no accountCreate cases, so the creating function is pinned by nothing"
  );
  const names = new Set(suite.verification.map((testCase) => testCase.name));
  const seen = new Set();
  // Both arrays are checked by the same rules, because a case is a case: it names a token this file
  // carries, it describes callbacks a port could actually execute, it says how many times each one
  // runs, and its status is the one statusMapping assigns to its code. A create case is only
  // exempt from one of them — the `created` field, which only exists on its success arm.
  for (const testCase of [...suite.account, ...suite.accountCreate]) {
    const creating = testCase.creator !== undefined;
    const label = `${creating ? "accountCreate" : "account"} case "${testCase.name}"`;
    assert.ok(names.has(testCase.token), `${label} names token "${testCase.token}", which is not a verification case`);
    assert.ok(!seen.has(testCase.name), `duplicate account case name "${testCase.name}"`);
    seen.add(testCase.name);
    for (const callback of ["resolver", ...(creating ? ["creator"] : [])]) {
      const described = testCase[callback];
      assert.ok(
        ["user", "null", "undefined", "throw"].includes(described.returns),
        `${label} describes its ${callback} as "${described.returns}", which no port could execute`
      );
      const returnsAValue = described.returns === "user";
      assert.strictEqual(
        "value" in described,
        returnsAValue,
        `${label} ${returnsAValue ? `names no value for its ${callback} to return` : `names a ${callback} value it never returns`}`
      );
    }
    for (const field of ["resolverCalls", "createCalls"]) {
      if (field === "createCalls" && !creating) continue;
      assert.strictEqual(
        typeof testCase.expect[field],
        "number",
        `${label} does not say how many times the ${field === "resolverCalls" ? "resolver" : "creator"} runs`
      );
    }
    if (testCase.expect.ok) {
      assert.ok("user" in testCase.expect, `${label} expects a success but names no user to compare against`);
      assert.strictEqual(testCase.expect.code, undefined, `a success cannot carry code ${testCase.expect.code}`);
      assert.strictEqual(testCase.expect.status, undefined, "a success has no response to carry a status");
      if (creating) {
        // The whole reason the creating function reports a boolean: "signed in" and "made an
        // account" are different events and a port has to be able to tell them apart.
        assert.strictEqual(
          typeof testCase.expect.created,
          "boolean",
          `${label} expects a success but does not say whether the account was created`
        );
      }
      continue;
    }
    assert.strictEqual(testCase.expect.created, undefined, `a rejection cannot carry created=${testCase.expect.created}`);
    assert.ok(
      Object.prototype.hasOwnProperty.call(VERIFY_ERROR_DESCRIPTIONS, testCase.expect.code) ||
        ACCOUNT_CODES.includes(testCase.expect.code),
      `${label} expects code "${testCase.expect.code}", which no runtime publishes`
    );
    assert.strictEqual(
      testCase.expect.status,
      statusForCode(mapping, testCase.expect.code),
      `${label} expects ${testCase.expect.code} at ${testCase.expect.status}, ` +
        `which is not the status statusMapping gives it`
    );
  }

  return (
    `${suite.account.length} account cases and ${suite.accountCreate.length} accountCreate cases, ` +
      `every token, callback and status coherent; ` +
    `${mapping.default} by default with ${mapping.overrides.length} overrides ` +
      `(${mapping.overrides.map((entry) => `${entry.code}->${entry.status}`).join(", ")})`
  );
}

/**
 * One of the Relying Party's callbacks, built from how the case describes it, recording every identity it
 * was handed so the case can say what crossed the boundary.
 *
 * `async` decides only how the value arrives. The function is the same in every leg that uses it: a
 * case that says the lookup throws has to throw wherever the case is checked, or the thing being
 * checked is a different situation from the one the case describes.
 */
function callbackFor(described, seen) {
  return async (identity) => {
    seen.push(identity);
    const { returns: how, value, message, async: isAsync } = described;
    if (how === "throw") throw new Error(message);
    const answer = how === "user" ? value : how === "null" ? null : undefined;
    return isAsync ? Promise.resolve(answer) : answer;
  };
}

/**
 * One account case, executed twice: once against `verifyAgentAccount` for the outcome, and once
 * through the framework binding for the status and the response body. The status is the whole point
 * of the case, and it only exists in the second one — a port that maps ACCOUNT_REQUIRED to 401
 * passes every verification case in this file.
 */
async function checkAccountCase(testCase, suite, jwksBase) {
  const source = suite.verification.find((entry) => entry.name === testCase.token);
  const options = {
    token: source.token,
    audience: source.audience,
    issuer: source.issuer,
    jwksUrl: `${jwksBase}/${source.keySet}/.well-known/jwks.json`,
  };

  const observed = [];
  /**
   * The Relying Party's lookup, built from the case. It is the same function for both legs — a case that
   * says the lookup throws has to throw in the framework leg too, or the status being checked is a
   * status for a different situation. `async` decides only how the value arrives.
   */
  const resolver = callbackFor(testCase.resolver, observed);

  let outcome;
  try {
    outcome = await verifyAgentAccount({ ...options, resolveAccount: resolver });
  } catch (err) {
    throw new Error(
      `verifyAgentAccount threw instead of returning a failure (${err && err.message}). The account ` +
        `layer never throws: a resolver that throws is RESOLVER_ERROR.`
    );
  }

  assert.ok(
    outcome && typeof outcome.ok === "boolean",
    `expected an object with a boolean ok, got ${JSON.stringify(outcome)}`
  );
  assert.strictEqual(
    outcome.ok,
    testCase.expect.ok,
    `expected ok=${testCase.expect.ok}, got ok=${outcome.ok} (${outcome.error ?? "no error message"})`
  );
  assert.strictEqual(
    observed.length,
    testCase.expect.resolverCalls,
    `the resolver ran ${observed.length} times; the case says ${testCase.expect.resolverCalls}. A ` +
      `resolver that runs for a token that did not verify will provision from an unproved email, ` +
      `and one that runs more than once per request is a cache this layer does not have.`
  );
  if (testCase.expect.resolverIdentity) {
    assert.deepStrictEqual(
      observed[0],
      testCase.expect.resolverIdentity,
      `the resolver received ${JSON.stringify(observed[0])}. A token claim or an internal user id ` +
        `crossing into their callback is what this boundary exists to withhold.`
    );
  }

  if (testCase.expect.ok) {
    assert.strictEqual(outcome.code, undefined, `a success carried the code ${outcome.code}`);
    assert.strictEqual(outcome.error, undefined, `a success carried the error "${outcome.error}"`);
    assert.strictEqual(outcome.email, testCase.expect.email, "the verified email on a success");
    assert.strictEqual(outcome.user, testCase.expect.user, "the Relying Party's own user id");
    assert.deepStrictEqual(
      Object.keys(outcome).sort(),
      ["email", "ok", "user"],
      `a success carried ${JSON.stringify(Object.keys(outcome))}; only the Relying Party's own id crosses`
    );
  } else {
    assert.strictEqual(
      outcome.code,
      testCase.expect.code,
      `expected code ${testCase.expect.code}, got ${outcome.code ?? "(none)"}`
    );
    assert.ok(
      typeof outcome.error === "string" && outcome.error.length > 0,
      "a rejection must carry a message a human can be shown"
    );
    for (const fragment of testCase.expect.errorExcludes ?? []) {
      assert.ok(
        !outcome.error.includes(fragment),
        `the failure message carries "${fragment}": ${outcome.error}. A thrown value is untrusted ` +
          `text that usually holds a connection string, and it lands in an error aggregator.`
      );
    }
  }

  // The framework leg. A synthetic header bag rather than a framework request, because the binding
  // is typed structurally and reads exactly one header.
  const request = {
    headers: { get: (name) => (name === "Authorization" ? `Bearer ${source.token}` : undefined) },
  };
  const answered = await requireAgentAccount(request, {
    audience: source.audience,
    issuer: source.issuer,
    jwksUrl: options.jwksUrl,
    resolveAccount: callbackFor(testCase.resolver, []),
  });

  if (testCase.expect.ok) {
    assert.strictEqual(answered.ok, true, `the binding rejected a case the account layer accepted`);
    assert.strictEqual(answered.user, testCase.expect.user, "the user id the handler receives");
    return "ok";
  }
  assert.strictEqual(answered.ok, false, "the binding accepted a case the account layer rejected");
  assert.strictEqual(
    answered.response.status,
    testCase.expect.status,
    `answered ${answered.response.status}, expected ${testCase.expect.status} for ${testCase.expect.code}`
  );
  const body = await answered.response.json();
  assert.strictEqual(body.code, testCase.expect.code, "the code in the response body");
  for (const fragment of testCase.expect.errorExcludes ?? []) {
    assert.ok(
      !JSON.stringify(body).includes(fragment),
      `the response an unauthenticated caller can read carries "${fragment}": ${JSON.stringify(body)}`
    );
  }
  return `${answered.response.status} ${body.code}`;
}

/**
 * One `accountCreate` case, executed against `createAgentAccount`.
 *
 * There is no framework leg, and that is not an omission: the bindings wrap `verifyAgentAccount`,
 * so a creating Relying Party calls this function in its own route handler and answers its own responses.
 * The status is therefore checked against `statusMapping` here rather than read off a binding — a
 * port still has to agree with the rule, and this is where it is asked to.
 *
 * The order of the three checks is the order the guarantees stack: the token first (neither callback
 * runs for a forged one), then the lookup (a hit never reaches the creator), then the creator (a
 * throw is RESOLVER_ERROR and its value is not echoed).
 */
async function checkAccountCreateCase(testCase, suite, jwksBase) {
  const source = suite.verification.find((entry) => entry.name === testCase.token);
  const options = {
    token: source.token,
    audience: source.audience,
    issuer: source.issuer,
    jwksUrl: `${jwksBase}/${source.keySet}/.well-known/jwks.json`,
  };

  const resolved = [];
  const requested = [];
  let outcome;
  try {
    outcome = await createAgentAccount({
      ...options,
      resolveAccount: callbackFor(testCase.resolver, resolved),
      createAccount: callbackFor(testCase.creator, requested),
    });
  } catch (err) {
    throw new Error(
      `createAgentAccount threw instead of returning a failure (${err && err.message}). The account ` +
        `layer never throws: a resolver or a creator that throws is RESOLVER_ERROR.`
    );
  }

  assert.ok(
    outcome && typeof outcome.ok === "boolean",
    `expected an object with a boolean ok, got ${JSON.stringify(outcome)}`
  );
  assert.strictEqual(
    outcome.ok,
    testCase.expect.ok,
    `expected ok=${testCase.expect.ok}, got ok=${outcome.ok} (${outcome.error ?? "no error message"})`
  );
  assert.strictEqual(
    resolved.length,
    testCase.expect.resolverCalls,
    `the resolver ran ${resolved.length} times; the case says ${testCase.expect.resolverCalls}. A ` +
      `resolver that runs for a token that did not verify will provision from an unproved email, ` +
      `and one that runs more than once per request is a cache this layer does not have.`
  );
  assert.strictEqual(
    requested.length,
    testCase.expect.createCalls,
    `the creator ran ${requested.length} times; the case says ${testCase.expect.createCalls}. Calling ` +
      `it on a hit mints a second account for a human who already has one, on every request.`
  );
  for (const [field, expectField, what] of [
    ["resolverIdentity", "resolverIdentity", "resolver"],
    ["createIdentity", "createIdentity", "creator"],
  ]) {
    if (!testCase.expect[expectField]) continue;
    const seen = field.startsWith("resolver") ? resolved : requested;
    assert.deepStrictEqual(
      seen[0],
      testCase.expect[expectField],
      `the ${what} received ${JSON.stringify(seen[0])}. A token claim or an internal user id ` +
        `crossing into their callback is what this boundary exists to withhold.`
    );
  }

  if (testCase.expect.ok) {
    assert.strictEqual(outcome.code, undefined, `a success carried the code ${outcome.code}`);
    assert.strictEqual(outcome.error, undefined, `a success carried the error "${outcome.error}"`);
    assert.strictEqual(outcome.email, testCase.expect.email, "the verified email on a success");
    assert.strictEqual(outcome.user, testCase.expect.user, "the Relying Party's own user id");
    assert.strictEqual(
      outcome.created,
      testCase.expect.created,
      `the outcome reported created=${outcome.created}; the case says ${testCase.expect.created}. ` +
        `"Signed in" and "made an account" are different events and an audit log cannot tell them ` +
        `apart without this field.`
    );
    assert.deepStrictEqual(
      Object.keys(outcome).sort(),
      ["created", "email", "ok", "user"],
      `a success carried ${JSON.stringify(Object.keys(outcome))}; only the Relying Party's own id crosses`
    );
    return `created=${outcome.created}`;
  }

  assert.strictEqual(
    outcome.code,
    testCase.expect.code,
    `expected code ${testCase.expect.code}, got ${outcome.code ?? "(none)"}`
  );
  assert.strictEqual(outcome.created, undefined, `a rejection carried created=${outcome.created}`);
  assert.ok(
    typeof outcome.error === "string" && outcome.error.length > 0,
    "a rejection must carry a message a human can be shown"
  );
  for (const fragment of testCase.expect.errorExcludes ?? []) {
    assert.ok(
      !outcome.error.includes(fragment),
      `the failure message carries "${fragment}": ${outcome.error}. A thrown value is untrusted ` +
        `text that usually holds a connection string, and it lands in an error aggregator.`
    );
  }
  const status = statusForCode(suite.statusMapping, outcome.code);
  assert.strictEqual(
    status,
    testCase.expect.status,
    `statusMapping gives ${outcome.code} ${status}; the case says ${testCase.expect.status}`
  );
  return `${status} ${outcome.code}`;
}

async function checkVerificationCase(testCase, jwksBase) {
  let result;
  try {
    result = await verifyAgentToken({
      token: testCase.token,
      audience: testCase.audience,
      issuer: testCase.issuer,
      jwksUrl: `${jwksBase}/${testCase.keySet}/.well-known/jwks.json`,
    });
  } catch (err) {
    throw new Error(
      `verifyAgentToken threw instead of returning a failure code (${err && err.message}). ` +
        `Never throwing is part of this contract.`
    );
  }

  assert.ok(
    result && typeof result.ok === "boolean",
    `expected an object with a boolean ok, got ${JSON.stringify(result)}`
  );
  assert.strictEqual(
    result.ok,
    testCase.expect.ok,
    `expected ok=${testCase.expect.ok}, got ok=${result.ok} (${result.error ?? "no error message"})`
  );

  if (testCase.expect.ok) {
    assert.strictEqual(result.code, undefined, `a success carried the failure code ${result.code}`);
    assert.strictEqual(result.error, undefined, `a success carried the error "${result.error}"`);
    assert.strictEqual(result.email, testCase.expect.email, "verified email");
    assert.strictEqual(
      result.audience,
      normalizeAudience(testCase.audience),
      "a success must report the normalized audience"
    );
    const detail = [`email=${result.email}`];
    for (const field of ["sub", "userId", "jti"]) {
      if (!(field in testCase.expect)) continue;
      assert.strictEqual(result[field], testCase.expect[field], field);
      if (field === "jti") detail.push(`jti=${result[field]}`);
    }
    return detail.join(" ");
  }

  assert.strictEqual(
    result.code,
    testCase.expect.code,
    `expected code ${testCase.expect.code}, got ${result.code ?? "(none)"}`
  );
  assert.strictEqual(result.email, undefined, `a rejected token yielded the email "${result.email}"`);
  // Every field a success carries, named on a rejection too: a rejected token that still handed back
  // a user id or an audience is a rejection a caller can read identity out of.
  for (const field of ["sub", "userId", "jti", "audience", "expiresAt"]) {
    assert.strictEqual(result[field], undefined, `a rejected token yielded ${field}`);
  }
  assert.ok(
    typeof result.error === "string" && result.error.length > 0,
    "a rejection must carry a human-readable error message"
  );
  return result.code;
}

/**
 * The portability gate, and the one that needs no second runtime: the published SDK must not reach
 * for a Node builtin, or it stops running on an edge worker, in Deno, or in a browser. It reads the
 * built artifact, because that artifact is what a Relying Party installs.
 *
 * It matches bare specifiers as well as "node:"-prefixed ones on purpose. tsup rewrites
 * `import fs from "node:fs"` to `import fs from "fs"`, so a scan for "node:" alone reports a clean
 * build on an artifact that opens the filesystem — and a gate that cannot fail is not a gate.
 *
 * It walks recursively for the same reason. `dist/frameworks/` is a directory: the non-recursive
 * version of this scan never opened the three published bindings, and reported "no Node builtin"
 * on an artifact whose Next adapter imported `node:fs`. Paths are relative to `dist` so a hit names
 * the file it came from.
 */
function checkPortability() {
  const dist = path.dirname(SDK_ENTRY);
  const builtins = new Set(builtinModules.map((name) => name.replace(/^node:/, "")));
  const specifiers = /(?:\bfrom|\bimport|\brequire)\s*\(?\s*["']([^"'\n]+)["']/g;
  const files = [];
  const nodeOnly = [];
  const unexpected = [];

  const walk = (dir, prefix) => {
    for (const entry of fs
      .readdirSync(dir, { withFileTypes: true })
      .sort((a, b) => a.name.localeCompare(b.name))) {
      const name = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        walk(path.join(dir, entry.name), name);
        continue;
      }
      if (!/\.(js|cjs|mjs)$/.test(entry.name)) continue;
      files.push(name);
      const text = fs.readFileSync(path.join(dir, entry.name), "utf8");
      for (const hit of new Set([...text.matchAll(specifiers)].map((match) => match[1]))) {
        if (builtins.has(hit.replace(/^node:/, ""))) nodeOnly.push(`${name}: ${hit}`);
        else if (!hit.startsWith("jose") && !hit.startsWith(".")) unexpected.push(`${name}: ${hit}`);
      }
    }
  };

  walk(dist, "");
  assert.ok(files.length > 0, `no built JavaScript found in ${dist}`);
  assert.deepStrictEqual(
    nodeOnly,
    [],
    `built output imports a Node builtin (${nodeOnly.join(", ")}). The SDK's runtime contract is ` +
      `no filesystem and no socket ownership, so it must ride on a host runtime's fetch alone.`
  );
  assert.deepStrictEqual(
    unexpected,
    [],
    `built output depends on something other than jose (${unexpected.join(", ")})`
  );
  return files.join(", ");
}

function report(suite, jwksBase, failure) {
  const passed = !failure;
  const vectors =
    suite.audienceNormalization.length +
    suite.verification.length +
    suite.account.length +
    suite.accountCreate.length;
  const fileChecks = groups.reduce((total, group) => total + group.fileChecks, 0);

  if (asJson) {
    console.log(
      JSON.stringify(
        {
          pass: passed,
          fixture: path.relative(process.cwd(), vectorsPath),
          formatVersion: suite.formatVersion,
          sdk: path.relative(process.cwd(), SDK_ENTRY),
          runtime,
          jwksBase,
          stoppedAt: failure ?? null,
          groups,
          entries,
        },
        null,
        2
      )
    );
    return;
  }

  console.log(`\n  ${"─".repeat(60)}`);
  if (passed) {
    console.log(
      `  PASS — ${vectors} vectors, ${fileChecks} file checks, ` +
        `${Object.keys(suite.keys).length} key sets, formatVersion ${suite.formatVersion}\n`
    );
    return;
  }
  const stopped = entries.find((entry) => entry.status === "FAIL");
  console.log(
    `  FAIL — stopped at ${stopped ? stopped.name : failure}, after ${entries.length - 1} checks\n`
  );
}

async function main() {
  const suite = JSON.parse(fs.readFileSync(vectorsPath, "utf8"));
  assert.strictEqual(
    suite.formatVersion,
    1,
    `this fixture declares formatVersion ${suite.formatVersion}; the harness understands 1`
  );

  nameWidth = Math.max(
    "expected codes are published".length,
    "the account layer and the status map agree".length,
    "built output is runtime-agnostic".length,
    ...suite.verification.map((testCase) => testCase.name.length),
    ...suite.account.map((testCase) => testCase.name.length),
    ...suite.accountCreate.map((testCase) => testCase.name.length),
    ...suite.audienceNormalization.map((testCase) => JSON.stringify(testCase.input).length)
  );

  const jwks = await serveKeySets(
    Object.fromEntries(Object.entries(suite.keys).map(([name, key]) => [name, key.jwks]))
  );

  if (!asJson) {
    console.log("============================================================");
    console.log(`  AgentOnboard cross-language vectors — formatVersion ${suite.formatVersion}`);
    console.log("============================================================");
    console.log(`  fixture  ${path.relative(process.cwd(), vectorsPath)}`);
    console.log(`  sdk      ${path.relative(process.cwd(), SDK_ENTRY)}`);
    console.log(`  runtime  ${runtime}`);
    console.log(`  jwks     ${jwks.baseUrl}/<keySet>/.well-known/jwks.json`);
  }

  let failure = null;
  try {
    startGroup("[1/6] the fixture is coherent, and every expected code is published");
    await check("expected codes are published", () => checkFixtureCoherence(suite), true);
    await check(
      "the account layer and the status map agree",
      () => checkAccountCoherence(suite),
      true
    );

    startGroup("[2/6] audience normalization");
    for (const testCase of suite.audienceNormalization) {
      await check(JSON.stringify(testCase.input), () => {
        const actual = normalizeAudience(testCase.input);
        assert.strictEqual(
          actual,
          testCase.expected,
          `normalizeAudience(${JSON.stringify(testCase.input)}) returned ${JSON.stringify(actual)}`
        );
        return `-> ${JSON.stringify(actual)}`;
      });
    }

    startGroup("[3/6] verification");
    for (const testCase of suite.verification) {
      await check(testCase.name, () => checkVerificationCase(testCase, jwks.baseUrl));
    }

    startGroup("[4/6] the account layer, and the status each code is answered with");
    for (const testCase of suite.account) {
      await check(testCase.name, () => checkAccountCase(testCase, suite, jwks.baseUrl));
    }

    startGroup("[5/6] account creation: the opt-in, and every way it goes wrong");
    for (const testCase of suite.accountCreate) {
      await check(testCase.name, () => checkAccountCreateCase(testCase, suite, jwks.baseUrl));
    }

    startGroup("[6/6] portability: no Node builtins in the published SDK");
    await check("built output is runtime-agnostic", () => checkPortability(), true);
  } catch (err) {
    failure = err instanceof GateFailure ? err.message : messageOf(err);
    if (!(err instanceof GateFailure)) console.error(err);
  } finally {
    await jwks.close();
  }

  report(suite, jwks.baseUrl, failure);
  if (failure) process.exitCode = 1;
}

try {
  await main();
} catch (err) {
  console.error(messageOf(err));
  process.exitCode = 1;
}
