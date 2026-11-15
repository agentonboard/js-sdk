// Runs the cross-language vector gate under bun, for the "the same vectors pass outside Node"
// runtime-neutrality requirement in docs/adr/0002-sdk-runtime-contract-and-framework-subpaths.md.
//
// Best effort by design: a machine without bun skips loudly and succeeds, a machine with bun must
// not. `scripts/verify-sdk-vectors.mjs` is the one list and the one gate; this only chooses the
// runtime it runs on, so there is nothing here that can pass a vector bun would reject.
//
//   node scripts/test-vectors-bun.mjs

import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const GATE = path.resolve(__dirname, "verify-sdk-vectors.mjs");

/**
 * The absolute path to bun, or null when it is genuinely not installed.
 *
 * Not `spawnSync("bun", ...)` and a look at `.error`: on Windows, CreateProcess only appends
 * `.exe`, so a bare spawn cannot resolve `bun.cmd` or the extensionless script npm creates. Getting
 * this wrong is not a cosmetic problem — it reports a skip on a machine that has bun installed, so
 * a real failure under bun would exit 0.
 */
function findBun() {
  if (process.platform !== "win32") {
    return spawnSync("bun", ["--version"], { encoding: "utf8" }).error ? null : "bun";
  }

  for (const dir of (process.env.PATH || "").split(path.delimiter).filter(Boolean)) {
    let entries;
    try {
      entries = fs.readdirSync(dir);
    } catch {
      continue; // not a directory, or unreadable
    }
    const hit = entries.find((entry) => /^bun\.(exe|com|cmd|bat)$/i.test(entry));
    if (hit) return path.join(dir, hit);
  }
  return null;
}

/** A `.cmd`/`.bat` shim is a batch file, so it needs a shell; an `.exe` is spawned directly. */
function runBun(bun, args, stdio) {
  const needsShell = /\.(cmd|bat)$/i.test(bun);
  if (needsShell) {
    const command = `"${bun}" ${args.map((arg) => `"${arg}"`).join(" ")}`;
    return spawnSync(command, {
      encoding: "utf8",
      stdio: stdio ?? "pipe",
      shell: true,
    });
  }
  return spawnSync(bun, args, {
    encoding: "utf8",
    stdio: stdio ?? "pipe",
  });
}

const bun = findBun();

if (!bun) {
  console.log(
    "SKIPPED test:vectors:bun — bun is not on PATH.\n" +
      "         The vectors still ran under Node (`pnpm test:vectors`); install bun to cover the\n" +
      "         second runtime this gate exists to prove."
  );
  process.exit(0);
}

const version = runBun(bun, ["--version"]);
assert.ok(
  version.status === 0,
  `bun is on PATH at ${bun} but \`bun --version\` failed (exit ${version.status}): ${version.stderr ?? ""}`
);
console.log(`bun ${version.stdout.trim()} (${bun}) — running the shared vector gate\n`);

const run = runBun(bun, [GATE], "inherit");

if (run.signal) {
  console.error(`test:vectors:bun — bun was killed by ${run.signal}`);
  process.exit(1);
}

// Never 0 on a real failure: a vector that fails under bun is a finding about the SDK, not a skip.
process.exit(run.status ?? 1);
