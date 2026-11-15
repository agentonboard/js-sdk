import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const typeFixture = path.resolve(repoRoot, "type-tests/adapter-options.ts");
const tsc = path.resolve(repoRoot, "node_modules/typescript/bin/tsc");

assert.ok(
  fs.existsSync(path.resolve(repoRoot, "dist/frameworks/next.d.ts")),
  "dist/frameworks/next.d.ts is missing; run `pnpm build` first"
);
assert.ok(fs.existsSync(tsc), `tsc is missing at ${tsc}; run \`pnpm install\``);

const run = spawnSync(
  process.execPath,
  [
    tsc,
    "--strict",
    "--noEmit",
    "--module",
    "nodenext",
    "--moduleResolution",
    "nodenext",
    "--target",
    "es2022",
    "--lib",
    "es2022,dom",
    path.basename(typeFixture),
  ],
  { cwd: path.dirname(typeFixture), encoding: "utf8" }
);

const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
const name = path.basename(typeFixture);
const errors = output.split(/\r?\n/).filter((line) => line.trim().startsWith(`${name}(`));
const at = (n) => errors.filter((line) => new RegExp(`^${name}\\(${n},`).test(line));

const fixtureLines = fs.readFileSync(typeFixture, "utf8").split(/\r?\n/);
const expected = fixtureLines.flatMap((line, index) => {
  const marker = line.match(/^\s*\/\/ EXPECTED ERROR: (\w+)\s*$/);
  if (!marker) return [];
  const property = new RegExp(`^\\s*${marker[1]}\\s*:`);
  return [
    {
      option: marker[1],
      line: fixtureLines.findIndex((l, i) => i > index && property.test(l)) + 1,
    },
  ];
});

assert.deepStrictEqual(
  expected.map((e) => e.option),
  ["jwks", "jwksUrl", "fetchJwks", "token"],
  "type-tests/adapter-options.ts no longer marks one compile error per withheld option"
);
assert.ok(
  expected.every((e) => e.line > 0),
  "a marker in type-tests/adapter-options.ts names an option it never writes"
);

const excess =
  /is not assignable to type 'RequireAgentAccountOptions|Object literal may only specify known properties/;
for (const { option, line } of expected) {
  const reported = at(line);
  assert.ok(
    reported.length > 0 && reported.every((l) => excess.test(l)),
    `a caller-supplied \`${option}\` is not a compile error on line ${line} ` +
      `(${reported[0]?.replace(`^${name}`, "").trim() ?? "no error reported"})`
  );
}

assert.strictEqual(
  errors.length,
  expected.length,
  `tsc reported ${errors.length} errors, expected ${expected.length}:\n${output.trim()}`
);

console.log(`PASS — ${expected.length} withheld adapter options refused at compile time, valid call compiles`);
