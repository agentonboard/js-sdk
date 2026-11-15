import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { builtinModules } from "node:module";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const distDir = path.resolve(repoRoot, "dist");

assert.ok(fs.existsSync(distDir), "dist/ does not exist; run `pnpm build` first");

const builtins = new Set(builtinModules.map((name) => name.replace(/^node:/, "")));
const specifiers = /(?:\bfrom|\bimport|\brequire)\s*\(?\s*["']([^"'\n]+)["']/g;

function moduleSpecifiersIn(dir, prefix = "") {
  const entries = fs
    .readdirSync(dir, { withFileTypes: true })
    .sort((a, b) => a.name.localeCompare(b.name));
  const files = [];
  const found = [];
  for (const entry of entries) {
    const name = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      const nested = moduleSpecifiersIn(path.join(dir, entry.name), name);
      files.push(...nested.files);
      found.push(...nested.found);
      continue;
    }
    if (!/\.(js|cjs|mjs)$/.test(entry.name)) continue;
    files.push(name);
    const text = fs.readFileSync(path.join(dir, entry.name), "utf8");
    for (const hit of new Set([...text.matchAll(specifiers)].map((m) => m[1]))) {
      found.push({ file: name, name: hit });
    }
  }
  return { files, found };
}

const nodeBuiltinsIn = (dir) =>
  moduleSpecifiersIn(dir).found
    .filter(({ name }) => builtins.has(name.replace(/^node:/, "")))
    .map(({ file, name }) => `${file}: ${name}`);

const FRAMEWORKS = /^(next|hono|express)\b|\/(next|hono|express)$/;
const frameworkImportsIn = (dir) =>
  moduleSpecifiersIn(dir).found
    .filter(({ name }) => FRAMEWORKS.test(name))
    .map(({ file, name }) => `${file}: ${name}`);

// 1. Framework bindings import no framework
const frameworksDir = path.join(distDir, "frameworks");
const { files: frameworkFiles } = moduleSpecifiersIn(frameworksDir);
const frameworkish = frameworkImportsIn(frameworksDir);
assert.deepStrictEqual(
  frameworkish,
  [],
  `a framework binding imports its framework (${frameworkish.join(", ")})`
);

// 2. Built SDK reaches for no Node builtin and depends only on jose + relative paths
const { files: distFiles, found } = moduleSpecifiersIn(distDir);
assert.ok(distFiles.length > 0, `no built JS found in ${distDir}`);
const nodeOnly = found
  .filter(({ name }) => builtins.has(name.replace(/^node:/, "")))
  .map(({ file, name }) => `${file}: ${name}`);
const other = found
  .filter(({ name }) => !name.startsWith(".") && !name.startsWith("jose"))
  .map(({ file, name }) => `${file}: ${name}`);
assert.deepStrictEqual(nodeOnly, [], `built output imports a Node builtin (${nodeOnly.join(", ")})`);
assert.deepStrictEqual(other, [], `built output depends on something other than jose (${other.join(", ")})`);

// 3. Control: prove the scans catch both node:-prefixed and bare builtins plus framework imports
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "aon-js-sdk-scan-"));
try {
  fs.cpSync(distDir, scratch, { recursive: true });
  fs.appendFileSync(
    path.join(scratch, "frameworks", "next.js"),
    `\nimport fs from "node:fs";\nimport { checkAgentAccount as _c } from "next/server";\n`
  );
  fs.appendFileSync(path.join(scratch, "frameworks", "hono.js"), `\nimport readline from "readline";\n`);

  const caught = nodeBuiltinsIn(scratch);
  assert.ok(caught.includes("frameworks/next.js: node:fs"), `scan missed node:fs (${caught})`);
  assert.ok(caught.includes("frameworks/hono.js: readline"), `scan missed bare readline (${caught})`);

  const frameworks = frameworkImportsIn(scratch);
  assert.ok(
    frameworks.includes("frameworks/next.js: next/server"),
    `scan missed next/server (${frameworks})`
  );
} finally {
  fs.rmSync(scratch, { recursive: true, force: true });
}

console.log(
  `PASS — ${distFiles.length} dist files (${frameworkFiles.length} framework bindings): only jose and relative imports`
);
