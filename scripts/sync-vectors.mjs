import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const canonicalPath = path.resolve(__dirname, "../../agentonboard/vectors/agent-token-v1.json");
const localFixturePath = path.resolve(__dirname, "../tests/fixtures/agent-token-v1.json");

const sha256 = (filePath) => crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");

if (!fs.existsSync(canonicalPath)) {
  console.log(`Canonical file not found at ${canonicalPath}; skipping sync check.`);
  process.exit(0);
}

const localHash = sha256(localFixturePath);
const canonicalHash = sha256(canonicalPath);

if (localHash === canonicalHash) {
  console.log("agent-token-v1.json is in sync with canonical repository.");
  process.exit(0);
}

if (process.argv.includes("--check")) {
  console.error(`ERROR: Local fixture ${localFixturePath} differs from ${canonicalPath}!`);
  process.exit(1);
}

fs.copyFileSync(canonicalPath, localFixturePath);
console.log("Updated local agent-token-v1.json from canonical source.");
