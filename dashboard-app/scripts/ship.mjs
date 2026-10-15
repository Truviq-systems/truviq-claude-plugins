// Copy the static export into the plugin so `truviq.py dashboard` serves it. End users never need Node.js.
import { cpSync, existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, "..", "out");
const target = join(here, "..", "..", "plugins", "truviq-guard", "dashboard");

if (!existsSync(join(out, "index.html"))) {
  console.error("No out/index.html: run `next build` first.");
  process.exit(1);
}
mkdirSync(target, { recursive: true });
for (const name of readdirSync(target)) rmSync(join(target, name), { recursive: true, force: true });
cpSync(out, target, { recursive: true });
console.log(`Shipped the dashboard into ${target}`);
