// Copies the compiled crypto core into the CLI package so the published tarball is self-contained.
// Runs on `npm pack` / `npm publish` (prepack). The workspace copy in packages/crypto-wasm stays the source.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const pkgDir = path.resolve(here, "..");
const source = path.resolve(pkgDir, "../crypto-wasm/pkg");
const target = path.join(pkgDir, "vendor/crypto");

fs.rmSync(target, { recursive: true, force: true });
fs.mkdirSync(target, { recursive: true });
for (const file of ["rabbitlock_crypto.js", "rabbitlock_crypto_bg.wasm"]) {
  fs.copyFileSync(path.join(source, file), path.join(target, file));
}
fs.writeFileSync(path.join(target, "package.json"), JSON.stringify({ type: "module" }) + "\n");
for (const file of ["LICENSE", "NOTICE"]) {
  fs.copyFileSync(path.resolve(pkgDir, "../..", file), path.join(pkgDir, file));
}
console.log(`vendored crypto core into ${path.relative(process.cwd(), target)}`);
