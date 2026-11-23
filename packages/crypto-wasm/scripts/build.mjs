import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const pkgDir = new URL("..", import.meta.url);
const pkgPath = path.resolve(pkgDir.pathname, "pkg");
console.log("Checking for prebuilt artifacts at:", pkgPath);
if (fs.existsSync(pkgPath)) {
  console.log("Directory contents:", fs.readdirSync(pkgPath));
} else {
  console.log("Directory does not exist.");
}

const requiredFiles = [
  "rabbitlock_crypto.js",
  "rabbitlock_crypto_bg.wasm",
  "rabbitlock_crypto.d.ts",
];

const hasCommand = (cmd) => {
  const result = spawnSync(cmd, ["--version"], { stdio: "ignore" });
  return result.status === 0;
};

const hasPrebuiltPkg = () =>
  requiredFiles.every((file) => fs.existsSync(path.join(pkgPath, file)));

const run = () => {
  const hasWasmPack = hasCommand("wasm-pack");
  const hasCargo = hasCommand("cargo");

  if (hasWasmPack && hasCargo) {
    const result = spawnSync("wasm-pack", ["build", "--target", "web"], {
      stdio: "inherit",
    });
    process.exit(result.status ?? 1);
  }

  if (hasPrebuiltPkg()) {
    console.log(
      "wasm-pack/cargo not available. Using prebuilt pkg artifacts.",
    );
    process.exit(0);
  }

  console.error(
    "Missing wasm toolchain and no prebuilt pkg artifacts found. Run `wasm-pack build --target web` locally and commit pkg/.",
  );
  process.exit(1);
};

run();
