import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/** Directory holding the identity seed and local CA. Override with RABBITLOCK_HOME. */
export function rabbitlockHome() {
  return process.env.RABBITLOCK_HOME || path.join(os.homedir(), ".rabbitlock");
}

export function ensurePrivateDir(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

export function writePrivateFile(filePath, contents) {
  ensurePrivateDir(path.dirname(filePath));
  fs.writeFileSync(filePath, contents, { mode: 0o600 });
  fs.chmodSync(filePath, 0o600);
}
