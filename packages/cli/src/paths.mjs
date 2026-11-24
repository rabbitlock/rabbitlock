import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";

/** Directory holding the identity seed and local CA. Override with RABBITLOCK_HOME. */
export function rabbitlockHome() {
  return process.env.RABBITLOCK_HOME || path.join(os.homedir(), ".rabbitlock");
}

export function ensurePrivateDir(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

/**
 * Writes a file readable only by the owner (0600), atomically: a crash mid-write leaves the old
 * file intact rather than a truncated identity or secrets file. New parent directories are 0700.
 */
export function writePrivateFile(filePath, contents) {
  ensurePrivateDir(path.dirname(filePath));
  const tmp = path.join(path.dirname(filePath), `.${path.basename(filePath)}.${randomBytes(6).toString("hex")}.tmp`);
  const fd = fs.openSync(tmp, "wx", 0o600);
  try {
    fs.writeFileSync(fd, contents);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    fs.chmodSync(tmp, 0o600); // in case a umask or ACL widened it
    fs.renameSync(tmp, filePath);
  } catch (err) {
    fs.rmSync(tmp, { force: true });
    throw err;
  }
}

/** Appends to a file, creating it (and new parent directories) owner-only. */
export function appendPrivateFile(filePath, contents) {
  ensurePrivateDir(path.dirname(filePath));
  fs.appendFileSync(filePath, contents, { mode: 0o600 });
}
