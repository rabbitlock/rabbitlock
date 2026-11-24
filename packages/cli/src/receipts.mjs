import fs from "node:fs";
import path from "node:path";

import { appendPrivateFile, ensurePrivateDir } from "./paths.mjs";

/**
 * Append-only JSONL receipts. A receipt records which secret was used where, never its value.
 * `values` is used defensively: if a real value ever reaches a receipt field it is redacted.
 */
export function createReceiptWriter(filePath, session, values) {
  ensurePrivateDir(path.dirname(filePath));
  const secretValues = Object.values(values).filter((v) => v.length >= 4);

  return (entry) => {
    let line = JSON.stringify({ ts: new Date().toISOString(), session, ...entry });
    for (const value of secretValues) {
      line = line.split(value).join("[REDACTED]");
    }
    appendPrivateFile(filePath, `${line}\n`);
  };
}

export function readReceipts(filePath, tail) {
  if (!fs.existsSync(filePath)) {
    return [];
  }
  const lines = fs.readFileSync(filePath, "utf8").split("\n").filter(Boolean);
  return (tail ? lines.slice(-tail) : lines).map((l) => JSON.parse(l));
}
