import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";

import { rabbitlockHome, writePrivateFile } from "./paths.mjs";

// Published package: crypto core vendored into ./vendor/crypto (see scripts/vendor-crypto.mjs).
// Workspace: the @rabbitlock/crypto-wasm package.
const vendored = new URL("../vendor/crypto/rabbitlock_crypto.js", import.meta.url);
const useVendored = fs.existsSync(vendored);
const wasm = useVendored ? await import(vendored.href) : await import("@rabbitlock/crypto-wasm");
const wasmBinaryPath = useVendored
  ? fileURLToPath(new URL("../vendor/crypto/rabbitlock_crypto_bg.wasm", import.meta.url))
  : fileURLToPath(import.meta.resolve("@rabbitlock/crypto-wasm/pkg/rabbitlock_crypto_bg.wasm"));

let initialized = false;

function crypto() {
  if (!initialized) {
    wasm.initSync({ module: fs.readFileSync(wasmBinaryPath) });
    initialized = true;
  }
  return wasm;
}

const SEED_PATTERN = /^[0-9a-f]{64}$/;

export function identityPath() {
  return path.join(rabbitlockHome(), "identity");
}

/** Returns the 32-byte identity seed (hex) from RABBITLOCK_SEED_HEX or the identity file. */
export function loadSeed() {
  const fromEnv = process.env.RABBITLOCK_SEED_HEX?.trim().toLowerCase();
  if (fromEnv) {
    if (!SEED_PATTERN.test(fromEnv)) {
      throw new Error("RABBITLOCK_SEED_HEX must be 64 hex characters.");
    }
    return fromEnv;
  }
  const file = identityPath();
  if (!fs.existsSync(file)) {
    throw new Error(`No identity found at ${file}. Run \`rabbitlock init\` first.`);
  }
  const seed = fs.readFileSync(file, "utf8").trim().toLowerCase();
  if (!SEED_PATTERN.test(seed)) {
    throw new Error(`Identity file ${file} is malformed.`);
  }
  return seed;
}

export function createIdentity() {
  const file = identityPath();
  if (fs.existsSync(file)) {
    return { created: false, seed: loadSeed() };
  }
  const seed = randomBytes(32).toString("hex");
  writePrivateFile(file, `${seed}\n`);
  return { created: true, seed };
}

export function keypairFromSeed(seedHex) {
  const pair = crypto().derive_hybrid_keypair(seedHex);
  const idx = pair.indexOf(":");
  if (idx === -1) {
    throw new Error("Failed to derive keypair from identity seed.");
  }
  return { privateKey: pair.slice(0, idx), publicKey: pair.slice(idx + 1) };
}

/** Decrypts a RabbitLock SOPS JSON document. Fails hard if the MAC does not verify. */
export function decryptSecrets(sopsJson, privateKey) {
  const c = crypto();
  const dataKey = c.decrypt_data_key(sopsJson, privateKey);
  const integrity = c.verify_sops_integrity(sopsJson, dataKey);
  if (!/passed/i.test(integrity)) {
    throw new Error(`Secrets file failed integrity check: ${integrity}`);
  }
  const plain = JSON.parse(c.decrypt_sops_content(sopsJson, privateKey));
  if (!plain || typeof plain !== "object" || Array.isArray(plain)) {
    throw new Error("Secrets file must contain a JSON object of NAME: value pairs.");
  }
  const out = {};
  for (const [key, value] of Object.entries(plain)) {
    out[key] = typeof value === "string" ? value : JSON.stringify(value);
  }
  return out;
}

export function encryptSecrets(secrets, recipientPublicKeys) {
  if (recipientPublicKeys.length === 0) {
    throw new Error("At least one recipient public key is required.");
  }
  return crypto().encrypt_sops_json_for_recipients(
    JSON.stringify(secrets),
    recipientPublicKeys,
  );
}

export function readSecretsFile(filePath, privateKey) {
  if (!fs.existsSync(filePath)) {
    return {};
  }
  return decryptSecrets(fs.readFileSync(filePath, "utf8"), privateKey);
}

export function writeSecretsFile(filePath, secrets, recipientPublicKeys) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${encryptSecrets(secrets, recipientPublicKeys)}\n`);
}
