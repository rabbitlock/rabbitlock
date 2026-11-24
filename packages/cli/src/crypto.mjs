import fs from "node:fs";
import path from "node:path";
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import { fileURLToPath } from "node:url";

import { rabbitlockHome, writePrivateFile } from "./paths.mjs";
import { promptTerminal } from "./prompt.mjs";

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

const IDENTITY_FORMAT = "rabbitlock-identity";
// scrypt cost: ~128 MiB and a few hundred ms per unlock, so offline guessing of a stolen file is slow.
const SCRYPT = { N: 2 ** 17, r: 8, p: 1 };
const SCRYPT_MAXMEM = 512 * 1024 * 1024;
export const MIN_PASSPHRASE_LENGTH = 12;
const PROMPT_ATTEMPTS = 3;

function malformed(file) {
  return new Error(`Identity file ${file} is malformed.`);
}

function envSeed() {
  const fromEnv = process.env.RABBITLOCK_SEED_HEX?.trim().toLowerCase();
  if (!fromEnv) return null;
  if (!SEED_PATTERN.test(fromEnv)) {
    throw new Error("RABBITLOCK_SEED_HEX must be 64 hex characters.");
  }
  return fromEnv;
}

/**
 * Reads the identity file without unlocking it.
 * Plain:     { protected: false, seed }
 * Protected: { protected: true, envelope, publicKey }  (the public key is stored in clear, and bound
 *            to the ciphertext, so `rabbitlock key` and listings work without the passphrase)
 */
export function readIdentity(file = identityPath()) {
  if (!fs.existsSync(file)) {
    throw new Error(`No identity found at ${file}. Run \`rabbitlock init\` first.`);
  }
  const text = fs.readFileSync(file, "utf8").trim();
  if (text.startsWith("{")) {
    let envelope;
    try {
      envelope = JSON.parse(text);
    } catch {
      throw malformed(file);
    }
    const { format, version, kdf, N, r, p, salt, iv, ciphertext, tag, public_key: publicKey } = envelope;
    const validCost = Number.isInteger(N) && N >= 2 ** 14 && N <= 2 ** 20 && (N & (N - 1)) === 0 && r === 8 && p === 1;
    if (format !== IDENTITY_FORMAT || version !== 1 || kdf !== "scrypt" || !validCost || ![salt, iv, ciphertext, tag, publicKey].every((v) => typeof v === "string")) {
      throw malformed(file);
    }
    return { protected: true, envelope, publicKey };
  }
  const seed = text.toLowerCase();
  if (!SEED_PATTERN.test(seed)) throw malformed(file);
  return { protected: false, seed };
}

function identityAad(envelope) {
  return Buffer.from(`${IDENTITY_FORMAT}:${envelope.version}:${envelope.public_key}`);
}

function passphraseKey(passphrase, salt, { N, r, p }) {
  return scryptSync(passphrase.normalize("NFKC"), salt, 32, { N, r, p, maxmem: SCRYPT_MAXMEM });
}

/** Encrypts the seed under a passphrase (scrypt + AES-256-GCM). Returns the envelope to store. */
export function protectSeed(seed, passphrase) {
  if (typeof passphrase !== "string" || passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(`Use a passphrase of at least ${MIN_PASSPHRASE_LENGTH} characters.`);
  }
  const { publicKey } = keypairFromSeed(seed);
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const header = { format: IDENTITY_FORMAT, version: 1, kdf: "scrypt", ...SCRYPT, salt: salt.toString("base64"), iv: iv.toString("base64"), public_key: publicKey };
  const cipher = createCipheriv("aes-256-gcm", passphraseKey(passphrase, salt, SCRYPT), iv);
  cipher.setAAD(identityAad(header));
  const ciphertext = Buffer.concat([cipher.update(seed, "utf8"), cipher.final()]);
  return { ...header, ciphertext: ciphertext.toString("base64"), tag: cipher.getAuthTag().toString("base64") };
}

/** Decrypts a protected identity. Throws "Wrong passphrase." on a bad passphrase. */
export function unlockSeed(envelope, passphrase) {
  const decipher = createDecipheriv(
    "aes-256-gcm",
    passphraseKey(passphrase, Buffer.from(envelope.salt, "base64"), envelope),
    Buffer.from(envelope.iv, "base64"),
  );
  decipher.setAAD(identityAad(envelope));
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
  let seed;
  try {
    seed = Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, "base64")), decipher.final()]).toString("utf8");
  } catch {
    throw new Error("Wrong passphrase.");
  }
  if (!SEED_PATTERN.test(seed) || keypairFromSeed(seed).publicKey !== envelope.public_key) {
    throw new Error("Identity file is corrupted: its public key doesn't match the decrypted seed.");
  }
  return seed;
}

export function writeIdentity(contents, file = identityPath()) {
  writePrivateFile(file, typeof contents === "string" ? `${contents}\n` : `${JSON.stringify(contents, null, 2)}\n`);
}

/** True when the identity file is passphrase-protected (false when the seed comes from the environment). */
export function identityIsProtected() {
  if (process.env.RABBITLOCK_SEED_HEX) return false;
  const file = identityPath();
  return fs.existsSync(file) && readIdentity(file).protected;
}

/**
 * Returns the 32-byte identity seed (hex): RABBITLOCK_SEED_HEX, else the identity file. A protected
 * file is unlocked with RABBITLOCK_PASSPHRASE or a prompt on the user's terminal (never stdin, so
 * piped input stays for the command, and an agent's shell without a terminal gets a clear error).
 */
export async function loadSeed({ passphrase = process.env.RABBITLOCK_PASSPHRASE, prompt = promptTerminal } = {}) {
  const fromEnv = envSeed();
  if (fromEnv) return fromEnv;
  const id = readIdentity();
  if (!id.protected) return id.seed;
  if (passphrase) return unlockSeed(id.envelope, passphrase);
  for (let attempt = 1; ; attempt += 1) {
    const typed = await prompt("RabbitLock passphrase: ");
    if (typed === null) {
      throw new Error(
        "Your RabbitLock identity is passphrase-protected and there is no terminal to ask on. " +
          "Run this command in your own terminal (automation: set RABBITLOCK_PASSPHRASE).",
      );
    }
    try {
      return unlockSeed(id.envelope, typed);
    } catch (err) {
      if (err.message !== "Wrong passphrase." || attempt >= PROMPT_ATTEMPTS) throw err;
      process.stderr.write("Wrong passphrase, try again.\n");
    }
  }
}

/** Synchronous variant for read-only reporting: returns null for a protected identity it can't unlock. */
export function loadSeedIfUnlocked({ passphrase = process.env.RABBITLOCK_PASSPHRASE } = {}) {
  const fromEnv = envSeed();
  if (fromEnv) return fromEnv;
  const id = readIdentity();
  if (!id.protected) return id.seed;
  return passphrase ? unlockSeed(id.envelope, passphrase) : null;
}

/** The public key, without needing the passphrase. */
export function loadPublicKey() {
  const fromEnv = envSeed();
  if (fromEnv) return keypairFromSeed(fromEnv).publicKey;
  const id = readIdentity();
  return id.protected ? id.publicKey : keypairFromSeed(id.seed).publicKey;
}

export function createIdentity() {
  const file = identityPath();
  if (fs.existsSync(file)) {
    readIdentity(file); // fails early on a malformed file; no passphrase needed
    return { created: false };
  }
  writeIdentity(randomBytes(32).toString("hex"), file);
  return { created: true };
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

/** Owner-only (0600) and atomic. The file is ciphertext, but there's no reason for others to read it. */
export function writeSecretsFile(filePath, secrets, recipientPublicKeys) {
  writePrivateFile(filePath, `${encryptSecrets(secrets, recipientPublicKeys)}\n`);
}

/** Secret names from a SOPS file without decrypting it (SOPS keeps keys in clear; values are encrypted). */
export function readSecretNames(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const doc = JSON.parse(fs.readFileSync(filePath, "utf8"));
  return Object.keys(doc).filter((k) => k !== "sops").sort();
}
