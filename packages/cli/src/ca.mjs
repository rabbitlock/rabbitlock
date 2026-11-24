import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";
import { createCipheriv, createDecipheriv, createHash, generateKeyPairSync, hkdfSync, randomBytes } from "node:crypto";
import forge from "node-forge";

import { ensurePrivateDir, rabbitlockHome, writePrivateFile } from "./paths.mjs";

const DAY_MS = 24 * 60 * 60 * 1000;

function rsaKeyPair() {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pem = privateKey.export({ type: "pkcs8", format: "pem" });
  const forgeKey = forge.pki.privateKeyFromPem(pem);
  return {
    pem,
    privateKey: forgeKey,
    publicKey: forge.pki.setRsaPublicKey(forgeKey.n, forgeKey.e),
  };
}

function serial() {
  // Positive serial: clear the top bit.
  const bytes = randomBytes(16);
  bytes[0] &= 0x7f;
  return bytes.toString("hex");
}

/** Creates a self-signed CA certificate. Exported so tests can mint their own upstream CA. */
export function createCertificateAuthority(commonName, validDays = 3 * 365) {
  const keys = rsaKeyPair();
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = serial();
  cert.validity.notBefore = new Date(Date.now() - DAY_MS);
  cert.validity.notAfter = new Date(Date.now() + validDays * DAY_MS);
  const attrs = [{ name: "commonName", value: commonName }, { name: "organizationName", value: "RabbitLock" }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: "basicConstraints", cA: true, critical: true },
    { name: "keyUsage", keyCertSign: true, cRLSign: true, critical: true },
    { name: "subjectKeyIdentifier" },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return { certPem: forge.pki.certificateToPem(cert), keyPem: keys.pem, cert, privateKey: keys.privateKey };
}

/** Issues a short-lived server certificate for one host, signed by the given CA. */
export function issueLeaf(ca, host, leafKeys) {
  const cert = forge.pki.createCertificate();
  cert.publicKey = leafKeys.publicKey;
  cert.serialNumber = serial();
  cert.validity.notBefore = new Date(Date.now() - DAY_MS);
  cert.validity.notAfter = new Date(Date.now() + 30 * DAY_MS);
  cert.setSubject([{ name: "commonName", value: host }]);
  cert.setIssuer(ca.cert.subject.attributes);
  const altName = net.isIP(host) ? { type: 7, ip: host } : { type: 2, value: host };
  cert.setExtensions([
    { name: "basicConstraints", cA: false },
    { name: "keyUsage", digitalSignature: true, keyEncipherment: true, critical: true },
    { name: "extKeyUsage", serverAuth: true },
    { name: "subjectAltName", altNames: [altName] },
  ]);
  cert.sign(ca.privateKey, forge.md.sha256.create());
  return forge.pki.certificateToPem(cert);
}

export function caPaths() {
  const dir = path.join(rabbitlockHome(), "ca");
  return {
    dir,
    certPath: path.join(dir, "rabbitlock-ca.pem"),
    keyPath: path.join(dir, "rabbitlock-ca.key"),
    bundlePath: path.join(dir, "bundle.pem"),
  };
}

const CA_KEY_FORMAT = "rabbitlock-ca-key";

/**
 * The CA private key is stored encrypted under a key derived from the identity seed (HKDF-SHA256,
 * then AES-256-GCM). It is therefore exactly as protected as the identity: with a passphrase on the
 * identity, a copy of ~/.rabbitlock is useless without it, and unlocking needs no second prompt.
 * The ciphertext is bound to the CA certificate, so the two can't be mixed up.
 */
function caWrappingKey(seedHex) {
  return Buffer.from(hkdfSync("sha256", Buffer.from(seedHex, "hex"), Buffer.alloc(0), "rabbitlock ca key v1", 32));
}

function caKeyAad(certPem) {
  return Buffer.from(`${CA_KEY_FORMAT}:1:${createHash("sha256").update(certPem).digest("hex")}`);
}

export function sealCAKey(keyPem, certPem, seedHex) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", caWrappingKey(seedHex), iv);
  cipher.setAAD(caKeyAad(certPem));
  const ciphertext = Buffer.concat([cipher.update(keyPem, "utf8"), cipher.final()]);
  return {
    format: CA_KEY_FORMAT,
    version: 1,
    alg: "hkdf-sha256/aes-256-gcm",
    iv: iv.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
  };
}

export function openCAKey(envelope, certPem, seedHex) {
  if (envelope?.format !== CA_KEY_FORMAT || envelope.version !== 1) throw new Error("The local CA key file is malformed.");
  const decipher = createDecipheriv("aes-256-gcm", caWrappingKey(seedHex), Buffer.from(envelope.iv, "base64"));
  decipher.setAAD(caKeyAad(certPem));
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
  try {
    return Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, "base64")), decipher.final()]).toString("utf8");
  } catch {
    const { dir } = caPaths();
    throw new Error(
      `Couldn't decrypt the local CA key in ${dir}: it was encrypted for a different identity, or the certificate was replaced. ` +
        `Move ${dir} aside and run again to create a new CA (then \`rabbitlock ca trust\` again if you had trusted the old one).`,
    );
  }
}

function writeCAKey(keyPath, keyPem, certPem, seedHex) {
  writePrivateFile(keyPath, `${JSON.stringify(sealCAKey(keyPem, certPem, seedHex), null, 2)}\n`);
}

/** The CA certificate's paths if it exists. Needs no key: for printing the path and keychain trust. */
export function localCACertificate() {
  const paths = caPaths();
  return fs.existsSync(paths.certPath) ? paths : null;
}

/**
 * Loads the local CA (creating it on first use) with its private key, for issuing certificates in
 * `rabbitlock run`. Needs the identity seed. A key file left in plain PEM by an older version is
 * encrypted in place (`migrated: true`).
 */
export function loadLocalCA(seedHex) {
  if (typeof seedHex !== "string") throw new Error("loadLocalCA needs the identity seed.");
  const { dir, certPath, keyPath, bundlePath } = caPaths();
  ensurePrivateDir(dir);

  let ca;
  let migrated = false;
  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    const certPem = fs.readFileSync(certPath, "utf8");
    const stored = fs.readFileSync(keyPath, "utf8");
    let keyPem;
    if (stored.trimStart().startsWith("{")) {
      let envelope;
      try {
        envelope = JSON.parse(stored);
      } catch {
        throw new Error("The local CA key file is malformed.");
      }
      keyPem = openCAKey(envelope, certPem, seedHex);
    } else {
      keyPem = stored;
      writeCAKey(keyPath, keyPem, certPem, seedHex);
      migrated = true;
    }
    ca = { certPem, keyPem, cert: forge.pki.certificateFromPem(certPem), privateKey: forge.pki.privateKeyFromPem(keyPem) };
  } else {
    ca = createCertificateAuthority(`RabbitLock Local Agent CA (${os.hostname()})`);
    writeCAKey(keyPath, ca.keyPem, ca.certPem, seedHex);
    fs.writeFileSync(certPath, ca.certPem);
  }

  // Tools that take a full trust store (curl, Python, git) need system roots + our CA.
  fs.writeFileSync(bundlePath, `${tls.rootCertificates.join("\n")}\n${ca.certPem}`);

  return { ...ca, certPath, bundlePath, migrated };
}

/** Per-session cache of TLS contexts for intercepted hosts. */
export function createContextFactory(ca) {
  const leafKeys = rsaKeyPair();
  const cache = new Map();
  return (host) => {
    let ctx = cache.get(host);
    if (!ctx) {
      const leafPem = issueLeaf(ca, host, leafKeys);
      ctx = tls.createSecureContext({ key: leafKeys.pem, cert: `${leafPem}${ca.certPem}` });
      cache.set(host, ctx);
    }
    return ctx;
  };
}
