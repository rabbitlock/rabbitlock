import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";
import { generateKeyPairSync, randomBytes } from "node:crypto";
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

/** Loads (or creates on first use) the local CA under RABBITLOCK_HOME/ca. */
export function loadLocalCA() {
  const dir = ensurePrivateDir(path.join(rabbitlockHome(), "ca"));
  const certPath = path.join(dir, "rabbitlock-ca.pem");
  const keyPath = path.join(dir, "rabbitlock-ca.key");
  const bundlePath = path.join(dir, "bundle.pem");

  let ca;
  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    const certPem = fs.readFileSync(certPath, "utf8");
    const keyPem = fs.readFileSync(keyPath, "utf8");
    ca = {
      certPem,
      keyPem,
      cert: forge.pki.certificateFromPem(certPem),
      privateKey: forge.pki.privateKeyFromPem(keyPem),
    };
  } else {
    ca = createCertificateAuthority(`RabbitLock Local Agent CA (${os.hostname()})`);
    writePrivateFile(keyPath, ca.keyPem);
    fs.writeFileSync(certPath, ca.certPem);
  }

  // Tools that take a full trust store (curl, Python, git) need system roots + our CA.
  fs.writeFileSync(bundlePath, `${tls.rootCertificates.join("\n")}\n${ca.certPem}`);

  return { ...ca, certPath, bundlePath };
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
