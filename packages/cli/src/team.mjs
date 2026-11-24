import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";

import { readSecretsFile, writeSecretsFile } from "./crypto.mjs";
import { loadPolicy } from "./policy.mjs";

export const TEAM_SECRETS_FILE = "secrets.sops.json";

/** A short, stable label for a public key, for listings and confirmations. */
export function fingerprint(key) {
  return `${key.slice(0, 8)}…${key.slice(-8)}`;
}

function editPolicy(policyPath, mutate) {
  const doc = YAML.parseDocument(fs.readFileSync(policyPath, "utf8"));
  mutate(doc);
  fs.writeFileSync(policyPath, doc.toString());
}

function recipientNodes(entries) {
  return entries.map((r) => (r.name ? { name: r.name, key: r.key } : r.key));
}

/**
 * Individual -> team: move the encrypted secrets from ~/.rabbitlock into the repo (where they can be
 * committed and shared) and list the owner as the first named recipient.
 */
export function enableTeam(policy, { privateKey, publicKey, name }) {
  if (policy.mode === "team") {
    throw new Error(`Team mode is already on: secrets are in ${path.relative(process.cwd(), policy.secretsFile)}.`);
  }
  const secrets = readSecretsFile(policy.secretsFile, privateKey);
  const target = path.join(path.dirname(policy.path), TEAM_SECRETS_FILE);
  if (fs.existsSync(target)) {
    throw new Error(`${target} already exists. Move it aside first, or set secrets_file in the policy yourself.`);
  }
  const owner = { name, key: publicKey.toLowerCase() };
  const recipients = [owner, ...policy.recipientEntries.filter((r) => r.key !== owner.key)];
  writeSecretsFile(target, secrets, recipients.map((r) => r.key));
  editPolicy(policy.path, (doc) => {
    doc.set("secrets_file", TEAM_SECRETS_FILE);
    doc.set("recipients", recipientNodes(recipients));
  });
  if (fs.existsSync(policy.secretsFile)) fs.unlinkSync(policy.secretsFile);
  return { target, count: Object.keys(secrets).length };
}

function requireTeam(policy) {
  if (policy.mode !== "team") {
    throw new Error("This project is in individual mode. Run `rabbitlock team enable` first to share secrets.");
  }
}

/** Adds a teammate's public key and re-encrypts the shared file so they can decrypt it. */
export function addMember(policy, { privateKey, publicKey, key, name }) {
  requireTeam(policy);
  const normalized = key.trim().toLowerCase();
  if (!/^[0-9a-f]{64,}$/.test(normalized)) throw new Error("That doesn't look like a RabbitLock public key (expected hex from `rabbitlock key`).");
  if (policy.recipientEntries.some((r) => r.key === normalized)) throw new Error("That key is already a recipient.");
  if (name && policy.recipientEntries.some((r) => r.name === name)) throw new Error(`A recipient named ${name} already exists.`);
  const recipients = [...policy.recipientEntries, { name: name ?? null, key: normalized }];
  const keys = withSelf(recipients, publicKey);
  const secrets = readSecretsFile(policy.secretsFile, privateKey);
  writeSecretsFile(policy.secretsFile, secrets, keys); // fails on a malformed key, before the policy changes
  editPolicy(policy.path, (doc) => doc.set("recipients", recipientNodes(recipients)));
  return { count: Object.keys(secrets).length };
}

/** Removes a teammate by name or key and re-encrypts without them. */
export function removeMember(policy, { privateKey, publicKey, who }) {
  requireTeam(policy);
  const target = who.trim().toLowerCase();
  const match = policy.recipientEntries.find((r) => r.name?.toLowerCase() === target || r.key === target || r.key.startsWith(target));
  if (!match) throw new Error(`No recipient matches ${who}. See \`rabbitlock team ls\`.`);
  if (match.key === publicKey.toLowerCase()) throw new Error("You can't remove yourself; your key is always a recipient of files you write.");
  const recipients = policy.recipientEntries.filter((r) => r !== match);
  const secrets = readSecretsFile(policy.secretsFile, privateKey);
  writeSecretsFile(policy.secretsFile, secrets, withSelf(recipients, publicKey));
  editPolicy(policy.path, (doc) => doc.set("recipients", recipientNodes(recipients)));
  return { removed: match, secrets: Object.keys(secrets).sort() };
}

function withSelf(recipients, publicKey) {
  const keys = recipients.map((r) => r.key);
  const own = publicKey.toLowerCase();
  return keys.includes(own) ? keys : [own, ...keys];
}

export function listMembers(policyPath, publicKey) {
  const policy = loadPolicy(policyPath);
  return policy.recipientEntries.map((r) => ({ ...r, you: r.key === publicKey.toLowerCase() }));
}
