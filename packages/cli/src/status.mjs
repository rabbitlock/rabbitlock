import fs from "node:fs";
import path from "node:path";

import { identityPath, keypairFromSeed, loadSeedIfUnlocked, readIdentity, readSecretNames, readSecretsFile } from "./crypto.mjs";
import { findPolicy, loadPolicy } from "./policy.mjs";

const PLACEHOLDER = /^rl_ph_([A-Z][A-Z0-9_]*)_[0-9a-f]{32}$/;
const ENV_FILE = /^\.env(\..+)?$/;
const ENV_TEMPLATE = /\.(example|sample|template|dist)$/;
const MAX_SCAN_BYTES = 1024 * 1024;

export function cliVersion() {
  const pkg = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  return pkg.version;
}

function which(tool, envPath = process.env.PATH ?? "") {
  for (const dir of envPath.split(path.delimiter)) {
    const candidate = path.join(dir, tool);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return candidate;
    } catch {
      // keep looking
    }
  }
  return null;
}

export function sandboxSupport(platform = process.platform, envPath = process.env.PATH) {
  if (platform === "darwin") {
    return which("sandbox-exec", envPath)
      ? { available: true, kind: "seatbelt" }
      : { available: false, reason: "sandbox-exec not found" };
  }
  if (platform === "linux") {
    return which("bwrap", envPath)
      ? { available: true, kind: "bwrap" }
      : { available: false, reason: "bubblewrap (bwrap) is not installed" };
  }
  return { available: false, reason: `no sandbox support on ${platform}` };
}

/** What an agent can tell about its own session from its environment alone. */
export function sessionFromEnv(env) {
  const brokered = Object.entries(env)
    .map(([key, value]) => [key, PLACEHOLDER.exec(value ?? "")])
    .filter(([key, m]) => m && m[1] === key)
    .map(([key]) => key)
    .sort();
  return {
    active: env.RABBITLOCK_ACTIVE === "1",
    id: env.RABBITLOCK_SESSION ?? null,
    sandbox: env.RABBITLOCK_SANDBOX ?? null,
    brokered,
  };
}

/**
 * Files like .env or .env.local next to the policy that still contain a real value of a brokered
 * secret. The sandbox protects RabbitLock's own files, not these, so the agent could read them.
 */
export function findPlaintextCopies(dir, values) {
  const real = Object.entries(values).filter(([, v]) => typeof v === "string" && v.length >= 8);
  if (real.length === 0) return [];
  let names;
  try {
    names = fs.readdirSync(dir);
  } catch {
    return [];
  }
  const copies = [];
  for (const name of names.sort()) {
    if (!ENV_FILE.test(name) || ENV_TEMPLATE.test(name)) continue;
    const file = path.join(dir, name);
    let text;
    try {
      const stat = fs.statSync(file);
      if (!stat.isFile() || stat.size > MAX_SCAN_BYTES) continue;
      text = fs.readFileSync(file, "utf8");
    } catch {
      continue;
    }
    const found = real.filter(([, v]) => text.includes(v)).map(([k]) => k);
    if (found.length > 0) copies.push({ file: name, secrets: found });
  }
  return copies;
}

export function collectStatus({ env = process.env, policyPath, cwd = process.cwd(), platform = process.platform } = {}) {
  const status = {
    version: cliVersion(),
    session: sessionFromEnv(env),
    identity: null,
    policy: null,
    stored: null,
    missingValues: [],
    notInPolicy: [],
    plaintextCopies: [],
    sandbox: sandboxSupport(platform, env.PATH),
    nextSteps: [],
  };

  let policy = null;
  let found = null;
  try {
    found = findPolicy(policyPath, cwd);
  } catch {
    // No policy yet: reported as a next step below.
  }
  if (found && fs.existsSync(found)) {
    try {
      policy = loadPolicy(found);
      status.policy = {
        path: policy.path,
        mode: policy.mode,
        secretsFile: policy.secretsFile,
        secrets: Object.fromEntries(Object.entries(policy.secrets).map(([k, r]) => [k, { hosts: r.hosts, approval: r.approval }])),
      };
    } catch (err) {
      status.policy = { path: found, error: err.message };
    }
  }

  if (status.session.active) {
    // Inside a sandboxed session the identity is unreadable by design; report what the agent can use.
    const { brokered, sandbox } = status.session;
    status.nextSteps.push(
      brokered.length > 0
        ? `Use ${brokered.map((n) => `$${n}`).join(", ")} exactly as you would the real values; they are swapped in only on HTTPS requests to each secret's allowed hosts.`
        : "No secrets are brokered in this session.",
    );
    if (sandbox === "off" || sandbox === "unavailable") {
      status.nextSteps.push("This session has no sandbox, so the agent could read RabbitLock's key file.");
    }
    status.nextSteps.push("To add a secret, ask the user to run `rabbitlock set NAME` in their own terminal, add its hosts with their OK, and restart the session. Never ask for the value in chat.");
    return status;
  }

  const seedFromEnv = Boolean(env.RABBITLOCK_SEED_HEX);
  const idFile = identityPath();
  status.identity = { present: seedFromEnv || fs.existsSync(idFile), source: seedFromEnv ? "env" : "file", path: idFile, protected: false };
  if (!seedFromEnv && status.identity.present) {
    try {
      status.identity.protected = readIdentity(idFile).protected;
    } catch (err) {
      status.nextSteps.push(err.message);
      return status;
    }
  }

  if (!status.identity.present || !status.policy) {
    status.nextSteps.push("Run `rabbitlock init` in the project root to create your identity and rabbitlock.agent.yaml.");
    return status;
  }
  if (status.policy.error) {
    status.nextSteps.push(`Fix ${path.basename(status.policy.path)}: ${status.policy.error}`);
    return status;
  }

  // status never prompts (agents run it). A passphrase-protected identity is reported from the
  // secret names, which SOPS keeps in clear; the plaintext-copy check then runs at `rabbitlock run`.
  let values = null;
  try {
    const seed = loadSeedIfUnlocked({ passphrase: env.RABBITLOCK_PASSPHRASE });
    if (seed) {
      values = readSecretsFile(policy.secretsFile, keypairFromSeed(seed).privateKey);
      status.stored = Object.keys(values).sort();
    } else {
      status.stored = readSecretNames(policy.secretsFile);
    }
  } catch (err) {
    status.nextSteps.push(`Could not read ${policy.secretsFile}: ${err.message}`);
    return status;
  }

  const listed = Object.keys(policy.secrets);
  status.missingValues = listed.filter((n) => !status.stored.includes(n)).sort();
  status.notInPolicy = status.stored.filter((n) => !listed.includes(n));
  if (values) {
    const brokeredValues = Object.fromEntries(listed.filter((n) => n in values).map((n) => [n, values[n]]));
    status.plaintextCopies = findPlaintextCopies(path.dirname(policy.path), brokeredValues);
  }

  if (listed.length === 0 && status.stored.length === 0) {
    status.nextSteps.push(
      "Add the secrets your agent needs to rabbitlock.agent.yaml, each with the hosts it may be sent to, then store them: " +
        "the user runs `rabbitlock import .env` or `rabbitlock set NAME` in their own terminal.",
    );
  }
  if (status.missingValues.length > 0) {
    status.nextSteps.push(
      `Store the missing values (the user runs this in their own terminal, never in chat): ${status.missingValues.map((n) => `rabbitlock set ${n}`).join("; ")}`,
    );
  }
  if (status.notInPolicy.length > 0) {
    status.nextSteps.push(`Agents don't receive ${status.notInPolicy.join(", ")} yet: add each to rabbitlock.agent.yaml with its allowed hosts.`);
  }
  for (const copy of status.plaintextCopies) {
    status.nextSteps.push(`Delete or move ${copy.file}: it still contains the real value of ${copy.secrets.join(", ")}, and the agent can read it.`);
  }
  if (!status.sandbox.available) {
    status.nextSteps.push(
      platform === "linux"
        ? "Install bubblewrap (for example `sudo apt install bubblewrap`) so agents can't read RabbitLock's keys."
        : `Agents will run without a sandbox here (${status.sandbox.reason}). Claude Code still uses its own sandbox.`,
    );
  }
  if (status.missingValues.length === 0 && listed.length > 0) {
    status.nextSteps.push("Start your agent through RabbitLock, for example: rabbitlock run -- claude");
  }
  return status;
}

export function formatStatus(s) {
  const out = [`RabbitLock ${s.version}`];
  if (s.session.active) {
    out.push(`Session: active (${s.session.id ?? "unknown id"}), sandbox: ${s.session.sandbox ?? "unknown"}`);
    out.push(`Brokered: ${s.session.brokered.join(", ") || "none"}`);
  } else {
    out.push("Session: not running under `rabbitlock run`");
    if (s.identity) {
      const detail = s.identity.source === "env" ? "from RABBITLOCK_SEED_HEX" : s.identity.protected ? "passphrase-protected" : "not passphrase-protected; `rabbitlock key protect` adds one";
      out.push(`Identity: ${s.identity.present ? `present (${detail})` : "missing"}`);
    }
  }
  if (s.policy?.path) out.push(`Policy: ${s.policy.path}${s.policy.error ? ` (error: ${s.policy.error})` : ""}`);
  if (s.policy?.mode) {
    out.push(
      s.policy.mode === "individual"
        ? `Mode: individual (encrypted secrets kept on this machine: ${s.policy.secretsFile})`
        : `Mode: team (encrypted secrets shared in ${s.policy.secretsFile})`,
    );
  }
  for (const [name, rule] of Object.entries(s.policy?.secrets ?? {})) {
    const state = s.stored === null ? "" : s.stored.includes(name) ? "" : "  MISSING VALUE";
    out.push(`  ${name.padEnd(28)} ${rule.hosts.join(", ")}  approval=${rule.approval}${state}`);
  }
  if (!s.session.active) {
    out.push(`Sandbox: ${s.sandbox.available ? s.sandbox.kind : `not available (${s.sandbox.reason})`}`);
  }
  if (s.nextSteps.length > 0) {
    out.push("", "Next:");
    for (const step of s.nextSteps) out.push(`  - ${step}`);
  }
  return out.join("\n");
}
