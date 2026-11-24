import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";

import { rabbitlockHome } from "./paths.mjs";

export const POLICY_FILENAME = "rabbitlock.agent.yaml";
export const SECRET_NAME_PATTERN = /^[A-Z][A-Z0-9_]*$/;
export const PROJECT_PATTERN = /^[a-z0-9][a-z0-9-]{3,63}$/;
const APPROVAL_MODES = new Set(["never", "once", "every"]);
const HOST_PATTERN = /^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/;

export function findPolicy(explicitPath, cwd = process.cwd()) {
  if (explicitPath) {
    return path.resolve(cwd, explicitPath);
  }
  let dir = cwd;
  for (;;) {
    const candidate = path.join(dir, POLICY_FILENAME);
    if (fs.existsSync(candidate)) {
      return candidate;
    }
    const parent = path.dirname(dir);
    if (parent === dir) {
      throw new Error(`No ${POLICY_FILENAME} found in ${cwd} or any parent. Run \`rabbitlock init\`.`);
    }
    dir = parent;
  }
}

/**
 * Parses and validates the agent policy. Unknown or malformed entries are errors:
 * a typo in a host list must never silently widen or drop protection.
 */
export function parsePolicy(text, policyPath) {
  const raw = YAML.parse(text) ?? {};
  const baseDir = path.dirname(policyPath);
  const errors = [];

  const project = raw.project;
  if (project !== undefined && (typeof project !== "string" || !PROJECT_PATTERN.test(project))) {
    errors.push(`project must match ${PROJECT_PATTERN}`);
  }

  // Recipients: a hex public key, or { name, key } for readability.
  const rawRecipients = raw.recipients ?? [];
  const recipientEntries = [];
  if (!Array.isArray(rawRecipients)) {
    errors.push("recipients must be a list");
  } else {
    for (const r of rawRecipients) {
      const entry = typeof r === "string" ? { name: null, key: r } : r && typeof r === "object" ? { name: r.name ?? null, key: r.key } : null;
      if (!entry || typeof entry.key !== "string" || !/^[0-9a-f]+$/i.test(entry.key) || (entry.name !== null && typeof entry.name !== "string")) {
        errors.push("recipients entries must be a hex public key or { name, key }");
        continue;
      }
      recipientEntries.push({ name: entry.name, key: entry.key.toLowerCase() });
    }
  }

  const secrets = {};
  const rawSecrets = raw.secrets ?? {};
  if (typeof rawSecrets !== "object" || Array.isArray(rawSecrets)) {
    errors.push("secrets must be a map of NAME: { hosts, approval }");
  } else {
    for (const [name, rule] of Object.entries(rawSecrets)) {
      if (!SECRET_NAME_PATTERN.test(name)) {
        errors.push(`secret name ${name} must match ${SECRET_NAME_PATTERN}`);
        continue;
      }
      const hosts = rule?.hosts;
      if (!Array.isArray(hosts) || hosts.length === 0) {
        errors.push(`secrets.${name}.hosts must be a non-empty list`);
        continue;
      }
      const normalized = hosts.map((h) => String(h).trim().toLowerCase());
      const bad = normalized.filter((h) => !HOST_PATTERN.test(h));
      if (bad.length > 0) {
        errors.push(`secrets.${name}.hosts has invalid entries: ${bad.join(", ")}`);
        continue;
      }
      const approval = rule.approval ?? "never";
      if (!APPROVAL_MODES.has(approval)) {
        errors.push(`secrets.${name}.approval must be one of never|once|every`);
        continue;
      }
      secrets[name] = { hosts: normalized, approval };
    }
  }

  if (errors.length > 0) {
    throw new Error(`Invalid policy ${policyPath}:\n  - ${errors.join("\n  - ")}`);
  }

  // Where secrets and receipts live:
  //  - secrets_file set: in the repo (team mode: the encrypted file is committed and shared)
  //  - project set, no secrets_file: under RABBITLOCK_HOME/projects/<project> (individual mode)
  //  - neither (policies from before 0.4): in the repo, as before
  const projectDir = project ? path.join(rabbitlockHome(), "projects", project) : null;
  const secretsFile = raw.secrets_file
    ? path.resolve(baseDir, raw.secrets_file)
    : projectDir
      ? path.join(projectDir, "secrets.sops.json")
      : path.resolve(baseDir, "secrets.sops.json");
  const receipts = raw.receipts
    ? path.resolve(baseDir, raw.receipts)
    : projectDir
      ? path.join(projectDir, "receipts.jsonl")
      : path.resolve(baseDir, ".rabbitlock/receipts.jsonl");

  return {
    path: policyPath,
    project: project ?? null,
    mode: raw.secrets_file || !project ? "team" : "individual",
    secretsFile,
    receipts,
    recipients: recipientEntries.map((r) => r.key),
    recipientEntries,
    secrets,
  };
}

export function loadPolicy(explicitPath) {
  const policyPath = findPolicy(explicitPath);
  return parsePolicy(fs.readFileSync(policyPath, "utf8"), policyPath);
}

export function hostMatches(pattern, host) {
  const h = host.toLowerCase();
  if (pattern.startsWith("*.")) {
    return h.endsWith(pattern.slice(1)) && h.length > pattern.length - 1;
  }
  return h === pattern;
}

export function secretAllowedForHost(rule, host) {
  return rule.hosts.some((pattern) => hostMatches(pattern, host));
}

/** Hosts whose TLS the broker terminates so placeholders can be swapped. */
export function interceptHosts(policy) {
  return [...new Set(Object.values(policy.secrets).flatMap((rule) => rule.hosts))];
}

export function newProjectId() {
  return randomBytes(6).toString("hex");
}

/** Individual mode: nothing secret in the repo, nothing to decide about committing. */
export function examplePolicy(projectId = newProjectId()) {
  return `# RabbitLock policy: which hosts may receive each secret. Safe to commit; it contains no secrets.
# Encrypted values and receipts are kept on your machine, in ~/.rabbitlock/projects/<project>.
# To share secrets with teammates, run: rabbitlock team enable
project: ${projectId}

secrets: {}
# Example:
#   GITHUB_TOKEN:
#     hosts: [api.github.com, github.com]
#     approval: never        # never | once (first use per session) | every
#   STRIPE_API_KEY:
#     hosts: [api.stripe.com]
#     approval: once
`;
}
