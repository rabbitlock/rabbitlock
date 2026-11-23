import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";

export const POLICY_FILENAME = "rabbitlock.agent.yaml";
export const SECRET_NAME_PATTERN = /^[A-Z][A-Z0-9_]*$/;
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

  const secretsFile = raw.secrets_file ?? "secrets.sops.json";
  const receipts = raw.receipts ?? ".rabbitlock/receipts.jsonl";
  const recipients = raw.recipients ?? [];

  if (!Array.isArray(recipients) || recipients.some((r) => typeof r !== "string" || !/^[0-9a-f]+$/i.test(r))) {
    errors.push("recipients must be a list of hex public keys");
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

  return {
    path: policyPath,
    secretsFile: path.resolve(baseDir, secretsFile),
    receipts: path.resolve(baseDir, receipts),
    recipients: recipients.map((r) => r.toLowerCase()),
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

export function examplePolicy(publicKey) {
  return `# RabbitLock agent policy. Commit this file; it contains no secrets.
# Secrets live encrypted in secrets_file. The agent only ever sees placeholders.
secrets_file: secrets.sops.json
receipts: .rabbitlock/receipts.jsonl

# Public keys that can decrypt secrets_file (yours first; add teammates' keys).
recipients:
  - ${publicKey}

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
