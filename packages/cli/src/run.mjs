import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import path from "node:path";

import { createApprovalGate } from "./approval.mjs";
import { createContextFactory, loadLocalCA } from "./ca.mjs";
import { keypairFromSeed, loadSeed, readSecretsFile } from "./crypto.mjs";
import { rabbitlockHome } from "./paths.mjs";
import { makePlaceholders } from "./placeholders.mjs";
import { startProxy } from "./proxy.mjs";
import { createReceiptWriter } from "./receipts.mjs";
import { findPlaintextCopies } from "./status.mjs";
import { planSandbox, protectedPaths } from "./sandbox.mjs";

/**
 * Claude Code applies its own Seatbelt/bubblewrap sandbox to the commands it runs, and macOS
 * cannot nest sandbox profiles. So for `claude` RabbitLock configures Claude Code's sandbox
 * for the session (--settings) instead of wrapping it.
 */
export function claudeSessionSettings(paths) {
  const denyWrite = [paths.home, ...paths.noWrite];
  return {
    permissions: {
      deny: [
        ...paths.noRead.map((p) => `Read(/${p})`),
        ...denyWrite.map((p) => `Edit(/${p}/**)`),
        ...paths.noWrite.map((p) => `Edit(/${p})`),
      ],
    },
    sandbox: {
      enabled: true,
      failIfUnavailable: true,
      allowUnsandboxedCommands: false,
      filesystem: { denyRead: paths.noRead, denyWrite },
    },
  };
}

/** Decides how the agent is launched: OS sandbox, Claude Code session settings, or unsandboxed. */
export function planLaunch(command, args, paths, { mode, hideProcesses }) {
  if (mode === "off") {
    return { command, args, sandbox: "off" };
  }
  if (path.basename(command) === "claude") {
    return {
      command,
      args: ["--settings", JSON.stringify(claudeSessionSettings(paths)), ...args],
      sandbox: "claude-settings",
      warning: hideProcesses
        ? "RABBITLOCK_SEED_HEX is set; Claude Code's sandbox may not hide the broker's environment. Prefer the identity file."
        : undefined,
    };
  }
  const plan = planSandbox(command, args, paths, { hideProcesses });
  if (plan.ok) {
    return { command: plan.command, args: plan.args, sandbox: plan.kind };
  }
  if (mode === "on") {
    throw new Error(`Sandbox required (--sandbox on) but unavailable: ${plan.reason}`);
  }
  return {
    command,
    args,
    sandbox: "unavailable",
    warning: `running WITHOUT a sandbox (${plan.reason}). The agent can read ${paths.home}. Use --sandbox on to make this an error.`,
  };
}

/**
 * Builds the agent's environment: real values never enter it.
 * - every brokered secret name maps to its placeholder
 * - RABBITLOCK_* (identity seed, test hooks) are removed
 * - any other variable whose value equals a brokered secret is removed
 * - proxy + CA trust variables point tools at the broker
 */
export function buildChildEnv(parentEnv, { placeholders, values, proxyUrl, ca, session, sandbox = "unknown" }) {
  const realValues = new Set(Object.values(values).filter((v) => v.length > 0));
  const env = {};
  for (const [key, value] of Object.entries(parentEnv)) {
    if (key.startsWith("RABBITLOCK_")) continue;
    if (realValues.has(value)) continue;
    env[key] = value;
  }
  for (const [name, placeholder] of placeholders) {
    env[name] = placeholder;
  }
  Object.assign(env, {
    HTTPS_PROXY: proxyUrl,
    https_proxy: proxyUrl,
    HTTP_PROXY: proxyUrl,
    http_proxy: proxyUrl,
    NODE_USE_ENV_PROXY: "1",
    NODE_EXTRA_CA_CERTS: ca.certPath,
    SSL_CERT_FILE: ca.bundlePath,
    REQUESTS_CA_BUNDLE: ca.bundlePath,
    CURL_CA_BUNDLE: ca.bundlePath,
    GIT_SSL_CAINFO: ca.bundlePath,
    RABBITLOCK_ACTIVE: "1",
    RABBITLOCK_SESSION: session,
    RABBITLOCK_SANDBOX: sandbox,
  });
  return env;
}

export async function runBrokered(policy, command, args, { quiet = false, sandbox = "auto" } = {}) {
  const seedFromEnv = Boolean(process.env.RABBITLOCK_SEED_HEX);
  const { privateKey } = keypairFromSeed(loadSeed());
  const stored = readSecretsFile(policy.secretsFile, privateKey);

  const names = Object.keys(policy.secrets);
  const missing = names.filter((name) => !(name in stored));
  if (missing.length > 0) {
    throw new Error(`Policy lists secrets not present in ${policy.secretsFile}: ${missing.join(", ")}. Add them with \`rabbitlock set NAME\`.`);
  }
  // Only secrets named in policy are brokered; anything else in the file stays unused.
  const values = Object.fromEntries(names.map((name) => [name, stored[name]]));

  const session = randomUUID();
  const placeholders = makePlaceholders(names);
  const ca = loadLocalCA();
  const receipt = createReceiptWriter(policy.receipts, session, values);
  const proxy = await startProxy({
    policy,
    placeholders,
    values,
    contextFor: createContextFactory(ca),
    approvalGate: createApprovalGate(policy),
    receipt,
  });

  const launch = planLaunch(
    command,
    args,
    protectedPaths({ home: rabbitlockHome(), policyPath: policy.path, secretsFile: policy.secretsFile, receiptsPath: policy.receipts }),
    { mode: sandbox, hideProcesses: seedFromEnv },
  );
  if (launch.warning) {
    process.stderr.write(`rabbitlock: WARNING: ${launch.warning}\n`);
  }

  receipt({ decision: "session_start", secrets: names, command, sandbox: launch.sandbox });
  if (!quiet) {
    process.stderr.write(
      `rabbitlock: brokering ${names.length} secret(s) [${names.join(", ")}] for \`${command}\` (sandbox: ${launch.sandbox}) via ${proxy.url}; receipts -> ${policy.receipts}\n`,
    );
  }

  for (const copy of findPlaintextCopies(path.dirname(policy.path), values)) {
    process.stderr.write(
      `rabbitlock: WARNING: ${copy.file} contains the real value of ${copy.secrets.join(", ")}, and the agent can read it. Delete it or remove those lines.\n`,
    );
  }

  const env = buildChildEnv(process.env, { placeholders, values, proxyUrl: proxy.url, ca, session, sandbox: launch.sandbox });

  return await new Promise((resolve, reject) => {
    const child = spawn(launch.command, launch.args, { stdio: "inherit", env });
    const forward = (signal) => child.kill(signal);
    process.on("SIGINT", forward);
    process.on("SIGTERM", forward);

    const finish = async (code) => {
      process.off("SIGINT", forward);
      process.off("SIGTERM", forward);
      receipt({ decision: "session_end", exitCode: code });
      await proxy.close();
      resolve(code);
    };

    child.on("error", async (err) => {
      await proxy.close();
      reject(new Error(`Failed to start ${command}: ${err.message}`));
    });
    child.on("exit", (code, signal) => finish(code ?? (signal ? 128 : 1)));
  });
}
