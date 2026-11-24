import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

/**
 * OS sandbox for the agent process. The broker stays outside it.
 *
 * Denied to the agent:
 *  - reading the identity seed and the local CA private key
 *  - writing anything under RABBITLOCK_HOME (so the CA and identity cannot be replaced)
 *  - writing the policy, the encrypted secrets file and the receipts (so an injected agent
 *    cannot widen its own policy for the next run or erase its tracks)
 *  - when the seed or passphrase came from the environment (RABBITLOCK_SEED_HEX, RABBITLOCK_PASSPHRASE):
 *    inspecting other processes, because on macOS
 *    and Linux a same-user process can otherwise read the broker's environment
 *
 * macOS uses Seatbelt (sandbox-exec). Linux uses bubblewrap (bwrap) with a private PID namespace.
 */

export const SANDBOX_MODES = new Set(["auto", "on", "off"]);

function real(p) {
  try {
    return fs.realpathSync(p);
  } catch {
    return path.resolve(p);
  }
}

function sbplString(p) {
  return `"${p.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

export function protectedPaths({ home, policyPath, secretsFile, receiptsPath }) {
  const realHome = real(home);
  return {
    home: realHome,
    noRead: [path.join(realHome, "identity"), path.join(realHome, "ca", "rabbitlock-ca.key")],
    noWrite: [real(policyPath), real(secretsFile), real(path.dirname(receiptsPath))],
  };
}

export function seatbeltProfile(paths, { hideProcesses }) {
  const lines = [
    "(version 1)",
    "(allow default)",
    `(deny file-read* ${paths.noRead.map((p) => `(literal ${sbplString(p)})`).join(" ")})`,
    `(deny file-write* (subpath ${sbplString(paths.home)}))`,
    `(deny file-write* ${paths.noWrite.map((p) => `(subpath ${sbplString(p)})`).join(" ")})`,
  ];
  if (hideProcesses) {
    lines.push("(deny process-info* (target others))");
  }
  return lines.join("\n");
}

export function bwrapArgs(paths, { hideProcesses }) {
  const args = ["--dev-bind", "/", "/", "--die-with-parent"];
  if (hideProcesses) {
    args.push("--unshare-pid", "--proc", "/proc");
  }
  // Read-only view of RABBITLOCK_HOME, then mask the private files with empty ones.
  args.push("--ro-bind", paths.home, paths.home);
  for (const file of paths.noRead) {
    if (fs.existsSync(file)) args.push("--ro-bind", "/dev/null", file);
  }
  for (const target of paths.noWrite) {
    if (fs.existsSync(target)) args.push("--ro-bind", target, target);
  }
  return args;
}

function which(bin) {
  return spawnSync("sh", ["-c", `command -v ${bin}`], { encoding: "utf8" }).stdout.trim() || null;
}

/**
 * Returns how to launch `command args` inside the sandbox, or the reason it cannot be sandboxed.
 * A preflight run catches environments where the sandbox exists but cannot be applied
 * (for example when RabbitLock itself already runs inside a sandbox).
 */
export function planSandbox(command, args, paths, { hideProcesses, platform = process.platform } = {}) {
  if (platform === "darwin") {
    const tool = which("sandbox-exec");
    if (!tool) return { ok: false, reason: "sandbox-exec not found" };
    const profile = seatbeltProfile(paths, { hideProcesses });
    const preflight = spawnSync(tool, ["-p", profile, "/usr/bin/true"], { encoding: "utf8" });
    if (preflight.status !== 0) {
      return { ok: false, reason: `sandbox-exec cannot apply a profile here (${preflight.stderr.trim() || `exit ${preflight.status}`})` };
    }
    return { ok: true, kind: "seatbelt", command: tool, args: ["-p", profile, command, ...args] };
  }

  if (platform === "linux") {
    const tool = which("bwrap");
    if (!tool) return { ok: false, reason: "bubblewrap (bwrap) not installed" };
    const wrap = bwrapArgs(paths, { hideProcesses });
    const preflight = spawnSync(tool, [...wrap, "--", "true"], { encoding: "utf8" });
    if (preflight.status !== 0) {
      return { ok: false, reason: `bwrap cannot create a sandbox here (${preflight.stderr.trim() || `exit ${preflight.status}`})` };
    }
    return { ok: true, kind: "bwrap", command: tool, args: [...wrap, "--", command, ...args] };
  }

  return { ok: false, reason: `no sandbox support on ${platform}` };
}
