import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);
const TIMEOUT_SECONDS = 120;

/**
 * Asks a human to approve a secret use. The agent owns the terminal, so we use an OS dialog.
 * Resolves to "once" | "session" | "deny". Anything unexpected is a deny.
 *
 * RABBITLOCK_APPROVER=allow|deny overrides the dialog (tests, CI, headless use).
 */
export async function askApproval({ secret, host, method, path }) {
  const forced = process.env.RABBITLOCK_APPROVER;
  if (forced === "allow") return "session";
  if (forced === "deny") return "deny";

  const message = `An agent wants to use ${secret}\n\n${method} https://${host}${path}\n\nAllow?`;

  try {
    if (process.platform === "darwin") {
      // Message is passed as argv, never interpolated into AppleScript source.
      const { stdout } = await run("osascript", [
        "-e", "on run argv",
        "-e", `display dialog (item 1 of argv) with title "RabbitLock" buttons {"Deny", "Allow once", "Allow for session"} default button "Deny" cancel button "Deny" giving up after ${TIMEOUT_SECONDS}`,
        "-e", "end run",
        message,
      ]);
      if (/gave up:true/.test(stdout)) return "deny";
      if (/button returned:Allow for session/.test(stdout)) return "session";
      if (/button returned:Allow once/.test(stdout)) return "once";
      return "deny";
    }

    if (process.platform === "linux") {
      try {
        await run("zenity", [
          "--question", "--title=RabbitLock", `--text=${message}`,
          "--ok-label=Allow once", "--cancel-label=Deny", "--extra-button=Allow for session",
          `--timeout=${TIMEOUT_SECONDS}`,
        ]);
        return "once";
      } catch (err) {
        if (typeof err.stdout === "string" && err.stdout.includes("Allow for session")) return "session";
        return "deny";
      }
    }
  } catch {
    return "deny";
  }

  process.stderr.write(
    `rabbitlock: no approval dialog available on ${process.platform}; denying ${secret}. Set RABBITLOCK_APPROVER to override.\n`,
  );
  return "deny";
}

/**
 * Serializes approval prompts and remembers per-session grants, so parallel requests
 * produce one dialog instead of a stack of them.
 */
export function createApprovalGate(policy, approver = askApproval) {
  const sessionApproved = new Set();
  let queue = Promise.resolve();

  return async function check(names, request) {
    for (const name of names) {
      const mode = policy.secrets[name].approval;
      if (mode === "never") continue;
      if (mode === "once" && sessionApproved.has(name)) continue;

      const pending = queue
        .then(async () => {
          if (mode === "once" && sessionApproved.has(name)) return "session";
          return approver({ secret: name, ...request });
        })
        .catch(() => "deny");
      queue = pending;
      const decision = await pending;

      if (decision === "deny") return { ok: false, secret: name };
      if (decision === "session") sessionApproved.add(name);
    }
    return { ok: true };
  };
}
