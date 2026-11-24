import crypto from "node:crypto";
import { spawnSync } from "node:child_process";

/**
 * Generated secrets for credentials the agent will set up but must never see (a new admin password,
 * a webhook signing secret). The value goes straight from here to the encrypted secrets file and, if
 * asked, to the human: never to the agent, argv or the environment.
 */

export const CHARSETS = {
  // Safe in URLs, JSON, form bodies, shells and most password rules that don't demand symbols.
  alnum: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
  hex: "0123456789abcdef",
  base64url: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
  // Printable ASCII without space, quotes, backslash or backtick, for systems that require a symbol.
  symbols: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,-./:;<=>?@[]^_{|}~",
};

export const DEFAULT_LENGTH = 32;
export const MIN_LENGTH = 16;
export const MAX_LENGTH = 256;

export function generateSecret({ length = DEFAULT_LENGTH, charset = "alnum" } = {}) {
  const alphabet = CHARSETS[charset];
  if (!alphabet) {
    throw new Error(`--charset must be one of: ${Object.keys(CHARSETS).join(", ")}`);
  }
  if (!Number.isInteger(length) || length < MIN_LENGTH || length > MAX_LENGTH) {
    throw new Error(`--length must be an integer from ${MIN_LENGTH} to ${MAX_LENGTH}`);
  }
  let value = "";
  for (let i = 0; i < length; i += 1) {
    value += alphabet[crypto.randomInt(alphabet.length)]; // unbiased
  }
  if (charset === "symbols" && !/[^A-Za-z0-9]/.test(value)) {
    // Rare (about 1 in 4 at length 16), but a "symbols" password must contain one.
    return generateSecret({ length, charset });
  }
  return value;
}

/** Entropy in bits, for the confirmation message. */
export function entropyBits(length, charset) {
  return Math.floor(length * Math.log2(CHARSETS[charset].length));
}

/**
 * Decide how the human gets the value. Exactly one mode is required, so nobody ends up with a
 * credential they can't use and didn't mean to discard.
 */
export function parseHandoff({ reveal, toCommand, noHandoff }) {
  const chosen = [reveal && "reveal", toCommand && "command", noHandoff && "none"].filter(Boolean);
  if (chosen.length !== 1) {
    throw new Error(
      "With --generate, choose how you get the value (exactly one):\n" +
        "  --reveal               show it once in this terminal\n" +
        "  --to-command 'CMD'     pipe it to CMD's stdin (for example a password manager)\n" +
        "  --no-handoff           nobody sees it; only agents can use it, through RabbitLock",
    );
  }
  return chosen[0] === "command" ? { mode: "command", command: toCommand } : { mode: chosen[0] };
}

/**
 * Deliver the value to the human. Runs before the value is stored, so a failed hand-off stores
 * nothing. `--reveal` refuses unless stdout is a terminal: when an agent runs this command its
 * output is captured, and the value would land in the agent's context.
 */
export function handOff(value, handoff, { stdout = process.stdout, spawn = spawnSync } = {}) {
  if (handoff.mode === "none") return;
  if (handoff.mode === "reveal") {
    if (!stdout.isTTY) {
      throw new Error(
        "--reveal only prints to an interactive terminal (output here is being captured, possibly by an agent). " +
          "Run it yourself in a terminal, or use --to-command.",
      );
    }
    stdout.write(`\n  ${value}\n\nShown once. Save it now; RabbitLock cannot show it again.\n`);
    return;
  }
  const shell = process.env.SHELL && process.platform !== "win32" ? process.env.SHELL : "/bin/sh";
  const result = spawn(shell, ["-c", handoff.command], {
    input: `${value}\n`,
    stdio: ["pipe", "inherit", "inherit"],
  });
  if (result.error) throw new Error(`--to-command failed to start: ${result.error.message}`);
  if (result.status !== 0) {
    throw new Error(`--to-command exited with status ${result.status}; nothing was stored.`);
  }
}
