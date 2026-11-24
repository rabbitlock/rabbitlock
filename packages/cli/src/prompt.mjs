import fs from "node:fs";
import tty from "node:tty";

/** Reads a line without echoing it. `input` must be a TTY stream; the prompt goes to `output`. */
export function readHidden(label, { input = process.stdin, output = process.stderr } = {}) {
  output.write(label);
  return new Promise((resolve, reject) => {
    let value = "";
    input.setRawMode(true);
    input.resume();
    input.setEncoding("utf8");
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n" || ch === "\u0004") {
          cleanup();
          output.write("\n");
          resolve(value);
          return;
        }
        if (ch === "\u0003") {
          cleanup();
          output.write("\n");
          reject(new Error("Cancelled."));
          return;
        }
        if (ch === "\u007f" || ch === "\b") value = value.slice(0, -1);
        else value += ch;
      }
    };
    const cleanup = () => {
      input.off("data", onData);
      input.setRawMode(false);
      input.pause();
    };
    input.on("data", onData);
  });
}

/**
 * Prompts on the controlling terminal (/dev/tty), so it works even when stdin is piped, and fails
 * cleanly when there is no terminal (for example inside an agent's shell tool).
 * Returns null when no terminal is available.
 */
export async function promptTerminal(label) {
  let fd;
  try {
    fd = fs.openSync("/dev/tty", "r+");
  } catch {
    return null;
  }
  const input = new tty.ReadStream(fd); // owns fd; destroy() closes it
  const output = { write: (s) => fs.writeSync(fd, s) };
  try {
    return await readHidden(label, { input, output });
  } finally {
    input.destroy();
  }
}
