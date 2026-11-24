import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

import { keypairFromSeed, readSecretsFile } from "../src/crypto.mjs";
import { CHARSETS, entropyBits, generateSecret, handOff, parseHandoff } from "../src/generate.mjs";

const CLI = new URL("../bin/rabbitlock.mjs", import.meta.url).pathname;
const SEED = "4".repeat(64);

test("generated secrets have the requested length and alphabet", () => {
  for (const charset of Object.keys(CHARSETS)) {
    for (const length of [16, 32, 64]) {
      const value = generateSecret({ length, charset });
      assert.equal(value.length, length);
      for (const ch of value) assert.ok(CHARSETS[charset].includes(ch), `${ch} not in ${charset}`);
    }
  }
  assert.equal(generateSecret().length, 32);
  assert.match(generateSecret(), /^[A-Za-z0-9]{32}$/);
  for (let i = 0; i < 50; i += 1) {
    assert.match(generateSecret({ length: 16, charset: "symbols" }), /[^A-Za-z0-9]/, "symbols must include a symbol");
  }
  assert.notEqual(generateSecret(), generateSecret());
  assert.equal(entropyBits(32, "alnum"), 190);
});

test("generated characters are spread across the whole alphabet", () => {
  const counts = new Map();
  const sample = generateSecret({ length: 256, charset: "hex" }) + generateSecret({ length: 256, charset: "hex" });
  for (const ch of sample) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  assert.equal(counts.size, 16);
  for (const n of counts.values()) assert.ok(n > 8 && n < 64, `skewed count ${n}`);
});

test("rejects bad length and charset", () => {
  assert.throws(() => generateSecret({ length: 8 }), /--length/);
  assert.throws(() => generateSecret({ length: 1000 }), /--length/);
  assert.throws(() => generateSecret({ length: 20.5 }), /--length/);
  assert.throws(() => generateSecret({ charset: "emoji" }), /--charset/);
});

test("exactly one hand-off mode is required", () => {
  assert.throws(() => parseHandoff({}), /exactly one/);
  assert.throws(() => parseHandoff({ reveal: true, noHandoff: true }), /exactly one/);
  assert.deepEqual(parseHandoff({ reveal: true }), { mode: "reveal" });
  assert.deepEqual(parseHandoff({ noHandoff: true }), { mode: "none" });
  assert.deepEqual(parseHandoff({ toCommand: "pass insert -m x" }), { mode: "command", command: "pass insert -m x" });
});

test("--reveal refuses captured output and prints only to a terminal", () => {
  let written = "";
  const captured = { isTTY: false, write: (s) => (written += s) };
  assert.throws(() => handOff("s3cret-value", { mode: "reveal" }, { stdout: captured }), /interactive terminal/);
  assert.equal(written, "");
  const terminal = { isTTY: true, write: (s) => (written += s) };
  handOff("s3cret-value", { mode: "reveal" }, { stdout: terminal });
  assert.match(written, /s3cret-value/);
});

test("--to-command receives the value on stdin, not argv; failure throws", () => {
  const calls = [];
  const spawnOk = (cmd, args, opts) => {
    calls.push({ cmd, args, opts });
    return { status: 0 };
  };
  handOff("s3cret-value", { mode: "command", command: "pass insert -m db" }, { spawn: spawnOk });
  assert.equal(calls[0].opts.input, "s3cret-value\n");
  assert.ok(!calls[0].args.join(" ").includes("s3cret-value"), "value must not be in argv");
  assert.throws(
    () => handOff("x", { mode: "command", command: "false" }, { spawn: () => ({ status: 1 }) }),
    /nothing was stored/,
  );
});

function runCli(args, { cwd, env }) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { cwd, env, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.stdin.end("");
    child.on("exit", (code) => resolve({ code, stdout, stderr }));
  });
}

test("CLI: set --generate stores, hands off, refuses unsafe cases, and never logs the value", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rl-gen-"));
  fs.writeFileSync(path.join(dir, "rabbitlock.agent.yaml"), "secrets:\n  ADMIN_PASSWORD:\n    hosts: [admin.rabbitlock.test]\n");
  const env = { PATH: process.env.PATH, SHELL: "/bin/sh", RABBITLOCK_HOME: path.join(dir, "home"), RABBITLOCK_SEED_HEX: SEED };
  const { privateKey } = keypairFromSeed(SEED);
  const stored = () => readSecretsFile(path.join(dir, "secrets.sops.json"), privateKey);

  const noMode = await runCli(["set", "ADMIN_PASSWORD", "--generate"], { cwd: dir, env });
  assert.equal(noMode.code, 1);
  assert.match(noMode.stderr, /exactly one/);

  // Output is piped here, as it would be for an agent: --reveal must refuse and store nothing.
  const reveal = await runCli(["set", "ADMIN_PASSWORD", "--generate", "--reveal"], { cwd: dir, env });
  assert.equal(reveal.code, 1);
  assert.match(reveal.stderr, /interactive terminal/);
  assert.equal(stored().ADMIN_PASSWORD, undefined);

  const failed = await runCli(["set", "ADMIN_PASSWORD", "--generate", "--to-command", "exit 3"], { cwd: dir, env });
  assert.equal(failed.code, 1);
  assert.equal(stored().ADMIN_PASSWORD, undefined, "a failed hand-off stores nothing");

  const ok = await runCli(["set", "ADMIN_PASSWORD", "--generate", "--to-command", "cat > handed.txt"], { cwd: dir, env });
  assert.equal(ok.code, 0, ok.stderr);
  const handed = fs.readFileSync(path.join(dir, "handed.txt"), "utf8");
  assert.match(handed, /^[A-Za-z0-9]{32}\n$/);
  const value = handed.trim();
  assert.equal(stored().ADMIN_PASSWORD, value);
  assert.ok(!ok.stdout.includes(value) && !ok.stderr.includes(value), "CLI output must not contain the value");
  assert.ok(!fs.readFileSync(path.join(dir, "secrets.sops.json"), "utf8").includes(value));

  const receipts = fs.readFileSync(path.join(dir, ".rabbitlock", "receipts.jsonl"), "utf8");
  assert.ok(!receipts.includes(value));
  const receipt = JSON.parse(receipts.trim().split("\n").at(-1));
  assert.equal(receipt.decision, "generated");
  assert.deepEqual(receipt.secrets, ["ADMIN_PASSWORD"]);
  assert.match(receipt.command, /handoff: command/);

  const again = await runCli(["set", "ADMIN_PASSWORD", "--generate", "--no-handoff"], { cwd: dir, env });
  assert.equal(again.code, 1);
  assert.match(again.stderr, /already stored/);
  assert.equal(stored().ADMIN_PASSWORD, value);

  const forced = await runCli(
    ["set", "ADMIN_PASSWORD", "--generate", "--no-handoff", "--force", "--length", "48", "--charset", "base64url"],
    { cwd: dir, env },
  );
  assert.equal(forced.code, 0, forced.stderr);
  assert.match(stored().ADMIN_PASSWORD, /^[A-Za-z0-9_-]{48}$/);
  assert.notEqual(stored().ADMIN_PASSWORD, value);

  const misuse = await runCli(["set", "OTHER", "--reveal"], { cwd: dir, env });
  assert.equal(misuse.code, 1);
  assert.match(misuse.stderr, /only apply with --generate/);
});
