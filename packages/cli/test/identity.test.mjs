import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

import { keypairFromSeed, protectSeed, unlockSeed } from "../src/crypto.mjs";

const CLI = new URL("../bin/rabbitlock.mjs", import.meta.url).pathname;
const PASS = "correct horse battery staple";

function runCli(args, { cwd, env, input = "" }) {
  return new Promise((resolve) => {
    // detached: no controlling terminal, as in an agent's shell tool, so a prompt can't hang the test.
    const child = spawn(process.execPath, [CLI, ...args], { cwd, env, stdio: ["pipe", "pipe", "pipe"], detached: true });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.stdin.end(input);
    child.on("exit", (code) => resolve({ code, stdout, stderr }));
  });
}

const mode = (file) => fs.statSync(file).mode & 0o777;

test("protectSeed/unlockSeed: round-trip, wrong passphrase, tampering, short passphrase", () => {
  const seed = "ab".repeat(32);
  const envelope = protectSeed(seed, PASS);
  assert.ok(!JSON.stringify(envelope).includes(seed), "seed is not stored in clear");
  assert.equal(envelope.public_key, keypairFromSeed(seed).publicKey);
  assert.equal(unlockSeed(envelope, PASS), seed);
  assert.throws(() => unlockSeed(envelope, `${PASS}!`), /Wrong passphrase/);
  // Swapping the clear public key (e.g. so `rabbitlock key` hands out someone else's) is detected.
  const swapped = { ...envelope, public_key: keypairFromSeed("cd".repeat(32)).publicKey };
  assert.throws(() => unlockSeed(swapped, PASS), /Wrong passphrase/);
  assert.throws(() => protectSeed(seed, "short"), /at least 12/);
});

test("CLI: key protect, use without a terminal, status/ls/key without the passphrase, unprotect; files are 0600", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rl-identity-"));
  const home = path.join(dir, "home");
  const env = { PATH: process.env.PATH, RABBITLOCK_HOME: home };
  const idFile = path.join(home, "identity");

  assert.equal((await runCli(["init"], { cwd: dir, env })).code, 0);
  const policyFile = path.join(dir, "rabbitlock.agent.yaml");
  fs.writeFileSync(policyFile, fs.readFileSync(policyFile, "utf8").replace(/^secrets: \{\}$/m, "secrets:\n  API_TOKEN:\n    hosts: [api.example.com]"));
  const plainSeed = fs.readFileSync(idFile, "utf8").trim();
  const publicKey = (await runCli(["key"], { cwd: dir, env })).stdout.trim();

  assert.equal((await runCli(["set", "API_TOKEN"], { cwd: dir, env, input: "token-value-123456" })).code, 0);
  const project = /^project: (\S+)$/m.exec(fs.readFileSync(policyFile, "utf8"))[1];
  const secretsFile = path.join(home, "projects", project, "secrets.sops.json");
  assert.equal(mode(secretsFile), 0o600, "secrets file is owner-only");
  assert.equal(mode(path.dirname(secretsFile)), 0o700);
  assert.equal(mode(idFile), 0o600);

  // Protect: new passphrase from stdin (automation path); short ones are refused without changing anything.
  const short = await runCli(["key", "protect"], { cwd: dir, env, input: "short" });
  assert.notEqual(short.code, 0);
  assert.equal(fs.readFileSync(idFile, "utf8").trim(), plainSeed);
  const protect = await runCli(["key", "protect"], { cwd: dir, env, input: PASS });
  assert.equal(protect.code, 0, protect.stderr);
  assert.match(protect.stdout, /no recovery/);
  const stored = fs.readFileSync(idFile, "utf8");
  assert.ok(!stored.includes(plainSeed), "the seed is no longer in the file");
  assert.equal(mode(idFile), 0o600);
  assert.deepEqual(fs.readdirSync(home).filter((f) => f.endsWith(".tmp")), [], "no temp files left behind");

  // No passphrase, no terminal: commands that need the key fail clearly instead of hanging.
  const locked = await runCli(["set", "OTHER"], { cwd: dir, env, input: "x" });
  assert.notEqual(locked.code, 0);
  assert.match(locked.stderr, /passphrase-protected and there is no terminal/);
  const wrong = await runCli(["set", "OTHER"], { cwd: dir, env: { ...env, RABBITLOCK_PASSPHRASE: "not the passphrase" }, input: "x" });
  assert.match(wrong.stderr, /Wrong passphrase/);

  // Read-only commands work without it.
  assert.equal((await runCli(["key"], { cwd: dir, env })).stdout.trim(), publicKey);
  assert.match((await runCli(["ls"], { cwd: dir, env })).stdout, /API_TOKEN\s+api\.example\.com/);
  const status = JSON.parse((await runCli(["status", "--json"], { cwd: dir, env })).stdout);
  assert.equal(status.identity.protected, true);
  assert.deepEqual(status.stored, ["API_TOKEN"]);
  assert.deepEqual(status.missingValues, []);
  assert.match((await runCli(["status"], { cwd: dir, env })).stdout, /passphrase-protected/);

  // With the passphrase, the key works and the same secrets decrypt.
  const unlocked = { ...env, RABBITLOCK_PASSPHRASE: PASS };
  assert.equal((await runCli(["set", "OTHER"], { cwd: dir, env: unlocked, input: "other-value-7890" })).code, 0);
  const inside = await runCli(["run", "--quiet", "--sandbox", "off", "--", process.execPath, "-e", "console.log(process.env.API_TOKEN, process.env.RABBITLOCK_PASSPHRASE ?? 'none')"], { cwd: dir, env: unlocked });
  assert.equal(inside.code, 0, inside.stderr);
  assert.match(inside.stdout, /^rl_ph_API_TOKEN_[0-9a-f]{32} none$/m, "agent gets a placeholder and never the passphrase");

  // Change, then remove the passphrase.
  assert.equal((await runCli(["key", "protect"], { cwd: dir, env: unlocked, input: `${PASS} v2` })).code, 0);
  assert.match((await runCli(["set", "X"], { cwd: dir, env: unlocked, input: "x" })).stderr, /Wrong passphrase/);
  const unprotect = await runCli(["key", "unprotect"], { cwd: dir, env: { ...env, RABBITLOCK_PASSPHRASE: `${PASS} v2` } });
  assert.equal(unprotect.code, 0, unprotect.stderr);
  assert.equal(fs.readFileSync(idFile, "utf8").trim(), plainSeed, "the same identity comes back");
  assert.equal(mode(idFile), 0o600);
});
