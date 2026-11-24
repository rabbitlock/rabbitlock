import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

import { AGENTS_BLOCK, ensureClaudeImport, upsertAgentsBlock } from "../src/agentsmd.mjs";
import { keypairFromSeed, readSecretsFile } from "../src/crypto.mjs";
import { parseDotenv } from "../src/dotenv.mjs";
import { findPlaintextCopies, sessionFromEnv } from "../src/status.mjs";

const CLI = new URL("../bin/rabbitlock.mjs", import.meta.url).pathname;
const SEED = "6".repeat(64);

test("parseDotenv handles the common .env forms and reports bad lines without values", () => {
  const text = [
    "# comment",
    "",
    "PLAIN=abc123",
    "export EXPORTED=with-export",
    "SPACED = padded value   # trailing comment",
    'DOUBLE="line1\\nline2 \\"quoted\\""',
    "SINGLE='lit\\n # not a comment'",
    'PEM="-----BEGIN KEY-----',
    "abc",
    '-----END KEY-----"',
    "HASH=pass#word",
    "EMPTY=",
    "this is not valid",
    'UNTERMINATED="oops',
  ].join("\n");
  const { entries, errors } = parseDotenv(text);
  const map = Object.fromEntries(entries);
  assert.equal(map.PLAIN, "abc123");
  assert.equal(map.EXPORTED, "with-export");
  assert.equal(map.SPACED, "padded value");
  assert.equal(map.DOUBLE, 'line1\nline2 "quoted"');
  assert.equal(map.SINGLE, "lit\\n # not a comment");
  assert.equal(map.PEM, "-----BEGIN KEY-----\nabc\n-----END KEY-----");
  assert.equal(map.HASH, "pass#word", "a # without a preceding space is part of the value");
  assert.equal(map.EMPTY, "");
  assert.deepEqual(errors.map((e) => e.line), [13, 14]);
  assert.ok(!JSON.stringify(errors).includes("oops"));
});

test("AGENTS.md block is inserted once and updated in place; CLAUDE.md gets an import", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rl-agents-"));
  const file = path.join(dir, "AGENTS.md");
  assert.equal(upsertAgentsBlock(file), "created");
  assert.equal(upsertAgentsBlock(file), "unchanged");
  fs.writeFileSync(file, `# Project\n\nOwn notes.\n\n${AGENTS_BLOCK.replace("Run `rabbitlock status`", "OLD TEXT")}\n\nMore notes.\n`);
  assert.equal(upsertAgentsBlock(file), "updated");
  const text = fs.readFileSync(file, "utf8");
  assert.equal(text.split("rabbitlock:start").length, 2, "exactly one block");
  assert.ok(text.includes("Own notes.") && text.includes("More notes.") && !text.includes("OLD TEXT"));

  assert.equal(ensureClaudeImport(dir), "absent");
  fs.writeFileSync(path.join(dir, "CLAUDE.md"), "# Claude\n");
  assert.equal(ensureClaudeImport(dir), "updated");
  assert.equal(ensureClaudeImport(dir), "unchanged");
  assert.match(fs.readFileSync(path.join(dir, "CLAUDE.md"), "utf8"), /^@AGENTS\.md$/m);
});

test("sessionFromEnv only counts placeholders that match their variable name", () => {
  const s = sessionFromEnv({
    RABBITLOCK_ACTIVE: "1",
    RABBITLOCK_SESSION: "abc",
    RABBITLOCK_SANDBOX: "seatbelt",
    GITHUB_TOKEN: `rl_ph_GITHUB_TOKEN_${"a".repeat(32)}`,
    COPY: `rl_ph_GITHUB_TOKEN_${"a".repeat(32)}`,
    OTHER: "plain",
  });
  assert.deepEqual(s, { active: true, id: "abc", sandbox: "seatbelt", brokered: ["GITHUB_TOKEN"] });
  assert.equal(sessionFromEnv({}).active, false);
});

test("findPlaintextCopies flags .env files holding real values and ignores templates", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rl-copies-"));
  fs.writeFileSync(path.join(dir, ".env"), "A=real-value-aaaa\nB=other\n");
  fs.writeFileSync(path.join(dir, ".env.local"), "B=real-value-bbbb\n");
  fs.writeFileSync(path.join(dir, ".env.example"), "A=real-value-aaaa\n");
  fs.writeFileSync(path.join(dir, "notes.txt"), "real-value-aaaa\n");
  const copies = findPlaintextCopies(dir, { A: "real-value-aaaa", B: "real-value-bbbb", SHORT: "x" });
  assert.deepEqual(copies, [
    { file: ".env", secrets: ["A"] },
    { file: ".env.local", secrets: ["B"] },
  ]);
});

function runCli(args, { cwd, env, input = "" }) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { cwd, env, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.stdin.end(input);
    child.on("exit", (code) => resolve({ code, stdout, stderr }));
  });
}

test("CLI: init --agents-md, import, and status walk a new project to ready", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rl-onboard-"));
  const home = path.join(dir, "home");
  const env = { PATH: process.env.PATH, RABBITLOCK_HOME: home };
  fs.writeFileSync(path.join(dir, "CLAUDE.md"), "# Project rules\n");

  const version = await runCli(["--version"], { cwd: dir, env });
  assert.equal(version.stdout.trim(), JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8")).version);

  const before = JSON.parse((await runCli(["status", "--json"], { cwd: dir, env })).stdout);
  assert.equal(before.session.active, false);
  assert.match(before.nextSteps[0], /rabbitlock init/);

  const init = await runCli(["init", "--agents-md"], { cwd: dir, env });
  assert.equal(init.code, 0, init.stderr);
  assert.match(fs.readFileSync(path.join(dir, "AGENTS.md"), "utf8"), /Credentials \(RabbitLock\)/);
  assert.match(fs.readFileSync(path.join(dir, "CLAUDE.md"), "utf8"), /^@AGENTS\.md$/m);

  const real = { GITHUB_TOKEN: "ghp_realvalue_1234567890", STRIPE_KEY: "sk_test_realvalue_0987" };
  fs.writeFileSync(path.join(dir, ".env"), `GITHUB_TOKEN=${real.GITHUB_TOKEN}\nSTRIPE_KEY="${real.STRIPE_KEY}"\nlower_case=x\n`);
  const imp = await runCli(["import", ".env"], { cwd: dir, env });
  assert.equal(imp.code, 0, imp.stderr);
  assert.match(imp.stdout, /Imported 2: GITHUB_TOKEN, STRIPE_KEY/);
  assert.match(imp.stdout, /Skipped: lower_case/);
  assert.match(imp.stdout, /GITHUB_TOKEN:\n {4}hosts: \[<host>\]/);
  assert.match(imp.stdout, /still holds the plaintext values/);
  for (const v of Object.values(real)) assert.ok(!imp.stdout.includes(v) && !imp.stderr.includes(v), "import never prints values");
  const { privateKey } = keypairFromSeed(fs.readFileSync(path.join(home, "identity"), "utf8").trim());
  assert.deepEqual(readSecretsFile(path.join(dir, "secrets.sops.json"), privateKey), real);

  // Re-import with a changed value is refused without --force.
  fs.writeFileSync(path.join(dir, ".env.new"), "GITHUB_TOKEN=changed-value-123456\n");
  const conflict = await runCli(["import", ".env.new", "--delete"], { cwd: dir, env });
  assert.match(conflict.stdout, /already stored with a different value/);
  assert.match(conflict.stdout, /Not deleting/);
  assert.ok(fs.existsSync(path.join(dir, ".env.new")));

  // Add GITHUB_TOKEN to the policy; status shows the leftover .env and what's not brokered.
  const policyFile = path.join(dir, "rabbitlock.agent.yaml");
  fs.writeFileSync(policyFile, fs.readFileSync(policyFile, "utf8").replace(/^secrets: \{\}$/m, "secrets:\n  GITHUB_TOKEN:\n    hosts: [api.github.com]"));
  const mid = JSON.parse((await runCli(["status", "--json"], { cwd: dir, env })).stdout);
  assert.deepEqual(mid.stored, ["GITHUB_TOKEN", "STRIPE_KEY"]);
  assert.deepEqual(mid.notInPolicy, ["STRIPE_KEY"]);
  assert.deepEqual(mid.plaintextCopies, [{ file: ".env", secrets: ["GITHUB_TOKEN"] }]);
  assert.ok(mid.nextSteps.some((s) => s.includes("Delete or move .env")));
  assert.ok(!JSON.stringify(mid).includes(real.GITHUB_TOKEN));

  fs.unlinkSync(path.join(dir, ".env"));
  fs.unlinkSync(path.join(dir, ".env.new"));
  const ready = await runCli(["status"], { cwd: dir, env });
  assert.match(ready.stdout, /rabbitlock run -- claude/);

  // Inside a session, the agent can check itself (here under the default sandbox).
  const inside = await runCli(["run", "--quiet", "--", process.execPath, CLI, "status", "--json"], { cwd: dir, env: { ...env, HOME: dir } });
  assert.equal(inside.code, 0, inside.stderr);
  const s = JSON.parse(inside.stdout);
  assert.equal(s.session.active, true);
  assert.deepEqual(s.session.brokered, ["GITHUB_TOKEN"]);
  assert.ok(["seatbelt", "bwrap", "unavailable"].includes(s.session.sandbox), s.session.sandbox);
  assert.equal(s.stored, null, "the identity isn't read inside a session");
  assert.deepEqual(s.policy.secrets.GITHUB_TOKEN.hosts, ["api.github.com"]);
  assert.ok(!inside.stdout.includes(real.GITHUB_TOKEN));
});
