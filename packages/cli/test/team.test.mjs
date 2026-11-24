import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

import { decryptSecrets, keypairFromSeed, readSecretsFile } from "../src/crypto.mjs";
import { parsePolicy } from "../src/policy.mjs";

const CLI = new URL("../bin/rabbitlock.mjs", import.meta.url).pathname;

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

test("policy: individual mode stores under RABBITLOCK_HOME; secrets_file and legacy policies stay in the repo", () => {
  const prev = process.env.RABBITLOCK_HOME;
  process.env.RABBITLOCK_HOME = "/home/test/.rabbitlock";
  try {
    const individual = parsePolicy("project: abc123def456\nsecrets: {}\n", "/repo/rabbitlock.agent.yaml");
    assert.equal(individual.mode, "individual");
    assert.equal(individual.secretsFile, "/home/test/.rabbitlock/projects/abc123def456/secrets.sops.json");
    assert.equal(individual.receipts, "/home/test/.rabbitlock/projects/abc123def456/receipts.jsonl");

    const team = parsePolicy("project: abc123def456\nsecrets_file: secrets.sops.json\nrecipients:\n  - { name: ana, key: AB12 }\n  - cd34\nsecrets: {}\n", "/repo/rabbitlock.agent.yaml");
    assert.equal(team.mode, "team");
    assert.equal(team.secretsFile, "/repo/secrets.sops.json");
    assert.deepEqual(team.recipients, ["ab12", "cd34"]);
    assert.deepEqual(team.recipientEntries, [{ name: "ana", key: "ab12" }, { name: null, key: "cd34" }]);

    const legacy = parsePolicy("secrets: {}\n", "/repo/rabbitlock.agent.yaml");
    assert.equal(legacy.secretsFile, "/repo/secrets.sops.json");
    assert.equal(legacy.receipts, "/repo/.rabbitlock/receipts.jsonl");

    assert.throws(() => parsePolicy("project: ../evil\n", "/repo/p.yaml"), /project must match/);
    assert.throws(() => parsePolicy("recipients:\n  - { name: x }\n", "/repo/p.yaml"), /recipients entries/);
  } finally {
    if (prev === undefined) delete process.env.RABBITLOCK_HOME;
    else process.env.RABBITLOCK_HOME = prev;
  }
});

test("CLI: individual by default, then team enable / add / remove / ls", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rl-team-"));
  const repo = path.join(dir, "repo");
  fs.mkdirSync(repo);
  const ownerEnv = { PATH: process.env.PATH, RABBITLOCK_HOME: path.join(dir, "owner") };
  const mateEnv = { PATH: process.env.PATH, RABBITLOCK_HOME: path.join(dir, "mate") };
  const policyFile = path.join(repo, "rabbitlock.agent.yaml");

  assert.equal((await runCli(["init"], { cwd: repo, env: ownerEnv })).code, 0);
  const project = /^project: (\S+)$/m.exec(fs.readFileSync(policyFile, "utf8"))[1];
  assert.equal((await runCli(["set", "API_TOKEN"], { cwd: repo, env: ownerEnv, input: "secret-value-123" })).code, 0);
  const homeFile = path.join(dir, "owner", "projects", project, "secrets.sops.json");
  assert.ok(fs.existsSync(homeFile));
  assert.ok(!fs.existsSync(path.join(repo, "secrets.sops.json")));
  assert.match((await runCli(["team", "ls"], { cwd: repo, env: ownerEnv })).stdout, /Individual mode/);

  // Team commands other than enable are refused in individual mode.
  const early = await runCli(["team", "add", "ab".repeat(40)], { cwd: repo, env: ownerEnv });
  assert.equal(early.code, 1);
  assert.match(early.stderr, /team enable/);

  const enable = await runCli(["team", "enable", "--name", "owner"], { cwd: repo, env: ownerEnv });
  assert.equal(enable.code, 0, enable.stderr);
  assert.ok(!fs.existsSync(homeFile), "moved, not copied");
  const repoFile = path.join(repo, "secrets.sops.json");
  const ownerKeys = keypairFromSeed(fs.readFileSync(path.join(dir, "owner", "identity"), "utf8").trim());
  assert.deepEqual(readSecretsFile(repoFile, ownerKeys.privateKey), { API_TOKEN: "secret-value-123" });
  const policyText = fs.readFileSync(policyFile, "utf8");
  assert.match(policyText, /^secrets_file: secrets\.sops\.json$/m);
  assert.match(policyText, /name: owner/);
  assert.match(policyText, /# RabbitLock policy/, "comments are preserved");
  const again = await runCli(["team", "enable"], { cwd: repo, env: ownerEnv });
  assert.match(again.stderr, /already on/);

  // Teammate: init in the same repo keeps the policy, prints their key.
  assert.equal((await runCli(["init"], { cwd: repo, env: mateEnv })).code, 0);
  const mateKey = (await runCli(["key"], { cwd: repo, env: mateEnv })).stdout.trim();
  const mateKeys = keypairFromSeed(fs.readFileSync(path.join(dir, "mate", "identity"), "utf8").trim());
  assert.equal(mateKey, mateKeys.publicKey);
  assert.throws(() => decryptSecrets(fs.readFileSync(repoFile, "utf8"), mateKeys.privateKey));

  const bad = await runCli(["team", "add", "not-a-key"], { cwd: repo, env: ownerEnv });
  assert.equal(bad.code, 1);
  assert.equal(fs.readFileSync(policyFile, "utf8"), policyText, "a bad key changes nothing");

  const add = await runCli(["team", "add", mateKey, "--name", "mate"], { cwd: repo, env: ownerEnv });
  assert.equal(add.code, 0, add.stderr);
  assert.deepEqual(readSecretsFile(repoFile, mateKeys.privateKey), { API_TOKEN: "secret-value-123" });
  const ls = (await runCli(["team", "ls"], { cwd: repo, env: mateEnv })).stdout;
  assert.match(ls, /^owner\s/m);
  assert.match(ls, /^mate\s.*\(you\)$/m);

  // The teammate can now run the CLI against the shared file.
  assert.match((await runCli(["ls"], { cwd: repo, env: mateEnv })).stdout, /API_TOKEN/);

  const self = await runCli(["team", "remove", "owner"], { cwd: repo, env: ownerEnv });
  assert.match(self.stderr, /can't remove yourself/);

  const remove = await runCli(["team", "remove", "mate"], { cwd: repo, env: ownerEnv });
  assert.equal(remove.code, 0, remove.stderr);
  assert.match(remove.stdout, /rotate API_TOKEN/);
  assert.throws(() => decryptSecrets(fs.readFileSync(repoFile, "utf8"), mateKeys.privateKey), "removed member can't decrypt new versions");
  assert.deepEqual(readSecretsFile(repoFile, ownerKeys.privateKey), { API_TOKEN: "secret-value-123" });
});
