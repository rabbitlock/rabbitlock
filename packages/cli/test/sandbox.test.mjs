import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

import { bwrapArgs, planSandbox, protectedPaths, seatbeltProfile } from "../src/sandbox.mjs";
import { claudeSessionSettings, planLaunch } from "../src/run.mjs";

const CLI = new URL("../bin/rabbitlock.mjs", import.meta.url).pathname;

function fixture() {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "rl-sbx-")));
  const home = path.join(dir, "home");
  fs.mkdirSync(path.join(home, "ca"), { recursive: true });
  fs.writeFileSync(path.join(home, "identity"), "SEED\n");
  fs.writeFileSync(path.join(home, "ca", "rabbitlock-ca.key"), "KEY\n");
  fs.writeFileSync(path.join(home, "ca", "rabbitlock-ca.pem"), "CERT\n");
  fs.writeFileSync(path.join(dir, "rabbitlock.agent.yaml"), "secrets: {}\n");
  fs.writeFileSync(path.join(dir, "secrets.sops.json"), "{}\n");
  fs.mkdirSync(path.join(dir, ".rabbitlock"));
  const paths = protectedPaths({
    home,
    policyPath: path.join(dir, "rabbitlock.agent.yaml"),
    secretsFile: path.join(dir, "secrets.sops.json"),
    receiptsPath: path.join(dir, ".rabbitlock", "receipts.jsonl"),
  });
  return { dir, home, paths };
}

test("seatbelt profile denies key reads and protected writes; hides processes only when asked", () => {
  const { paths } = fixture();
  const profile = seatbeltProfile(paths, { hideProcesses: false });
  assert.match(profile, /\(deny file-read\* \(literal ".*\/identity"\) \(literal ".*rabbitlock-ca\.key"\)\)/);
  assert.match(profile, /\(deny file-write\* \(subpath ".*\/home"\)\)/);
  assert.ok(profile.includes("rabbitlock.agent.yaml"));
  assert.ok(!profile.includes("process-info"));
  assert.ok(seatbeltProfile(paths, { hideProcesses: true }).includes("(deny process-info* (target others))"));
  assert.ok(seatbeltProfile({ ...paths, home: '/a"b' }, { hideProcesses: false }).includes('"/a\\"b"'));
});

test("bwrap args mask keys, make protected paths read-only, isolate PIDs when asked", () => {
  const { paths } = fixture();
  const args = bwrapArgs(paths, { hideProcesses: true });
  assert.ok(args.includes("--unshare-pid"));
  const masked = args.map((a, i) => (a === "/dev/null" ? args[i + 1] : null)).filter(Boolean);
  assert.deepEqual(masked, paths.noRead);
  assert.ok(!bwrapArgs(paths, { hideProcesses: false }).includes("--unshare-pid"));
});

test("claude gets session settings instead of a nested OS sandbox", () => {
  const { paths } = fixture();
  const plan = planLaunch("/usr/local/bin/claude", ["--resume"], paths, { mode: "auto", hideProcesses: false });
  assert.equal(plan.sandbox, "claude-settings");
  assert.equal(plan.args[0], "--settings");
  assert.equal(plan.args.at(-1), "--resume");
  const settings = JSON.parse(plan.args[1]);
  assert.deepEqual(settings, claudeSessionSettings(paths));
  assert.equal(settings.sandbox.failIfUnavailable, true);
  assert.equal(settings.sandbox.allowUnsandboxedCommands, false);
  assert.deepEqual(settings.sandbox.filesystem.denyRead, paths.noRead);
  assert.ok(settings.permissions.deny.includes(`Read(/${paths.noRead[0]})`));
  assert.equal(planLaunch("claude", [], paths, { mode: "off", hideProcesses: false }).sandbox, "off");
});

const available = planSandbox("true", [], fixture().paths, { hideProcesses: true }).ok;

test("sandboxed agent cannot read keys, rewrite policy/receipts, or read the broker's env", { skip: !available && "no OS sandbox here" }, async () => {
  const { dir, home } = fixture();
  fs.rmSync(path.join(dir, "secrets.sops.json"));
  fs.rmSync(path.join(home, "ca"), { recursive: true }); // the broker creates a real CA
  const env = {
    PATH: process.env.PATH,
    RABBITLOCK_HOME: home,
    RABBITLOCK_SEED_HEX: "4".repeat(64),
    T_IDENTITY: path.join(home, "identity"),
    T_CAKEY: path.join(home, "ca", "rabbitlock-ca.key"),
    T_CACERT: path.join(home, "ca", "rabbitlock-ca.pem"),
    T_POLICY: path.join(dir, "rabbitlock.agent.yaml"),
    T_RECEIPTS: path.join(dir, ".rabbitlock", "receipts.jsonl"),
  };
  const script = [
    'r() { if "$@" >/dev/null 2>&1; then echo allowed; else echo denied; fi; }',
    'r cat "$T_IDENTITY"',
    'r cat "$T_CAKEY"',
    'r cat "$T_CACERT"',
    "r sh -c 'echo \"  EVIL: { hosts: [evil.example] }\" >> \"$T_POLICY\"'",
    "r sh -c 'echo forged >> \"$T_RECEIPTS\"'",
    "r sh -c 'ps -E -ww -o command= -p $PPID | grep -q RABBITLOCK_SEED_HEX'",
  ].join("\n");
  const out = await new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, "run", "--quiet", "--sandbox", "on", "--", "sh", "-c", script], { cwd: dir, env });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("exit", (code) => resolve({ code, stdout, stderr }));
  });
  assert.equal(out.code, 0, out.stderr);
  assert.deepEqual(out.stdout.trim().split("\n"), ["denied", "denied", "allowed", "denied", "denied", "denied"]);
  assert.equal(fs.readFileSync(env.T_POLICY, "utf8"), "secrets: {}\n");
  assert.ok(!fs.readFileSync(env.T_RECEIPTS, "utf8").includes("forged"));
});
