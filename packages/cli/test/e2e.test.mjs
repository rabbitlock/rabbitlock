import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import forge from "node-forge";

import { createCertificateAuthority, issueLeaf } from "../src/ca.mjs";

const CLI = new URL("../bin/rabbitlock.mjs", import.meta.url).pathname;
const SEED = "3".repeat(64);
const GOOD = "real-good-secret-1234567890";
const GATED = "real-gated-secret-0987654321";
const HOSTS = ["api.rabbitlock.test", "billing.rabbitlock.test", "other.rabbitlock.test"];
const hasCurl = spawnSync("curl", ["--version"]).status === 0;

function startUpstream(dir) {
  const ca = createCertificateAuthority("Test Upstream CA");
  const caFile = path.join(dir, "upstream-ca.pem");
  fs.writeFileSync(caFile, ca.certPem);

  const { privateKey } = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const leafKeys = { privateKey, publicKey: forge.pki.setRsaPublicKey(privateKey.n, privateKey.e) };
  const keyPem = forge.pki.privateKeyToPem(privateKey);
  const contexts = Object.fromEntries(
    HOSTS.map((h) => [h, tls.createSecureContext({ key: keyPem, cert: issueLeaf(ca, h, leafKeys) })]),
  );

  const seen = [];
  const server = https.createServer(
    {
      SNICallback: (name, cb) => cb(null, contexts[name]),
      ...{ key: keyPem, cert: issueLeaf(ca, HOSTS[0], leafKeys) },
    },
    (req, res) => {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        seen.push({
          host: req.headers.host,
          url: req.url,
          authorization: req.headers.authorization ?? "",
          body: Buffer.concat(chunks).toString("utf8"),
          contentLength: req.headers["content-length"],
        });
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("ok\n");
      });
    },
  );
  return new Promise((resolve) =>
    server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port, caFile, seen })),
  );
}

function runCli(args, { cwd, env, input }) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { cwd, env, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.stdin.end(input ?? "");
    child.on("exit", (code) => resolve({ code, stdout, stderr }));
  });
}

test("init creates identity, policy and CA", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rl-init-"));
  const env = { PATH: process.env.PATH, RABBITLOCK_HOME: path.join(dir, "home") };
  const out = await runCli(["init"], { cwd: dir, env });
  assert.equal(out.code, 0, out.stderr);
  const identity = path.join(dir, "home", "identity");
  assert.equal(fs.statSync(identity).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.join(dir, "home", "ca", "rabbitlock-ca.key")).mode & 0o777, 0o600);
  assert.match(fs.readFileSync(path.join(dir, "rabbitlock.agent.yaml"), "utf8"), /recipients:\n {2}- [0-9a-f]+/);
});

test("broker injects only for allowed hosts, gates approvals, and never leaks values", { skip: !hasCurl && "curl not installed" }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rl-e2e-"));
  const upstream = await startUpstream(dir);

  fs.writeFileSync(
    path.join(dir, "rabbitlock.agent.yaml"),
    `secrets:
  GOOD_TOKEN:
    hosts: [api.rabbitlock.test]
  GATED_TOKEN:
    hosts: [api.rabbitlock.test]
    approval: every
  BILLING_TOKEN:
    hosts: [billing.rabbitlock.test]
`,
  );

  const route = HOSTS.map((h) => `${h}=127.0.0.1:${upstream.port}`).join(",");
  const baseEnv = Object.fromEntries(
    Object.entries(process.env).filter(([k]) => !/^(no_proxy|https?_proxy|all_proxy)$/i.test(k) && !k.startsWith("RABBITLOCK_")),
  );
  const env = {
    ...baseEnv,
    RABBITLOCK_HOME: path.join(dir, "home"),
    RABBITLOCK_SEED_HEX: SEED,
    RABBITLOCK_TEST_UPSTREAM: route,
    RABBITLOCK_TEST_UPSTREAM_CA: upstream.caFile,
    RABBITLOCK_APPROVER: "deny",
    LEAKY_COPY: GOOD,
    TEST_UPSTREAM_CA_FILE: upstream.caFile,
  };

  for (const [name, value] of [["GOOD_TOKEN", GOOD], ["GATED_TOKEN", GATED], ["BILLING_TOKEN", "billing-value-xyz"]]) {
    const set = await runCli(["set", name], { cwd: dir, env, input: value });
    assert.equal(set.code, 0, set.stderr);
  }
  assert.ok(!fs.readFileSync(path.join(dir, "secrets.sops.json"), "utf8").includes(GOOD));

  const script = [
    'c() { curl -s -o /dev/null -w "%{http_code}\\n" "$@"; }',
    'c -H "Authorization: Bearer $GOOD_TOKEN" https://api.rabbitlock.test/good',
    'c -H "Authorization: Bearer $GOOD_TOKEN" https://billing.rabbitlock.test/wrong-host',
    // Unlisted hosts are tunneled untouched, so the client sees the upstream's real cert.
    'c --cacert "$TEST_UPSTREAM_CA_FILE" -H "Authorization: Bearer $GOOD_TOKEN" https://other.rabbitlock.test/unlisted',
    'c -u "x-access-token:$GOOD_TOKEN" https://api.rabbitlock.test/basic',
    'c -H "Authorization: Bearer $GATED_TOKEN" https://api.rabbitlock.test/gated',
    'c "https://api.rabbitlock.test/query?key=$GOOD_TOKEN"',
    // Spoofed Host header: connected to billing (not allowed for GOOD_TOKEN) but claims api.
    'c -H "Host: api.rabbitlock.test" -H "Authorization: Bearer $GOOD_TOKEN" https://billing.rabbitlock.test/spoofed',
    // Cleartext: never injected.
    'c -H "Authorization: Bearer $GOOD_TOKEN" http://api.rabbitlock.test/cleartext',
    // Bodies: JSON and form are rewritten on allowed hosts; wrong host is blocked; >1 MiB passes untouched.
    'c -H "Content-Type: application/json" -d "{\\"api_key\\":\\"$GOOD_TOKEN\\"}" https://api.rabbitlock.test/json',
    'c -H "Content-Type: application/x-www-form-urlencoded" -d "key=$GOOD_TOKEN&x=1" https://api.rabbitlock.test/form',
    'c -H "Content-Type: application/json" -d "{\\"api_key\\":\\"$GOOD_TOKEN\\"}" https://billing.rabbitlock.test/json-wrong-host',
    'big=$(head -c 1100000 /dev/zero | tr "\\0" a); printf "{\\"k\\":\\"%s\\",\\"pad\\":\\"%s\\"}" "$GOOD_TOKEN" "$big" > big.json; c -H "Content-Type: application/json" --data-binary @big.json https://api.rabbitlock.test/big',
    'echo "ENV $GOOD_TOKEN ${RABBITLOCK_SEED_HEX:-noseed} ${LEAKY_COPY:-nocopy}"',
  ].join("\n");

  const run = await runCli(["run", "--quiet", "--", "sh", "-c", script], { cwd: dir, env });
  upstream.server.close();
  assert.equal(run.code, 0, run.stderr);

  const lines = run.stdout.trim().split("\n");
  const [good, wrongHost, unlisted, basic, gated, query, spoofed, cleartext, jsonBody, formBody, jsonWrongHost, bigBody, envLine] = lines;
  assert.equal(good, "200", `stdout: ${run.stdout}\nstderr: ${run.stderr}`);
  assert.equal(wrongHost, "403");
  assert.equal(unlisted, "200");
  assert.equal(basic, "200");
  assert.equal(gated, "403");
  assert.equal(query, "200");
  assert.equal(spoofed, "403", "policy must use the CONNECT target, not the Host header");
  assert.equal(cleartext, "403", "secrets must never be injected over plain HTTP");
  assert.equal(jsonBody, "200");
  assert.equal(formBody, "200");
  assert.equal(jsonWrongHost, "403", "a placeholder in a body is held to the same host policy");
  assert.equal(bigBody, "200");

  const [, placeholder, seed, copy] = envLine.split(" ");
  assert.match(placeholder, /^rl_ph_GOOD_TOKEN_[0-9a-f]{32}$/);
  assert.equal(seed, "noseed");
  assert.equal(copy, "nocopy");

  const byPath = Object.fromEntries(upstream.seen.map((r) => [r.url.split("?")[0], r]));
  assert.equal(byPath["/good"].authorization, `Bearer ${GOOD}`);
  assert.equal(byPath["/wrong-host"], undefined, "blocked request must not reach upstream");
  assert.equal(byPath["/unlisted"].authorization, `Bearer ${placeholder}`, "unlisted hosts only ever see placeholders");
  assert.equal(Buffer.from(byPath["/basic"].authorization.slice(6), "base64").toString(), `x-access-token:${GOOD}`);
  assert.equal(byPath["/gated"], undefined, "denied approval must not reach upstream");
  assert.equal(byPath["/query"].url, `/query?key=${GOOD}`);
  assert.equal(byPath["/spoofed"], undefined, "spoofed request must not reach upstream");
  assert.equal(byPath["/cleartext"], undefined, "cleartext request must not reach upstream");
  assert.deepEqual(JSON.parse(byPath["/json"].body), { api_key: GOOD });
  assert.equal(byPath["/json"].contentLength, String(Buffer.byteLength(byPath["/json"].body)));
  assert.equal(new URLSearchParams(byPath["/form"].body).get("key"), GOOD);
  assert.equal(byPath["/json-wrong-host"], undefined, "blocked body request must not reach upstream");
  assert.ok(byPath["/big"].body.includes(placeholder) && !byPath["/big"].body.includes(GOOD), "oversized bodies pass untouched");

  const receiptsText = fs.readFileSync(path.join(dir, ".rabbitlock", "receipts.jsonl"), "utf8");
  for (const value of [GOOD, GATED, "billing-value-xyz"]) {
    assert.ok(!receiptsText.includes(value), "receipts must never contain secret values");
  }
  const decisions = receiptsText.trim().split("\n").map((l) => JSON.parse(l).decision);
  assert.deepEqual(
    decisions.filter((d) => !d.startsWith("session_")),
    ["injected", "blocked_host", "injected", "denied_approval", "injected", "blocked_host", "blocked_insecure", "injected", "injected", "blocked_host"],
  );

  const ls = execFileSync(process.execPath, [CLI, "ls"], { cwd: dir, env, encoding: "utf8" });
  assert.match(ls, /GOOD_TOKEN\s+api\.rabbitlock\.test approval=never/);
  assert.ok(!ls.includes(GOOD));
});

const [nodeMajor, nodeMinor] = process.versions.node.split(".").map(Number);
const nodeHasEnvProxy = nodeMajor > 24 || (nodeMajor === 24 && nodeMinor >= 5) || (nodeMajor === 22 && nodeMinor >= 21);

test("Node fetch inside the agent is brokered (NODE_USE_ENV_PROXY)", { skip: !nodeHasEnvProxy && "needs Node >=22.21 / >=24.5" }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rl-fetch-"));
  const upstream = await startUpstream(dir);
  fs.writeFileSync(path.join(dir, "rabbitlock.agent.yaml"), "secrets:\n  GOOD_TOKEN:\n    hosts: [api.rabbitlock.test]\n");
  const env = {
    PATH: process.env.PATH,
    RABBITLOCK_HOME: path.join(dir, "home"),
    RABBITLOCK_SEED_HEX: SEED,
    RABBITLOCK_TEST_UPSTREAM: `api.rabbitlock.test=127.0.0.1:${upstream.port}`,
    RABBITLOCK_TEST_UPSTREAM_CA: upstream.caFile,
  };
  assert.equal((await runCli(["set", "GOOD_TOKEN"], { cwd: dir, env, input: GOOD })).code, 0);

  const agent = `const r = await fetch("https://api.rabbitlock.test/fetch", { headers: { authorization: "Bearer " + process.env.GOOD_TOKEN } }); console.log(r.status);`;
  const run = await runCli(["run", "--quiet", "--", process.execPath, "--input-type=module", "-e", agent], { cwd: dir, env });
  upstream.server.close();
  assert.equal(run.code, 0, run.stderr);
  assert.equal(run.stdout.trim(), "200");
  assert.equal(upstream.seen.at(-1).authorization, `Bearer ${GOOD}`);
});
