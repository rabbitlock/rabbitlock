import { test } from "node:test";
import assert from "node:assert/strict";

import { createApprovalGate } from "../src/approval.mjs";
import { decryptSecrets, encryptSecrets, keypairFromSeed } from "../src/crypto.mjs";
import { bodyKind, detectInText, detectSecrets, makePlaceholders, substituteBody, substituteSecrets } from "../src/placeholders.mjs";
import { hostMatches, parsePolicy } from "../src/policy.mjs";
import { parseHostPort } from "../src/proxy.mjs";
import { buildChildEnv } from "../src/run.mjs";

const SEED = "1111111111111111111111111111111111111111111111111111111111111111";

test("placeholders are unique per session and never contain the value", () => {
  const a = makePlaceholders(["TOKEN"]);
  const b = makePlaceholders(["TOKEN"]);
  assert.notEqual(a.get("TOKEN"), b.get("TOKEN"));
  assert.match(a.get("TOKEN"), /^rl_ph_TOKEN_[0-9a-f]{32}$/);
});

test("detects and substitutes Bearer, Basic and URL placeholders", () => {
  const ph = makePlaceholders(["GH", "OTHER"]);
  const values = { GH: "ghp_real", OTHER: "other_real" };
  const basic = Buffer.from(`x-access-token:${ph.get("GH")}`).toString("base64");

  const bearerReq = { url: "/user", headers: { authorization: `Bearer ${ph.get("GH")}` } };
  assert.deepEqual([...detectSecrets(bearerReq, ph)], ["GH"]);
  assert.equal(substituteSecrets(bearerReq, ["GH"], ph, values).headers.authorization, "Bearer ghp_real");

  const basicReq = { url: "/repo.git/info/refs", headers: { authorization: `Basic ${basic}` } };
  assert.deepEqual([...detectSecrets(basicReq, ph)], ["GH"]);
  const swapped = substituteSecrets(basicReq, ["GH"], ph, values).headers.authorization;
  assert.equal(Buffer.from(swapped.slice(6), "base64").toString(), "x-access-token:ghp_real");

  const urlReq = { url: `/v1?key=${ph.get("OTHER")}`, headers: { "x-api-key": ph.get("GH") } };
  assert.deepEqual([...detectSecrets(urlReq, ph)].sort(), ["GH", "OTHER"]);
  const both = substituteSecrets(urlReq, ["GH", "OTHER"], ph, values);
  assert.equal(both.url, "/v1?key=other_real");
  assert.equal(both.headers["x-api-key"], "ghp_real");

  assert.equal(detectSecrets({ url: "/", headers: { authorization: "Bearer unrelated" } }, ph).size, 0);
});

test("policy validation rejects malformed entries instead of guessing", () => {
  const ok = parsePolicy("secrets:\n  GH:\n    hosts: [API.GitHub.com, '*.example.com']\n", "/repo/rabbitlock.agent.yaml");
  assert.deepEqual(ok.secrets.GH, { hosts: ["api.github.com", "*.example.com"], approval: "never" });
  assert.equal(ok.secretsFile, "/repo/secrets.sops.json");

  assert.throws(() => parsePolicy("secrets:\n  gh:\n    hosts: [a.com]\n", "/p"), /must match/);
  assert.throws(() => parsePolicy("secrets:\n  GH: {}\n", "/p"), /non-empty list/);
  assert.throws(() => parsePolicy("secrets:\n  GH:\n    hosts: ['https://a.com/x']\n", "/p"), /invalid entries/);
  assert.throws(() => parsePolicy("secrets:\n  GH:\n    hosts: [a.com]\n    approval: sometimes\n", "/p"), /never\|once\|every/);
});

test("host matching: exact and single wildcard, no suffix tricks", () => {
  assert.ok(hostMatches("api.github.com", "API.GITHUB.COM"));
  assert.ok(!hostMatches("api.github.com", "api.github.com.evil.io"));
  assert.ok(hostMatches("*.example.com", "a.example.com"));
  assert.ok(!hostMatches("*.example.com", "example.com"));
  assert.ok(!hostMatches("*.example.com", "evilexample.com"));
});

test("parses CONNECT authorities", () => {
  assert.deepEqual(parseHostPort("api.github.com:443", 443), { host: "api.github.com", port: 443 });
  assert.deepEqual(parseHostPort("[::1]:8443", 443), { host: "::1", port: 8443 });
  assert.deepEqual(parseHostPort("example.com", 80), { host: "example.com", port: 80 });
});

test("secrets round-trip; tampering fails closed", () => {
  const { privateKey, publicKey } = keypairFromSeed(SEED);
  const doc = encryptSecrets({ A: "alpha", B: "beta" }, [publicKey]);
  assert.ok(!doc.includes("alpha"));
  assert.deepEqual(decryptSecrets(doc, privateKey), { A: "alpha", B: "beta" });

  const parsed = JSON.parse(doc);
  const [key] = Object.keys(parsed).filter((k) => k !== "sops");
  const other = encryptSecrets({ A: "mallory", B: "beta" }, [publicKey]);
  parsed[key] = JSON.parse(other)[key];
  assert.throws(() => decryptSecrets(JSON.stringify(parsed), privateKey));

  const stranger = keypairFromSeed("2".repeat(64));
  assert.throws(() => decryptSecrets(doc, stranger.privateKey));
});

test("child env carries placeholders only and drops key material", () => {
  const ph = makePlaceholders(["GH"]);
  const env = buildChildEnv(
    { PATH: "/bin", GH: "ghp_real", COPY: "ghp_real", RABBITLOCK_SEED_HEX: SEED },
    { placeholders: ph, values: { GH: "ghp_real" }, proxyUrl: "http://127.0.0.1:1", ca: { certPath: "/ca", bundlePath: "/b" }, session: "s" },
  );
  assert.equal(env.GH, ph.get("GH"));
  assert.equal(env.COPY, undefined);
  assert.equal(env.RABBITLOCK_SEED_HEX, undefined);
  assert.equal(env.HTTPS_PROXY, "http://127.0.0.1:1");
  assert.ok(!Object.values(env).includes("ghp_real"));
});

test("approval gate: never/once/every and deny", async () => {
  const policy = { secrets: { N: { approval: "never" }, O: { approval: "once" }, E: { approval: "every" } } };
  const asked = [];
  const gate = createApprovalGate(policy, async ({ secret }) => {
    asked.push(secret);
    return "session";
  });
  for (let i = 0; i < 2; i++) {
    assert.deepEqual(await gate(["N", "O", "E"], {}), { ok: true });
  }
  assert.deepEqual(asked, ["O", "E", "E"]);

  const denyGate = createApprovalGate(policy, async () => "deny");
  assert.deepEqual(await denyGate(["O"], {}), { ok: false, secret: "O" });

  const throwingGate = createApprovalGate(policy, async () => {
    throw new Error("dialog crashed");
  });
  assert.deepEqual(await throwingGate(["E"], {}), { ok: false, secret: "E" });
});

test("body substitution escapes values for JSON, form and URL", () => {
  const ph = makePlaceholders(["K"]);
  const values = { K: 'a"b&c d/\\e' };
  assert.equal(bodyKind("application/json; charset=utf-8"), "json");
  assert.equal(bodyKind("application/vnd.api+json"), "json");
  assert.equal(bodyKind("application/x-www-form-urlencoded"), "form");
  assert.equal(bodyKind("text/plain"), "text");
  assert.equal(bodyKind("multipart/form-data; boundary=x"), null);
  assert.equal(bodyKind(undefined), null);

  const json = JSON.stringify({ api_key: ph.get("K") });
  assert.deepEqual([...detectInText(json, ph)], ["K"]);
  assert.deepEqual(JSON.parse(substituteBody(json, "json", ["K"], ph, values)), { api_key: values.K });

  const form = `key=${ph.get("K")}&x=1`;
  assert.equal(new URLSearchParams(substituteBody(form, "form", ["K"], ph, values)).get("key"), values.K);

  const swapped = substituteSecrets({ url: `/v1?key=${ph.get("K")}`, headers: {} }, ["K"], ph, values);
  assert.equal(new URL(swapped.url, "https://x").searchParams.get("key"), values.K);
});
