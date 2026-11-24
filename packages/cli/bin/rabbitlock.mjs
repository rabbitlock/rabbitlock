#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

import { loadLocalCA } from "../src/ca.mjs";
import {
  createIdentity,
  identityPath,
  keypairFromSeed,
  loadSeed,
  readSecretsFile,
  writeSecretsFile,
} from "../src/crypto.mjs";
import { POLICY_FILENAME, SECRET_NAME_PATTERN, examplePolicy, loadPolicy } from "../src/policy.mjs";
import { AGENTS_BLOCK, ensureClaudeImport, upsertAgentsBlock } from "../src/agentsmd.mjs";
import { parseDotenv } from "../src/dotenv.mjs";
import { collectStatus, formatStatus } from "../src/status.mjs";
import { DEFAULT_LENGTH, entropyBits, generateSecret, handOff, parseHandoff } from "../src/generate.mjs";
import { createReceiptWriter, readReceipts } from "../src/receipts.mjs";
import { runBrokered } from "../src/run.mjs";
import { SANDBOX_MODES } from "../src/sandbox.mjs";

const HELP = `rabbitlock - credential broker for coding agents

The agent gets placeholders. RabbitLock swaps in real credentials only on
outbound HTTPS requests to hosts your policy allows, and records a receipt.

Usage:
  rabbitlock init [--agents-md]       Create your identity and ${POLICY_FILENAME}
                                      (--agents-md: add agent instructions to AGENTS.md)
  rabbitlock status [--json]          Setup state and next steps (agents: am I brokered?)
  rabbitlock import FILE [--only A,B] [--force] [--delete]
                                      Encrypt the secrets in a .env file
  rabbitlock set NAME                 Encrypt a secret (value from stdin or prompt)
  rabbitlock set NAME --generate (--reveal | --to-command CMD | --no-handoff)
                [--length N] [--charset alnum|hex|base64url|symbols] [--force]
                                      Create a random secret the agent can use but never see
  rabbitlock rm NAME                  Remove a secret
  rabbitlock ls                       List secret names and their policy
  rabbitlock run [--sandbox auto|on|off] [--quiet] -- CMD...
                                      Run an agent with brokered credentials
  rabbitlock receipts [--tail N]      Show recent receipts
  rabbitlock ca                       Print the local CA certificate path
  rabbitlock ca trust | untrust       Trust the CA in the macOS login keychain (for Go tools such as gh)

Options:
  --policy PATH                       Use a specific policy file
  --sandbox auto|on|off               Isolate the agent from your keys, policy and receipts
                                      (default auto: macOS sandbox-exec, Linux bwrap,
                                      Claude Code via its own sandbox settings)

Example:
  rabbitlock run -- claude
`;

function takeFlag(args, flag) {
  const idx = args.indexOf(flag);
  if (idx === -1) return undefined;
  const value = args[idx + 1];
  args.splice(idx, 2);
  return value;
}

function takeBool(args, flag) {
  const idx = args.indexOf(flag);
  if (idx === -1) return false;
  args.splice(idx, 1);
  return true;
}

async function readValue(name) {
  if (!process.stdin.isTTY) {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    return Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, "");
  }
  process.stderr.write(`Value for ${name} (hidden): `);
  return await new Promise((resolve, reject) => {
    let value = "";
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding("utf8");
    const onData = (ch) => {
      if (ch === "\r" || ch === "\n" || ch === "\u0004") {
        cleanup();
        process.stderr.write("\n");
        resolve(value);
      } else if (ch === "\u0003") {
        cleanup();
        reject(new Error("Cancelled."));
      } else if (ch === "\u007f") {
        value = value.slice(0, -1);
      } else {
        value += ch;
      }
    };
    const cleanup = () => {
      process.stdin.off("data", onData);
      process.stdin.setRawMode(false);
      process.stdin.pause();
    };
    process.stdin.on("data", onData);
  });
}

async function confirm(question) {
  const readline = await import("node:readline/promises");
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
  try {
    return (await rl.question(question)).trim().toLowerCase();
  } finally {
    rl.close();
  }
}

function recipientsFor(policy, publicKey) {
  const recipients = [...policy.recipients];
  if (!recipients.includes(publicKey.toLowerCase())) {
    recipients.unshift(publicKey.toLowerCase());
  }
  return recipients;
}

async function main(argv) {
  const args = [...argv];
  const separator = args.indexOf("--");
  const passthrough = separator === -1 ? [] : args.splice(separator).slice(1);
  const policyPath = takeFlag(args, "--policy");
  const command = args.shift();

  switch (command) {
    case "init": {
      const agentsMd = takeBool(args, "--agents-md");
      const { created, seed } = createIdentity();
      const { publicKey } = keypairFromSeed(seed);
      const ca = loadLocalCA();
      console.log(created ? `Created identity at ${identityPath()}` : `Using existing identity at ${identityPath()}`);
      console.log(`Public key (share with teammates who should encrypt for you):\n  ${publicKey}`);
      const target = path.resolve(policyPath ?? POLICY_FILENAME);
      if (!fs.existsSync(target)) {
        fs.writeFileSync(target, examplePolicy(publicKey));
        console.log(`Wrote ${target}`);
      }
      console.log(`Local CA: ${ca.certPath}`);
      if (agentsMd) {
        const dir = path.dirname(target);
        const result = upsertAgentsBlock(path.join(dir, "AGENTS.md"), AGENTS_BLOCK);
        console.log(`AGENTS.md: ${result} (RabbitLock instructions for coding agents)`);
        if (ensureClaudeImport(dir) === "updated") console.log("CLAUDE.md: added `@AGENTS.md` so Claude Code reads them too");
      }
      console.log("Add `.rabbitlock/` to .gitignore (receipts live there). Then: rabbitlock import .env, or rabbitlock set NAME");
      return 0;
    }

    case "status": {
      const json = takeBool(args, "--json");
      const status = collectStatus({ policyPath });
      console.log(json ? JSON.stringify(status, null, 2) : formatStatus(status));
      return 0;
    }

    case "import": {
      const only = takeFlag(args, "--only");
      const force = takeBool(args, "--force");
      const remove = takeBool(args, "--delete");
      const file = args.shift();
      if (!file) throw new Error("Usage: rabbitlock import FILE [--only A,B] [--force] [--delete]");
      if (args.length > 0) throw new Error(`Unexpected arguments: ${args.join(" ")}`);
      const { entries, errors } = parseDotenv(fs.readFileSync(file, "utf8"));
      const wanted = only ? new Set(only.split(",").map((n) => n.trim()).filter(Boolean)) : null;

      const policy = loadPolicy(policyPath);
      const { privateKey, publicKey } = keypairFromSeed(loadSeed());
      const secrets = readSecretsFile(policy.secretsFile, privateKey);

      const imported = [];
      const unchanged = [];
      const skipped = [];
      for (const [name, value] of entries) {
        if (wanted && !wanted.has(name)) continue;
        if (!SECRET_NAME_PATTERN.test(name)) skipped.push(`${name} (name must match ${SECRET_NAME_PATTERN})`);
        else if (value === "") skipped.push(`${name} (empty)`);
        else if (secrets[name] === value) unchanged.push(name);
        else if (name in secrets && !force) skipped.push(`${name} (already stored with a different value; --force to replace)`);
        else {
          secrets[name] = value;
          imported.push(name);
        }
      }
      for (const name of wanted ?? []) {
        if (!entries.some(([k]) => k === name)) skipped.push(`${name} (not in ${file})`);
      }
      for (const e of errors) skipped.push(`line ${e.line} (${e.reason})`);

      if (imported.length > 0) writeSecretsFile(policy.secretsFile, secrets, recipientsFor(policy, publicKey));
      console.log(`Imported ${imported.length}: ${imported.join(", ") || "none"}`);
      if (unchanged.length > 0) console.log(`Already stored: ${unchanged.join(", ")}`);
      for (const s of skipped) console.log(`Skipped: ${s}`);

      const noPolicy = [...imported, ...unchanged].filter((n) => !policy.secrets[n]);
      if (noPolicy.length > 0) {
        console.log(`\nAgents won't receive these until you add their allowed hosts to ${path.basename(policy.path)}:`);
        for (const n of noPolicy) console.log(`  ${n}:\n    hosts: [<host>]`);
      }
      const failed = skipped.some((s) => s.includes("--force") || s.startsWith("line "));
      if (remove) {
        if (failed) {
          console.log(`\nNot deleting ${file}: some entries were skipped.`);
        } else {
          fs.unlinkSync(file);
          console.log(`\nDeleted ${file}.`);
        }
      } else if (imported.length + unchanged.length > 0) {
        console.log(`\n${file} still holds the plaintext values, and the agent can read it. Delete it once you've checked the import (or re-run with --delete).`);
      }
      return 0;
    }

    case "set": {
      const generate = takeBool(args, "--generate");
      const reveal = takeBool(args, "--reveal");
      const noHandoff = takeBool(args, "--no-handoff");
      const force = takeBool(args, "--force");
      const toCommand = takeFlag(args, "--to-command");
      const lengthArg = takeFlag(args, "--length");
      const charset = takeFlag(args, "--charset") ?? "alnum";
      const name = args.shift();
      if (!name || !SECRET_NAME_PATTERN.test(name)) {
        throw new Error(`Usage: rabbitlock set NAME [--generate ...]  (NAME must match ${SECRET_NAME_PATTERN})`);
      }
      if (args.length > 0) throw new Error(`Unexpected arguments: ${args.join(" ")}`);
      if (!generate && (reveal || noHandoff || toCommand !== undefined || lengthArg !== undefined || force)) {
        throw new Error("--reveal, --to-command, --no-handoff, --length and --force only apply with --generate.");
      }
      const handoff = generate ? parseHandoff({ reveal, toCommand, noHandoff }) : null;
      const length = lengthArg === undefined ? DEFAULT_LENGTH : Number(lengthArg);

      const policy = loadPolicy(policyPath);
      const { privateKey, publicKey } = keypairFromSeed(loadSeed());
      const secrets = readSecretsFile(policy.secretsFile, privateKey);

      let value;
      if (generate) {
        if (name in secrets && !force) {
          throw new Error(
            `${name} is already stored. Replacing it breaks anything still using the old value; re-run with --force if that's intended.`,
          );
        }
        value = generateSecret({ length, charset });
        handOff(value, handoff);
      } else {
        value = await readValue(name);
        if (!value) throw new Error("Refusing to store an empty value.");
      }

      secrets[name] = value;
      writeSecretsFile(policy.secretsFile, secrets, recipientsFor(policy, publicKey));
      const where = path.relative(process.cwd(), policy.secretsFile);
      if (generate) {
        createReceiptWriter(policy.receipts, "cli", { [name]: value })({
          decision: "generated",
          secrets: [name],
          command: `set --generate (${charset}, ${length} chars, handoff: ${handoff.mode})`,
        });
        console.log(`Generated ${name} (${length} chars, ${charset}, ~${entropyBits(length, charset)} bits) and stored it in ${where}`);
        if (handoff.mode === "command") console.log("Handed off to --to-command.");
        if (handoff.mode === "none") console.log("Not shown to anyone. Agents can use it through RabbitLock; it cannot be read back.");
        console.log("Agents receive a placeholder for it. Restart any running `rabbitlock run` session to pick it up.");
      } else {
        console.log(`Stored ${name} in ${where}`);
      }
      if (!policy.secrets[name]) {
        console.log(`Note: ${name} is not in ${path.basename(policy.path)} yet, so agents will not receive it. Add hosts for it.`);
      }
      return 0;
    }

    case "rm": {
      const name = args.shift();
      const policy = loadPolicy(policyPath);
      const { privateKey, publicKey } = keypairFromSeed(loadSeed());
      const secrets = readSecretsFile(policy.secretsFile, privateKey);
      if (!(name in secrets)) throw new Error(`${name} is not stored.`);
      delete secrets[name];
      writeSecretsFile(policy.secretsFile, secrets, recipientsFor(policy, publicKey));
      console.log(`Removed ${name}`);
      return 0;
    }

    case "ls": {
      const policy = loadPolicy(policyPath);
      const { privateKey } = keypairFromSeed(loadSeed());
      const stored = Object.keys(readSecretsFile(policy.secretsFile, privateKey));
      const names = [...new Set([...stored, ...Object.keys(policy.secrets)])].sort();
      for (const name of names) {
        const rule = policy.secrets[name];
        const status = !stored.includes(name) ? "MISSING VALUE" : rule ? `${rule.hosts.join(",")} approval=${rule.approval}` : "not brokered (no policy)";
        console.log(`${name.padEnd(28)} ${status}`);
      }
      return 0;
    }

    case "run": {
      const quiet = takeBool(args, "--quiet");
      const sandbox = takeFlag(args, "--sandbox") ?? "auto";
      if (!SANDBOX_MODES.has(sandbox)) throw new Error("--sandbox must be auto, on or off");
      const [cmd, ...cmdArgs] = passthrough.length > 0 ? passthrough : args;
      if (!cmd) throw new Error("Usage: rabbitlock run -- CMD [ARGS...]");
      return await runBrokered(loadPolicy(policyPath), cmd, cmdArgs, { quiet, sandbox });
    }

    case "receipts": {
      const tail = Number(takeFlag(args, "--tail") ?? 20);
      const policy = loadPolicy(policyPath);
      for (const r of readReceipts(policy.receipts, tail)) {
        const secrets = r.secrets?.join(",") ?? "";
        const where = r.host ? `${r.method} ${r.host}${r.path}` : r.command ?? "";
        console.log(`${r.ts}  ${r.decision.padEnd(16)} ${secrets.padEnd(24)} ${where}${r.status ? ` -> ${r.status}` : ""}`);
      }
      return 0;
    }

    case "ca": {
      const ca = loadLocalCA();
      const sub = args.shift();
      if (!sub) {
        console.log(ca.certPath);
        return 0;
      }
      const usage = "Usage: rabbitlock ca [trust|untrust] [--yes]";
      if (["--help", "-h", "help"].includes(sub) || args.includes("--help") || args.includes("-h")) {
        console.log(`${usage}\n\nTrust (or stop trusting) the RabbitLock local CA in the macOS login keychain.\nNeeded only for tools that ignore SSL_CERT_FILE, such as Go binaries like gh.`);
        return 0;
      }
      if (sub !== "trust" && sub !== "untrust") throw new Error(usage);
      const yes = takeBool(args, "--yes");
      if (args.length > 0) throw new Error(`Unexpected arguments: ${args.join(" ")}\n${usage}`);
      if (process.platform !== "darwin") {
        console.log(
          `Only needed on macOS. On Linux, tools honour SSL_CERT_FILE, which \`rabbitlock run\` sets.\n` +
            `To trust system-wide anyway: sudo cp ${ca.certPath} /usr/local/share/ca-certificates/rabbitlock.crt && sudo update-ca-certificates`,
        );
        return 0;
      }
      const keychain = path.join(process.env.HOME ?? "", "Library/Keychains/login.keychain-db");
      const cmd = sub === "trust"
        ? ["add-trusted-cert", "-r", "trustRoot", "-k", keychain, ca.certPath]
        : ["remove-trusted-cert", ca.certPath];
      console.log(`This will run: security ${cmd.join(" ")}\nmacOS will ask for your password to change certificate trust.`);
      if (!yes) {
        if (!process.stdin.isTTY) throw new Error("Refusing to change keychain trust without confirmation. Re-run with --yes.");
        const answer = await confirm("Proceed? [y/N] ");
        if (answer !== "y") {
          console.log("Cancelled.");
          return 1;
        }
      }
      const result = spawnSync("security", cmd, { stdio: "inherit" });
      return result.status ?? 1;
    }

    case undefined:
    case "help":
    case "--help":
    case "-h":
      console.log(HELP);
      return 0;

    default:
      throw new Error(`Unknown command: ${command}\n\n${HELP}`);
  }
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err) => {
    console.error(`rabbitlock: ${err.message}`);
    process.exit(1);
  },
);
