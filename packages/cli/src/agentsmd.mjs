import fs from "node:fs";
import path from "node:path";

const START = "<!-- rabbitlock:start -->";
const END = "<!-- rabbitlock:end -->";

/** Instructions for coding agents working in a RabbitLock project. Kept short: agents read it every session. */
export const AGENTS_BLOCK = `${START}
## Credentials (RabbitLock)

This project uses [RabbitLock](https://rabbitlock.com/docs). Under \`rabbitlock run\`, secret environment variables (for example \`$GITHUB_TOKEN\`) hold placeholders like \`rl_ph_GITHUB_TOKEN_…\`. Use them exactly as you would the real value, in headers, URLs or JSON/form bodies. RabbitLock swaps in the real value only on HTTPS requests to that secret's allowed hosts in \`rabbitlock.agent.yaml\`.

- Never print, log or commit secret variables, and don't hash or re-encode them yourself (standard Basic auth is fine). Don't dump the environment (\`env\`, \`printenv\`, \`set\`): other tools keep credentials there too. Use \`rabbitlock status\` to see what's brokered.
- Run \`rabbitlock status\` to see whether you're running under RabbitLock, which variables are brokered and their allowed hosts.
- A \`403\` with the header \`x-rabbitlock: denied\` means the host isn't allowed for that secret, the request used plain HTTP, or a person declined the approval. Tell the user; don't work around it.
- Never ask the user to paste a secret into the chat. To add one, ask them to run \`rabbitlock set NAME\` in their own terminal (\`rabbitlock set NAME --generate --reveal\` for a new password), agree its allowed hosts with them, and have them restart the session.
- If \`rabbitlock status\` says you're not running under RabbitLock, ask the user to restart you with \`rabbitlock run -- <agent>\`.
${END}`;

/** Inserts or replaces the RabbitLock block. Returns "created" | "updated" | "unchanged". */
export function upsertAgentsBlock(filePath, block = AGENTS_BLOCK) {
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, `# Agent instructions\n\n${block}\n`);
    return "created";
  }
  const text = fs.readFileSync(filePath, "utf8");
  const start = text.indexOf(START);
  const end = text.indexOf(END);
  let next;
  if (start !== -1 && end > start) {
    next = text.slice(0, start) + block + text.slice(end + END.length);
  } else {
    next = `${text.replace(/\s*$/, "")}\n\n${block}\n`;
  }
  if (next === text) return "unchanged";
  fs.writeFileSync(filePath, next);
  return "updated";
}

/**
 * Claude Code reads AGENTS.md only when there is no CLAUDE.md. If the project has a CLAUDE.md, make
 * it import AGENTS.md (the documented `@AGENTS.md` form) so Claude Code sees the instructions too.
 */
export function ensureClaudeImport(dir) {
  const claude = path.join(dir, "CLAUDE.md");
  if (!fs.existsSync(claude)) return "absent";
  const text = fs.readFileSync(claude, "utf8");
  if (/^@(\.\/)?AGENTS\.md\s*$/m.test(text) || text.includes(START)) return "unchanged";
  fs.writeFileSync(claude, `${text.replace(/\s*$/, "")}\n\n@AGENTS.md\n`);
  return "updated";
}
