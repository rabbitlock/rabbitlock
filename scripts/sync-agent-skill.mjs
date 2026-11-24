// Keeps the Claude Code skill's body identical to docs/public/agents.md (served at rabbitlock.com/agents.md).
// Usage: node scripts/sync-agent-skill.mjs [--check]
import fs from "node:fs";

const SOURCE = new URL("../docs/public/agents.md", import.meta.url);
const SKILL = new URL("../plugins/rabbitlock/skills/setup/SKILL.md", import.meta.url);
const FRONTMATTER = `---
name: setup
description: Set up RabbitLock so this coding agent can use the project's API keys without ever seeing them. Use when the user asks to install or set up RabbitLock, to protect API keys, tokens or .env secrets from the agent, or to create an account or service with a password the agent must not see.
---

`;

const expected = FRONTMATTER + fs.readFileSync(SOURCE, "utf8");
if (process.argv.includes("--check")) {
  const actual = fs.existsSync(SKILL) ? fs.readFileSync(SKILL, "utf8") : "";
  if (actual !== expected) {
    console.error("plugins/rabbitlock/skills/setup/SKILL.md is out of date. Run: node scripts/sync-agent-skill.mjs");
    process.exit(1);
  }
  console.log("Agent skill matches docs/public/agents.md");
} else {
  fs.writeFileSync(SKILL, expected);
  console.log("Wrote plugins/rabbitlock/skills/setup/SKILL.md");
}
