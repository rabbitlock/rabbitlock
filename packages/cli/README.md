# @rabbitlock/cli

One credential policy for every coding agent: where each API key may go, which uses need your approval, and a receipt of every use. The agent only ever holds placeholders.

`rabbitlock run -- <agent>` starts your agent with placeholders instead of real credentials. A local proxy swaps in the real value only on outbound requests to the hosts you allow, asks you first for secrets you mark as sensitive, and records a receipt of every use (never the value). The agent is sandboxed so it can't read RabbitLock's own key files.

```bash
npm install -g @rabbitlock/cli

rabbitlock init --agents-md                      # identity, rabbitlock.agent.yaml, AGENTS.md
rabbitlock import .env                           # or: echo -n "$TOKEN" | rabbitlock set GITHUB_TOKEN
rabbitlock status                                # what's missing, what's next
rabbitlock run -- claude                         # agent sees rl_ph_GITHUB_TOKEN_…
rabbitlock receipts                              # what was used, where

# A password the agent will use to create an admin account, shown once to you only:
rabbitlock set ADMIN_PASSWORD --generate --reveal
```

Requires Node.js 20+, on macOS or Linux.

Or let your agent set it up: "Set up RabbitLock for this project: read https://rabbitlock.com/agents.md and follow it."

- Documentation: https://rabbitlock.com/docs
- Source, issues and security policy: https://github.com/rabbitlock/rabbitlock

Licensed under Apache-2.0. "RabbitLock" is a trademark of Rabbitlock Inc.
