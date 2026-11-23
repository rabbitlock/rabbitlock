# @rabbitlock/cli

Your coding agent uses your API keys without ever seeing them.

`rabbitlock run -- <agent>` starts your agent with placeholders instead of real credentials. A local proxy swaps in the real value only on outbound requests to the hosts you allow, asks you first for secrets you mark as sensitive, and records a receipt of every use (never the value). The agent is sandboxed so it can't read RabbitLock's own key files.

```bash
npm install -g @rabbitlock/cli

rabbitlock init                                  # identity + rabbitlock.agent.yaml
echo -n "$TOKEN" | rabbitlock set GITHUB_TOKEN   # stored encrypted
rabbitlock run -- claude                         # agent sees rl_ph_GITHUB_TOKEN_…
rabbitlock receipts                              # what was used, where
```

Requires Node.js 20+, on macOS or Linux.

- Documentation: https://rabbitlock.com/docs
- Source, issues and security policy: https://github.com/rabbitlock/rabbitlock

Licensed under Apache-2.0. "RabbitLock" is a trademark of Rabbitlock Inc.
