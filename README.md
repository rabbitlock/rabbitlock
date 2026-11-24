# RabbitLock

**Your coding agent can use your API keys without ever seeing them.**

RabbitLock is a credential broker for coding agents. It's set up for Claude Code out of the box, and works with other agents whose tools honour standard proxy settings. The agent's environment holds placeholders. A local proxy swaps in the real credential only on outbound HTTPS requests to hosts your policy allows. Sensitive secrets can require a human approval, and every use leaves a receipt that never contains the value.

**Let your agent set it up.** Paste this into Claude Code, Codex, OpenCode or any agent that can read the web:

```text
Set up RabbitLock for this project: read https://rabbitlock.com/agents.md and follow it.
```

In Claude Code, you can install the setup skill instead: `/plugin install rabbitlock --marketplace rabbitlock/rabbitlock`. The agent installs and configures everything. You approve the policy, type the secrets in your own terminal, and restart the agent under RabbitLock.

**Or do it yourself:**

```bash
npm install -g @rabbitlock/cli
rabbitlock init --agents-md
rabbitlock import .env          # or: rabbitlock set GITHUB_TOKEN
rabbitlock status               # what's missing, what's next
rabbitlock run -- claude
rabbitlock receipts
```

```yaml
# rabbitlock.agent.yaml (commit it; it contains no secrets)
secrets:
  GITHUB_TOKEN:
    hosts: [api.github.com, github.com]
  STRIPE_API_KEY:
    hosts: [api.stripe.com]
    approval: once
```

**Individual or team.** By default your encrypted secrets stay on your machine (`~/.rabbitlock/projects/…`); the policy file is the only thing in the repo. To share secrets with teammates, run `rabbitlock team enable`, then `rabbitlock team add <their key> --name ana`. That puts the encrypted file in the repo, readable only by the people you add. See [Teams](https://rabbitlock.com/docs/guides/teams). Hosted team features and enterprise controls: [rabbitlock.com/plans](https://rabbitlock.com/plans).

**Agents that set things up, not just use them:** `rabbitlock set ADMIN_PASSWORD --generate --reveal` creates a random secret and shows it once to you, not the agent. Use `--to-command` to send it to a password manager, or `--no-handoff` so nobody sees it. The agent can then create an admin account or configure a service through its API, using a credential it never sees. See [Let your agent set up accounts](https://rabbitlock.com/docs/guides/provisioning).

## What it protects, and what it doesn't

- **Protected:** the token never appears in the agent's environment, context, transcripts or logs. It is only sent to that secret's allowed hosts, never over plain HTTP, and every use is receipted.
- **Agent sandbox (default):** the agent can't read your identity key or the local CA key, and can't edit the policy, the encrypted secrets or the receipts. This uses `sandbox-exec` on macOS and `bwrap` on Linux; for `claude`, Claude Code's own sandbox is configured via `--settings`. If no sandbox can be applied, RabbitLock warns; `--sandbox on` refuses instead. Windows has no sandbox support.
- **Not protected:** misuse of a token on a host you allowed. Scope tokens narrowly and gate high-impact ones with `approval`.
- **Not yet:** response scrubbing, HTTP/2 and WebSocket interception, and substitution in multipart, compressed or >1 MiB bodies.
- **Go tools on macOS** (for example `gh`) ignore `SSL_CERT_FILE`. Run `rabbitlock ca trust` once.

Documentation: [rabbitlock.com/docs](https://rabbitlock.com/docs) (source in [`docs/`](docs)) · [Security](SECURITY.md)

## Repository

- `packages/cli`: the `rabbitlock` CLI and broker (Node ≥ 20, no build step).
- `packages/crypto-wasm`: crypto core (Rust → WebAssembly), bundled into the CLI.
- `docs`: the documentation site (Fumadocs, static export served at `rabbitlock.com/docs`). `docs/public/agents.md` holds the agent setup instructions.
- `plugins/rabbitlock`: the Claude Code plugin (setup skill). Keep it in sync with `node scripts/sync-agent-skill.mjs`.

```bash
npm install
npm test            # CLI tests (needs curl) + cargo test
```

The hosted team product (shared policy, central receipts, approvals, CI delivery) is a separate commercial service at [rabbitlock.com](https://rabbitlock.com).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). The RabbitLock name and logo are trademarks; see [TRADEMARKS.md](TRADEMARKS.md). Contributions require the [CLA](CLA.md); see [CONTRIBUTING.md](CONTRIBUTING.md).
