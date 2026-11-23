# Getting started

Requirements: Node 20+. Node 22.21+ or 24.5+ is needed for Node's built-in `fetch` to use the proxy.

## 1. Install and create your identity

```bash
npm install -g @rabbitlock/cli         # from this repo: npm link -w @rabbitlock/cli
cd your-repo
rabbitlock init
```

`init` creates:

- `~/.rabbitlock/identity`: your private seed. Back it up and never commit it.
- a local CA in `~/.rabbitlock/ca/`
- `rabbitlock.agent.yaml`, with your public key as the first recipient

Add `.rabbitlock/` to `.gitignore`; that's where receipts are written.

## 2. Store secrets

```bash
echo -n "ghp_..." | rabbitlock set GITHUB_TOKEN
rabbitlock set STRIPE_API_KEY            # prompts with hidden input
rabbitlock ls
```

Values are encrypted into `secrets.sops.json`. Commit it along with `rabbitlock.agent.yaml`.

## 3. Write the policy

```yaml
secrets:
  GITHUB_TOKEN:
    hosts: [api.github.com, github.com]
  STRIPE_API_KEY:
    hosts: [api.stripe.com]
    approval: once
```

A secret not listed under `secrets` is never given to an agent, not even as a placeholder. Host entries are exact host names or a single leading wildcard (`*.example.com`).

## 4. Run your agent

```bash
rabbitlock run -- claude
rabbitlock run -- codex
rabbitlock run -- sh -c 'curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user'
```

Afterwards, check what was used:

```bash
rabbitlock receipts --tail 50
```

## 5. The agent sandbox (on by default)

`rabbitlock run` keeps the agent away from what could undo the protection: your identity seed, the local CA key, and write access to the policy, the secrets file and the receipts.

| Agent | How |
| --- | --- |
| `claude` | RabbitLock passes Claude Code a per-session `--settings` that turns on Claude Code's sandbox with those paths denied (`failIfUnavailable`, no unsandboxed fallback). macOS cannot nest sandboxes, so RabbitLock does not wrap Claude Code in a second one. |
| anything else on macOS | Wrapped in `sandbox-exec`. |
| anything else on Linux | Wrapped in `bwrap` (install `bubblewrap`). |

The startup line shows which one is active (`sandbox: seatbelt`, `bwrap`, `claude-settings`, `unavailable` or `off`). If no sandbox can be applied, RabbitLock warns and continues. Use `--sandbox on` to refuse instead, or `--sandbox off` to opt out.

Prefer the identity file over `RABBITLOCK_SEED_HEX`. On macOS, any process running as you can read another process's environment unless it is sandboxed.

## 6. macOS: tools that ignore `SSL_CERT_FILE`

curl, git, Python and Node honour the CA variables RabbitLock sets. Go binaries such as `gh` use the macOS keychain instead. Trust the CA once (macOS asks for your password), and undo it any time:

```bash
rabbitlock ca trust
rabbitlock ca untrust
```

## Teams

Add each teammate's public key (printed by their `rabbitlock init`) under `recipients`, then run any `rabbitlock set` to re-encrypt for everyone. Removing someone from `recipients` does not remove their access to older ciphertext in git history, so rotate the underlying tokens.
