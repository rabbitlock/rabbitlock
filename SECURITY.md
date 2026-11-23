# Security policy

## Reporting a vulnerability

Email **security@rabbitlock.com**. Please don't open a public issue for security problems. Include steps to reproduce and the version or commit. We aim to acknowledge reports within 3 business days.

## Threat model in brief

RabbitLock is designed against a coding agent that has been prompt-injected and can run any command as you.

| Threat | Status |
| --- | --- |
| Agent prints, logs or pastes the token into its context | Protected: it only has a per-session placeholder |
| Agent sends the token to an attacker host | Protected: real values go only to that secret's allowed hosts |
| Token sent over plain HTTP | Protected: never injected over cleartext |
| Spoofed `Host` header redirects an allowed secret | Protected: policy and delivery use the `CONNECT` target |
| Agent reads the identity key or CA key from disk | Protected by the default sandbox; not with `--sandbox off` or when no sandbox is available (RabbitLock warns) |
| Agent edits the policy or forges receipts | Protected: read-only inside the sandbox |
| Agent reads the broker's environment (`RABBITLOCK_SEED_HEX`) | Protected when the seed comes from the environment (sandbox hides other processes); prefer the identity file |
| Tampered encrypted secrets file | Protected: integrity checked on every read |
| Agent misuses a token on an allowed host | **Not covered.** Scope tokens; use `approval` |
| Allowed API echoes the token in a response | **Not covered yet** |

Every "Protected" row is covered by tests in `packages/cli/test/`.
