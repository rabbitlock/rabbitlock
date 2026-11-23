# Agent broker design

Source: `packages/cli/`. Tests: `packages/cli/test/`.

## Flow

```
rabbitlock run -- <agent>
  1. load rabbitlock.agent.yaml            (policy: secret -> allowed hosts, approval mode)
  2. decrypt secrets.sops.json             (identity seed from ~/.rabbitlock/identity or RABBITLOCK_SEED_HEX;
                                            SOPS MAC must verify or the run aborts)
  3. mint placeholders                     rl_ph_<NAME>_<128-bit random>, new every session
  4. start proxy on 127.0.0.1:<random>
  5. spawn agent with:
       NAME=<placeholder> for each brokered secret
       HTTP(S)_PROXY, NODE_USE_ENV_PROXY=1
       NODE_EXTRA_CA_CERTS / SSL_CERT_FILE / REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE / GIT_SSL_CAINFO
     and WITHOUT: any RABBITLOCK_* variable, or any variable whose value equals a real secret
  6. inside a sandbox (default --sandbox auto):
       deny read:  ~/.rabbitlock/identity, ~/.rabbitlock/ca/rabbitlock-ca.key
       deny write: ~/.rabbitlock/**, policy file, secrets file, receipts directory
       if the seed came from RABBITLOCK_SEED_HEX: hide other processes (their environments are readable otherwise)
     macOS: sandbox-exec · Linux: bwrap · claude: Claude Code's own sandbox via --settings
```

The sandbox plan runs a preflight first. If the sandbox exists but cannot be applied (for example, RabbitLock is itself inside a sandbox), `auto` warns and continues and `on` refuses. `src/sandbox.mjs` and `test/sandbox.test.mjs` hold the profile and the enforcement tests.

## Request bodies

JSON (`application/json`, `*+json`), form (`application/x-www-form-urlencoded`) and `text/*` bodies up to 1 MiB, without `Content-Encoding`, are buffered on intercepted hosts. Placeholders in them are checked against the same host policy and approvals, then swapped with values escaped for the format (JSON string escaping, URL encoding). `Content-Length` is recomputed. Bodies that are larger, compressed or in another format (for example multipart) stream through untouched and can only carry the placeholder.

## Proxy decisions

| Request | Behaviour | Receipt |
| --- | --- | --- |
| `CONNECT` to a host listed in policy | TLS terminated with a leaf cert from the local CA. Request inspected. | — |
| ↳ no placeholder | Forwarded unchanged over verified upstream TLS | none |
| ↳ placeholder for a secret allowed on this host, approval passes | Placeholder swapped for real value (headers, Basic auth, URL), forwarded | `injected` + status |
| ↳ placeholder for a secret **not** allowed on this host | 403, never forwarded | `blocked_host` |
| ↳ approval denied / timed out / dialog unavailable | 403, never forwarded | `denied_approval` |
| `CONNECT` to any other host | Opaque TCP tunnel (no interception) | none. The traffic can only contain placeholders. |
| Plain HTTP containing a placeholder | 403. Secrets are never injected over cleartext. | `blocked_insecure` |

The policy host check uses the `CONNECT` target, not the `Host` header. Upstream TLS is always to the `CONNECT` target, so a forged `Host` header cannot redirect a secret.

## Approvals

`approval: never | once | every`. The agent owns the terminal, so prompts go to an OS dialog: `osascript` on macOS, `zenity` on Linux. If neither exists, the request is denied. The dialog times out after 120 seconds and treats that as a deny. Prompts are serialized, so parallel requests produce one dialog. `RABBITLOCK_APPROVER=allow|deny` overrides the dialog for tests and headless runs.

## Keys and files

| Path | Contents | Mode |
| --- | --- | --- |
| `~/.rabbitlock/identity` | 32-byte seed. Derives the hybrid (X25519 + ML-KEM) keypair. | 0600 |
| `~/.rabbitlock/ca/rabbitlock-ca.key` | Local CA private key | 0600 |
| `~/.rabbitlock/ca/rabbitlock-ca.pem` | Local CA certificate (trust this) | 0644 |
| `~/.rabbitlock/ca/bundle.pem` | System roots + local CA, rewritten every run | 0644 |
| `<repo>/rabbitlock.agent.yaml` | Policy and recipients. Commit it. | — |
| `<repo>/secrets.sops.json` | Encrypted secrets. Commit it. | — |
| `<repo>/.rabbitlock/receipts.jsonl` | Receipts. Gitignored. | — |

Team sharing: add teammates' public keys to `recipients` and run `rabbitlock set` again (any change re-encrypts for everyone listed). Removing a recipient does not revoke access to old ciphertext already in git history. Rotate the underlying tokens.

## Known gaps

- No substitution in multipart, compressed or >1 MiB bodies. No HTTP/2 or WebSocket interception.
- Response bodies are not scrubbed. An allowed API that echoes the credential back would expose it to the agent.
- The local CA has no name constraints. Anyone who obtains its key can impersonate any host to processes that trust it. The sandbox denies the agent read access to the key; with `--sandbox off` or no sandbox available, that protection is gone.
- Go binaries on macOS use the system verifier. Run `rabbitlock ca trust`, or those tools will fail TLS on intercepted hosts.
- Windows: no sandbox support.
