# @rabbitlock/cli

The `rabbitlock` command is a credential broker for coding agents. See the [repo README](../../README.md), [getting started](../../docs/getting-started.md) and [design](../../docs/agent-broker.md).

```bash
rabbitlock init
echo -n "$TOKEN" | rabbitlock set GITHUB_TOKEN
rabbitlock run -- claude
rabbitlock receipts
```

Tests: `npm test` (Node built-in test runner). The end-to-end test needs `curl`.

Test-only environment variables (stripped from the agent's environment along with every other `RABBITLOCK_*` variable):

- `RABBITLOCK_TEST_UPSTREAM=host=127.0.0.1:port,...`: route intercepted hosts to a local upstream.
- `RABBITLOCK_TEST_UPSTREAM_CA=<pem>`: trust a test upstream CA.
- `RABBITLOCK_APPROVER=allow|deny`: bypass the approval dialog.
