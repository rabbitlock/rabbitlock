# Contributing

Thanks for helping. A few things to know first.

## Contributor License Agreement

Every contributor must agree to the [CLA](CLA.md) before a pull request can be merged. The CLA bot comments on your first pull request; reply with the sentence it asks for. You only sign once.

Why: the CLA lets RabbitLock Inc. keep distributing the project, including under other licenses (for example, in the commercial hosted product). You keep the copyright to your contribution.

## Development

```bash
npm install
npm test                 # CLI tests + crypto tests
npm run test:cli         # needs curl
npm run test:crypto      # needs a Rust toolchain
```

On Linux, install `bubblewrap` to run the sandbox tests; without it they are skipped.

## Ground rules

- Security claims in docs must be backed by a test, or written as a stated limit.
- Keep the agent's environment free of real values. Any new code path that touches secrets needs a test proving the value doesn't reach the agent, logs or receipts.
- Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).
