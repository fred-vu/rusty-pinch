# Contributing to Rusty Pinch

Thanks for contributing.

## Before you start

- Read `README.md` and `docs/architecture.md`.
- Read license terms in `LICENSE` (personal-use source-available).
- Do not include secrets, tokens, local runtime data, or `.env` files.

## Development workflow

Run from `rusty-pinch/`:

```bash
cargo fmt --all
cargo check
cargo test
```

Recommended local smoke:

```bash
RUSTY_PINCH_PROVIDER=local cargo run -- run --session smoke --message "hello"
cargo run -- stats
```

## Pull request requirements

- Keep PRs focused and small.
- Include a short problem statement and solution summary.
- Include test evidence (commands and result).
- Update docs when behavior or config changes.

## Security and secrets

- Never commit API keys, tokens, bridge URLs with credentials, or private IDs.
- Use `.env.example` and deploy env templates only.
- Follow `SECURITY.md` and `docs/open-source-publish-checklist.md`.

## License and contribution terms

By contributing, you agree your contribution is licensed under this repository's `LICENSE` and that maintainers may use, modify, and redistribute contributions under the same project license terms.
