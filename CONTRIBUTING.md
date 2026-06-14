# Contributing

## Code standards

All code must pass the following before submission:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test
```

- Zero clippy warnings (treated as errors via `-D warnings`).
- Zero formatting drift (`cargo fmt --all -- --check`).
- All existing tests pass. Add tests for new behavior.

See [docs/testing.md](docs/testing.md) for the full test suite and pre-commit
checklist.

## Pull requests

- Keep changes focused and minimal.
- Match existing code style (rustfmt default, no custom rustfmt.toml).
- Update tests if changing behavior.
- No unrelated refactoring or formatting changes.
- Commit messages should explain *why*, not *what*.

## Reporting issues

Use the issue templates — bug report or feature request.
