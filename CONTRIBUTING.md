# Contributing

## Development

```bash
cargo build
cargo test
cargo clippy --workspace --all-targets
```

Run the full test suite before submitting:

```bash
cargo test --test integration
cargo test --test vision_relay_tests
cargo test --test anytls_tests
```

## Pull Requests

- Keep changes focused and minimal.
- Match existing code style (rustfmt, clippy clean).
- Update tests if changing behavior.
- No unrelated refactoring or formatting changes.

## Reporting Issues

Use the issue templates — bug report or feature request.
