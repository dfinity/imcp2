# Contributing

Thanks for your interest in contributing! This document explains how to build,
test, and propose changes to this project.

By participating, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to contribute

- **Report a bug** or request a feature by opening an
  [issue](../../issues). Please search existing issues first to avoid
  duplicates.
- **Report a security vulnerability** privately — do **not** open a public
  issue. See [SECURITY.md](SECURITY.md).
- **Submit a change** via a pull request, following the workflow below.

## Development setup

The server is a Rust crate; the status dashboard under `monitoring/mcp-status`
is a small Node tool.

Prerequisites:

- A recent stable [Rust toolchain](https://rustup.rs/) (the CI builds with
  `--locked` against the checked-in `Cargo.lock`).
- [Node.js](https://nodejs.org/) ≥ 20 (only needed to work on the status
  dashboard).

Build and test the server:

```sh
cargo build --locked --all-targets
cargo test  --locked --all-targets
```

Run it locally:

```sh
cargo run
# serves http://0.0.0.0:8000 (MCP streamable-HTTP at /mcp, info page at /)
```

Test the status dashboard:

```sh
npm test --prefix monitoring/mcp-status
```

See the [README](README.md) for the tool surface, the auth flow, and deploy
instructions.

## Pull request workflow

1. Fork the repository and create a topic branch from `main`.
2. Make your change. Keep commits focused and write clear commit messages.
3. Before opening a PR, make sure the checks that CI runs pass locally:
   - `cargo build --locked --all-targets`
   - `cargo test --locked --all-targets`
   - `cargo fmt --all` (formatting) and `cargo clippy --all-targets`
     (lints) — please leave the tree warning-free.
   - `npm test --prefix monitoring/mcp-status` if you touched the dashboard.
4. Open a pull request against `main`. Fill in the PR template, describe the
   motivation, and link any related issues.
5. A maintainer will review. Address feedback by pushing follow-up commits to
   the same branch.

## Coding guidelines

- Match the style of the surrounding code; keep the tree `rustfmt`-clean and
  `clippy`-clean.
- Add or update tests for behavior you change.
- Update the README and any affected docs when you change user-visible behavior
  or the tool surface.

## License

Unless you state otherwise, any contribution you intentionally submit for
inclusion in this project shall be licensed under the
[Apache License 2.0](LICENSE), without any additional terms or conditions.
