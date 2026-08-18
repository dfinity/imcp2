# Contributing

Thanks for your interest! This document explains how to build and test the
project and how contributions are handled.

By participating, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Contribution mode

This repository is **public but closed to external code contributions**. Pull
requests opened by people outside the DFINITY organization are not merged and
may be closed automatically. **Bug reports and suggestions are always welcome.**

If the repository is later opened to external code contributions, contributors
will be required to sign the [DFINITY CLA](https://github.com/dfinity/cla/).

## Ways to contribute

- **Report a bug** or request a feature by opening an
  [issue](../../issues). Please search existing issues first to avoid
  duplicates.
- **Report a security vulnerability** privately — do **not** open a public
  issue. See [SECURITY.md](SECURITY.md).

The build and test instructions below are aimed at maintainers (the owning
DFINITY team). If the repository is later opened to external contributions, they
apply to approved contributors as well.

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

1. Create a topic branch from `main` (maintainers work in-repo; external code
   contributions are not currently accepted — see Contribution mode above).
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

## Releasing to crates.io

`imcp2` is published as a library crate. Releases are cut from a version tag:
bump `version` in `Cargo.toml`, land that on `main`, then tag that commit and
push the tag.

```sh
git tag v0.1.1
git push origin v0.1.1
```

`.github/workflows/publish-crate.yml` takes it from there — it checks the tag
against `Cargo.toml`, runs the suite, and publishes. It authenticates with
crates.io [trusted publishing](https://crates.io/docs/trusted-publishing)
(short-lived OIDC credentials), so there is no crates.io token in this
repository's secrets and none should be added. The workflow header documents
the one-time crates.io configuration it depends on.

Note that `v*` tags are for crate releases only; production rollouts are cut
separately with `release-*` tags (see `.github/workflows/deploy-release.yml`).
A crates.io release is permanent — a bad one can only be yanked, and a version
number can never be reused — so the fix for a bad release is a new version.

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
