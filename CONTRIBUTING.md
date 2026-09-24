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

### End-to-end tests

Three suites run against a real replica in
[PocketIC](https://github.com/dfinity/pocketic) rather than against mocks. Each
is behind its crate's `e2e` cargo feature, so the commands above compile
neither them nor `pocket-ic`, and each skips cleanly when the artifacts it
needs — which cargo does not fetch — are absent.

Fetch the PocketIC server once. Its version must satisfy the `pocket-ic` crate
the workspace pins (v15 today), and the asset below is the Linux x86-64 build:

```sh
curl -fL -o pocket-ic.gz \
  https://github.com/dfinity/pocketic/releases/download/15.0.0/pocket-ic-x86_64-linux.gz
gunzip pocket-ic.gz && chmod +x pocket-ic
```

**The canister tools** — every tool that reaches a canister, driven over a real
MCP session against canisters installed in PocketIC
(`crates/imcp2-core/src/e2e_canister_tools.rs`). CI runs this one:

```sh
POCKET_IC_BIN=$PWD/pocket-ic cargo test -p imcp2-core --features e2e
```

The other two drive the Internet Identity connect ceremony against a live
Internet Identity canister, so they additionally need an Internet Identity
release wasm — which is why CI runs neither.

**The hosted server's handshake** (`src/e2e_handshake.rs`), which redeems a
real registration delegation through the OAuth connect flow:

```sh
II_WASM=/abs/internet_identity_backend.wasm.gz POCKET_IC_BIN=$PWD/pocket-ic \
  cargo test --features e2e
```

**The local binary's login** (`crates/imcp2-local/src/e2e_local_login.rs`),
which does the same through `imcp2-local`'s browser login flow:

```sh
II_WASM=/abs/internet_identity_backend.wasm.gz POCKET_IC_BIN=$PWD/pocket-ic \
  cargo test -p imcp2-local --features e2e
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

## Releasing

A release takes two human actions, both tag pushes, and all three crates
(`imcp2`, `imcp2-core`, `imcp2-local`) share one version.

1. **Land the version bump on `main`.** Set `version` in `Cargo.toml`,
   `crates/imcp2-core/Cargo.toml` and `crates/imcp2-local/Cargo.toml`, plus the
   workspace's `imcp2-core` pin, refresh `Cargo.lock` (`cargo update -w`), and
   merge that like any other change.
2. **Cut a candidate.** Tag that commit `rc-X.Y.Z-1` and push the tag.
   `.github/workflows/deploy-candidate.yml` checks that the tag names the
   manifests' version and that the commit is on `main`, deploys it to staging,
   and publishes a GitHub prerelease carrying the deployed binary. Test it
   there. If it fails, fix on `main` and cut `rc-X.Y.Z-2`: nothing is bumped
   after a candidate, so the commit that is promoted is the one that was tested.
3. **Promote.** Tag the same commit `vX.Y.Z` and push. Two workflows run from
   it, and nothing is deployed by either:
   - `.github/workflows/publish-crate.yml` publishes `imcp2-core` and `imcp2` to
     crates.io. It checks the tag against every `Cargo.toml`, that the commit is
     on `main`, and that an `rc-X.Y.Z-N` tag on it has its prerelease with the
     deployed binary (which exists only if the staging deploy succeeded), runs
     the suite and a dry-run package, and only then publishes from a second job
     that compiles nothing.
     It authenticates with crates.io
     [trusted publishing](https://crates.io/docs/trusted-publishing) (short-lived
     OIDC credentials), so there is no crates.io token in this repository's
     secrets and none should be added.
   - `.github/workflows/v-release.yml` (generated by `dist` from
     `dist-workspace.toml`) builds `imcp2-local`'s platform archives,
     installers and Claude Desktop bundle and creates the `vX.Y.Z` GitHub
     release. Candidates are prereleases, so GitHub's `latest` release is
     always a promoted version.

   Production is not deployed from this repository: it embeds the published
   crate, and picks the new version up with a dependency bump there.

```sh
git tag rc-0.6.0-1 <commit on main> && git push origin rc-0.6.0-1   # candidate -> staging
git tag v0.6.0 rc-0.6.0-1^{}        && git push origin v0.6.0       # promote
```

Two repository settings are prerequisites, because GitHub loads a
tag-triggered workflow from the tagged commit, so the guards in the workflow
files cannot defend against a tag that carries its own edited copy of them:

- **Protected `v*` and `rc-*` tags** (Settings → Rules → Rulesets, targeting
  tags), so only maintainers can cut a candidate or promote one.
- **Required reviewers on the `release` environment** (Settings →
  Environments), which gates the one job that can reach crates.io from outside
  the workflow file.

The publish workflow's header documents these along with the one-time
crates.io configuration. A crates.io release is permanent: a bad one can only
be yanked, and a version number can never be reused, so the fix for a bad
release is a new version, cut through the same two steps.

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
