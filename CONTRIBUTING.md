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

The server is a Rust workspace: `imcp2` (the hosted server and its binary),
`crates/imcp2-core`, `crates/imcp2-local`, and the two crates of shared sessions,
`crates/imcp2-session-api` (the session canister's Candid contract) and
`crates/imcp2-session-canister` (the canister). The status dashboard under
`monitoring/mcp-status` is a small Node tool.

Prerequisites:

- A recent stable [Rust toolchain](https://rustup.rs/) (the CI builds with
  `--locked` against the checked-in `Cargo.lock`).
- [Node.js](https://nodejs.org/) ≥ 20 (only needed to work on the status
  dashboard).
- Only to build the session canister's wasm: the `wasm32-unknown-unknown` target
  and `ic-wasm` (see [The session canister](#the-session-canister)), or Docker
  with BuildKit for the reproducible build.

Build and test everything (the session crates build and test natively here too):

```sh
cargo build --locked --workspace --all-targets
cargo test  --locked --workspace --all-targets
```

Run it locally:

```sh
cargo run
# serves http://0.0.0.0:8000 (MCP streamable-HTTP at /mcp; / redirects to the landing site)
cargo run -- --help   # the environment it reads, shared sessions included
```

Test the status dashboard:

```sh
npm test --prefix monitoring/mcp-status
```

### Shared sessions: the in-process suites

Most of shared sessions is tested natively by the commands above, with no
replica: the canister's state machine (`crates/imcp2-session-canister`,
`state/tests.rs`, and the `.did` equality check), the contract and wire tests of
`crates/imcp2-session-api`, the engine in `src/shared` (golden vectors, the
mirror, the sync loop, `resolve`, the failure matrix), the shared OAuth flow
(`src/auth/shared_flow.rs`), and the multi-instance suite
(`src/shared/multi_instance_tests.rs`: four servers over the real canister state
machine run in process, driven through their routers as a non-sticky load
balancer would). To run just those:

```sh
cargo test --locked -p imcp2-session-api -p imcp2-session-canister
cargo test --locked -p imcp2 --lib shared::            # the engine, the matrix, the multi-instance suite
cargo test --locked -p imcp2 --lib auth::shared_flow   # the shared OAuth flow
cargo test --locked -p imcp2 --bin imcp2               # the binary: settings, PEMs, shared-key-check, shared-config-check, probes
```

### The session canister

The canister ships as a wasm release asset, never through crates.io. Two scripts
build it:

- **`scripts/build-session-canister.sh`** builds it with your toolchain. It needs
  the wasm target, `ic-wasm` and `gzip`:

  ```sh
  rustup target add wasm32-unknown-unknown
  cargo install ic-wasm --locked --version 0.11.1
  scripts/build-session-canister.sh            # extra arguments go to cargo build, e.g. --offline
  ```

  It writes `build-out/session-canister/` (`SESSION_CANISTER_OUT_DIR` overrides
  it): `imcp2-session-canister.wasm.gz`, its `.sha256`, `imcp2_session.did` and
  `build-info.txt`, and fails unless the module exports exactly the methods the
  `.did` declares. `GIT_SHA` (default: `git rev-parse HEAD`) is the commit the
  module reports from `get_status`. Use it for local work: another toolchain gives
  other bytes.
- **`scripts/build-session-canister-docker.sh [--twice] [out-dir]`** runs the same
  script inside the digest-pinned image of `scripts/session-canister.Dockerfile`
  (Rust 1.99.1, `ic-wasm` 0.11.1, always `linux/amd64`; on an arm64 host it runs
  under emulation). This is the **reproducible build**: CI, the release workflows
  and the canister deploy all run it, so the same commit gives the digest a
  release page shows. `--twice` builds a second time from scratch at another
  path and fails unless the outputs are byte-identical, as CI does. It needs
  Docker with BuildKit, takes `GIT_SHA` as a full 40-character commit, and warns
  when the working tree has uncommitted changes (the module would then not be the
  one that commit builds). Changing any pin in the Dockerfile changes every
  digest, so bump the image tag and its digest together.

### End-to-end tests

Four suites run against a real replica in
[PocketIC](https://github.com/dfinity/pocketic) rather than against mocks. Each
is behind its crate's `e2e` cargo feature, so the commands above compile
neither them nor `pocket-ic`, and each skips cleanly when the artifacts it
needs, which cargo does not fetch, are absent.

Fetch the PocketIC server once. Its version must satisfy the `pocket-ic` crate
the workspace pins (v15 today). CI pins the Linux x86-64 build below by its
digest; on another platform, take the matching asset of the same release:

```sh
curl -fL -o pocket-ic.gz \
  https://github.com/dfinity/pocketic/releases/download/15.0.0/pocket-ic-x86_64-linux.gz
echo "972d592975bdd0f046b05b5414ed6f9a044c676ef912b8ac81d359dd4982b038  pocket-ic.gz" \
  | sha256sum --check --strict
gunzip pocket-ic.gz && chmod +x pocket-ic
```

The suites that sign in need Internet Identity's release wasm. CI pins this one
(any recent release should do for the other suites, but this is the tested one):

```sh
curl -fL -o internet_identity_backend.wasm.gz \
  https://github.com/dfinity/internet-identity/releases/download/release-2026-07-17/internet_identity_backend.wasm.gz
echo "37d293d20330ca7c18328530f57bb33deb1670e13aa1a4b6d052ba4490a70382  internet_identity_backend.wasm.gz" \
  | sha256sum --check --strict
```

(`shasum -a 256 -c` instead of `sha256sum --check --strict` on macOS.)

**The canister tools**: every tool that reaches a canister, driven over a real
MCP session against canisters installed in PocketIC
(`crates/imcp2-core/src/e2e_canister_tools.rs`). CI runs this one:

```sh
POCKET_IC_BIN=$PWD/pocket-ic cargo test -p imcp2-core --features e2e
```

**Shared sessions** (`src/e2e_shared_sessions.rs`): imcp2 engines and servers
sharing sessions through the real session canister wasm, over PocketIC's HTTP
gateway, with real agents: access control, an upgrade, two nodes converging, a
sign-in through real Internet Identity that hops from one server to another, an
ordinary II login to another dapp that passes the redeem's root check and that
II refuses, the idle purge, 10 000 sessions purged in bounded runs, a stopped
canister, and a snapshot load. It needs the module (build it as above, or take it
from a release and check its `.sha256`) and, for the two II tests, the II wasm.
CI runs it against the module its `canister` job built, and fails if any test
skipped itself:

```sh
POCKET_IC_BIN=$PWD/pocket-ic \
SESSION_CANISTER_WASM=$PWD/build-out/session-canister/imcp2-session-canister.wasm.gz \
II_WASM=$PWD/internet_identity_backend.wasm.gz \
  cargo test -p imcp2 --features e2e e2e_shared_sessions -- --nocapture
```

Each test runs its own PocketIC instance; the suite takes one to two minutes,
most of it storing the 10 000 sessions. A test missing an artifact prints
`skipping <test>: set POCKET_IC_BIN …` and passes, so check for that line.

The other two drive the Internet Identity connect ceremony against a live
Internet Identity canister with the II wasm above. CI runs neither yet.

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

### Changing shared-session formats or the canister interface

Nodes running different releases read each other's values, and those values
outlive a deploy: session records stay in the canister up to a grant's 31 days,
and clients hold client ids, codes and tokens. So two rules hold, and the tests
pin both. The design record,
[`docs/scoping-shared-sessions.md`](docs/scoping-shared-sessions.md), sections 3
and 4.2, has the detail.

**The sealed formats in `src/shared` change only additively, readers first.**
Every label, prefix and byte layout in `keys.rs`, `seal.rs`, `codec.rs` and
`dcr.rs` is a wire contract (`src/shared/mod.rs`, "Wire contract"):

- Never change a label, prefix or layout in place: a change is a new label or a
  new version (a new `imcp2_at2.` family version, a new codec `writer_ver`).
- Payload fields are append-only, and readers ignore trailing bytes. Raise
  `min_reader` only for an incompatible change; a value a node cannot read then
  answers 503, never 401.
- **The two-release rule:** a release that starts *writing* a new field or
  version must follow a release that already *reads* it. Ship the reader in one
  release and the writer in the next, so a rollback by one release still reads
  everything the newer release wrote.
- **Golden vectors pin the bytes.** Each file's tests check fixed outputs that
  were computed independently of the crate (Python's standard library and the
  `cryptography` package; `src/shared/test_vectors.rs` holds the inputs), and
  `codec::tests::a_next_version_payload_decodes_or_is_newer` feeds next-version
  payloads to today's decoder. Do not regenerate a vector to make a test pass:
  a changed vector is a changed wire format. Add vectors for a new version, and
  compute them outside the crate.

**The canister's interface only grows.** `crates/imcp2-session-api/imcp2_session.did`
is hand-written, and the tests hold it to the Rust types in both directions
(`src/tests/contract.rs`), to golden Candid bytes (`src/tests/wire.rs`), to the
canister's exported interface (`exported_interface_equals_the_did`), and to the
method names imcp2's client calls (`the_method_table_is_the_did_service`). The build
script also refuses a module whose exports differ from it.

- Add methods; never remove or change one.
- Records gain only `opt` fields (old payloads without them must still decode:
  `payloads_without_later_opt_fields_still_decode`).
- Every method takes one record and returns `variant { Ok : …; Err : … }`, so
  arguments and replies can grow. A method a node acts on is an update; a hint
  is a separate `*_non_replicated` query.
- Errors are records (`err_code`, `err_case : opt …`, `err_str`). A new error
  case may be added, with a new code in the `.did`'s list (codes are never
  reused): an older node decodes it as `err_case = null`
  (`an_unknown_error_case_decodes_as_none`) and treats it as no definite answer.
- Every other returned variant never gains a case: an older node would fail to
  decode the whole reply.
- The canister's stable layout is append-only too: memory ids are never reused,
  keys never change layout, values start with a version byte, and a migration
  bumps `SCHEMA` (`crates/imcp2-session-canister/src/storage.rs`).

## Pull request workflow

1. Create a topic branch from `main` (maintainers work in-repo; external code
   contributions are not currently accepted — see Contribution mode above).
2. Make your change. Keep commits focused and write clear commit messages.
3. Before opening a PR, make sure the checks that CI runs pass locally:
   - `cargo build --locked --workspace --all-targets`
   - `cargo test --locked --workspace --all-targets`
   - `cargo fmt --all` (formatting) and
     `cargo clippy --workspace --all-targets -- -D warnings` (lints): please
     leave the tree warning-free.
   - `npm test --prefix monitoring/mcp-status` if you touched the dashboard.
   - If you touched the session canister or `src/shared`: the canister build
     (`scripts/build-session-canister.sh`) and the shared-sessions PocketIC suite
     (above), which CI runs in its `canister` and `e2e-shared-sessions` jobs.
4. Open a pull request against `main`. Fill in the PR template, describe the
   motivation, and link any related issues.
5. A maintainer will review. Address feedback by pushing follow-up commits to
   the same branch.

## Releasing

A release takes two human actions, both tag pushes, and every crate of the
workspace (`imcp2`, `imcp2-core`, `imcp2-local`, `imcp2-session-api`,
`imcp2-session-canister`) shares one version.

1. **Land the version bump on `main`.** Set `version` in `Cargo.toml` and in
   the `Cargo.toml` of each crate under `crates/`, plus the workspace's
   `imcp2-core` and `imcp2-session-api` pins, refresh `Cargo.lock`
   (`cargo update -w`), and merge that like any other change.
2. **Cut a candidate.** Tag that commit `rc-X.Y.Z-1` and push the tag.
   `.github/workflows/deploy-candidate.yml` checks that the tag names the
   manifests' version and that the commit is on `main`, deploys it to staging,
   and publishes a GitHub prerelease carrying the deployed binary. Test it
   there. If it fails, fix on `main` and cut `rc-X.Y.Z-2`: nothing is bumped
   after a candidate, so the commit that is promoted is the one that was tested.
3. **Promote.** Tag the same commit `vX.Y.Z` and push. Two workflows run from
   it, and nothing is deployed by either:
   - `.github/workflows/publish-crate.yml` publishes `imcp2-core`,
     `imcp2-session-api` and `imcp2` to crates.io. It checks the tag against every `Cargo.toml`, that the commit is
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

**The session crates in a release.**

- **The canister** is never published to crates.io (`publish = false`). Each
  `rc-X.Y.Z-N` prerelease carries its module (`imcp2-session-canister.wasm.gz`,
  its `.sha256`, `imcp2_session.did`, `build-info.txt`), built reproducibly from
  the tagged commit by `deploy-candidate.yml`, and the `vX.Y.Z` release carries
  the same files (`imcp2-session-canister-assets.yml`, run from `v-release.yml`),
  rebuilt and attached unless they differ from the candidate's on the same commit
  (no candidate there is only a warning). Nothing installs
  it: `deploy-session-canister.yml` does, by hand, after rebuilding it from the
  tag to the same digest (see `docs/shared-sessions-operations.md`).
- **`imcp2-session-api`** is a dependency of `imcp2` from 0.7.0, so it must
  reach crates.io first; `cargo publish --workspace` uploads it before `imcp2`.
  It does not exist on crates.io yet, and a trusted publisher can only be
  configured on a crate that exists, so **before the first `vX.Y.Z` tag that
  carries it**:
  1. publish a placeholder by hand (as `imcp2` and `imcp2-core` once were; see
     the header of `publish-crate.yml`), from a throwaway copy of the
     repository (a fresh clone of `main`, say):
     - set `version = "0.0.1"` in `crates/imcp2-session-api/Cargo.toml`,
       **and** the `imcp2-session-api` pin in the root `Cargo.toml`'s
       `[workspace.dependencies]` to `version = "0.0.1"`. Editing the crate
       alone cannot resolve: `imcp2` and the canister require `^0.7.0` of it
       through that pin, and Cargo refuses the workspace ("failed to select a
       version for the requirement `imcp2-session-api = "^0.7.0"`") before
       it packages anything;
     - rehearse, then publish, with a personal crates.io token
       (`cargo login`, or `CARGO_REGISTRY_TOKEN`):

       ```sh
       cargo publish --dry-run --allow-dirty -p imcp2-session-api
       cargo publish --allow-dirty -p imcp2-session-api
       ```

       Without `--locked`, so that Cargo can rewrite `Cargo.lock` (it records
       0.7.0), and with `--allow-dirty`, because both edits are uncommitted
       (Cargo names them and stops otherwise). The dry run reads the
       crates.io index, packages and builds `imcp2-session-api` 0.0.1, and
       uploads nothing;
     - discard the copy;
  2. configure its trusted publisher on crates.io (the same repository,
     workflow and `release` environment as the other crates).

  Without both, the tag's publish job fails at the `imcp2-session-api` upload,
  after `imcp2-core` has already been uploaded. Every workspace crate, the
  canister included, is held to the tag's version by the lockstep checks of
  `publish-crate.yml` and `deploy-candidate.yml`.

```sh
git tag rc-0.7.0-1 <commit on main> && git push origin rc-0.7.0-1   # candidate -> staging
git tag v0.7.0 rc-0.7.0-1^{}        && git push origin v0.7.0       # promote
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
