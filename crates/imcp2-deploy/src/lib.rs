//! imcp2-deploy — deploying an icp project bundle to the Internet Computer
//! through the icp CLI's own project library (`icp-project`, the code behind
//! `icp deploy`).
//!
//! This crate is composed into the local server only. It depends on
//! `icp-project` straight from the icp-cli repository, which crates.io does
//! not allow, so it cannot be part of the published `imcp2-core`/`imcp2`
//! crates (see `Cargo.toml`).
//!
//! [`host`] is the `icp_project::Host` for a bundle: the archive `icp project
//! bundle` writes, treated as untrusted input. The rule it is held to is the
//! library's own, `icp_project::untrusted`, the one `icp --untrusted`
//! applies (dfinity/icp-cli#871, on #866 for the confined filesystem this
//! crate reads it through and #868 for what `icp project bundle` writes;
//! issue #865): this crate pins
//! that stack, composes the rule as the CLI does, and adds the bounds on the
//! archive itself and the checks on the bundle's shape. [`deploy_bundle`]
//! runs the library's deploy operation over it as a given identity: create
//! the canisters the bundle names that do not exist yet, wire their ids,
//! install or upgrade, run the sync steps. The MCP tools that expose it
//! follow in their own change.

mod calls;
mod deploy;
pub mod host;

pub use deploy::{deploy_bundle, BundleSource, DeployOutcome, DeployRequest, RequestError, Status};
