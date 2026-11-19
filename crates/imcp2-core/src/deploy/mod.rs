//! The deploy tools: deploying an icp project bundle (the `.tar.gz` that
//! `icp project bundle` writes) to the Internet Computer as the user, through
//! the icp CLI's own project library (`icp-project`, the code behind `icp
//! deploy`).
//!
//! The module lands in steps: so far the bundle host and the upload store.
//! The deploy pipeline, the MCP tools and the servers that serve them
//! follow, and the items here are public until the tools that use them are
//! in.
//!
//! The bundle is untrusted input, and the rule it is held to is the
//! library's own: `icp_project::untrusted`, the one `icp --untrusted`
//! applies (dfinity/icp-cli#873, on #868 for what `icp project bundle`
//! writes; issue #865). This crate depends on the release that has them,
//! composes the rule as the CLI does, and adds the bounds on the archive
//! itself and the checks on the bundle's shape (see [`host`]).
//!
//! It runs on the icp CLI's own crates (`icp-project` and its siblings), from
//! crates.io, which is where the wasmtime runtime in this crate's
//! dependencies comes from: a sync plugin runs on it.

pub mod host;
pub mod uploads;

pub use uploads::Uploads;
