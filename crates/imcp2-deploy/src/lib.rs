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
//! bundle` writes, treated as untrusted input. The deploy pipeline over it and
//! the MCP tools that expose it follow in their own changes.

pub mod host;
