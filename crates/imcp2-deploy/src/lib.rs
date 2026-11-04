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
//! bundle` writes, treated as untrusted input. The confinement of the files
//! the library reads is the library's own (`icp_project::files::Confined`,
//! added for this use by dfinity/icp-cli#866, issue #865): this crate pins
//! that change and adds the bounds on the archive itself and the checks on
//! the bundle's shape. The deploy pipeline over it and the MCP tools that
//! expose it follow in their own changes.

pub mod host;
