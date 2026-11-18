//! imcp2-deploy — deploying an icp project bundle to the Internet Computer
//! through the icp CLI's own project library (`icp-project`, the code behind
//! `icp deploy`).
//!
//! The modules arrive one change at a time; the MCP tools that tie them
//! together, and the account of the whole, come with the last of them.

pub mod calls;
pub mod host;
pub mod identity;
