//! imcp2-deploy — the `icp_deploy_bundle` MCP tool: deploy an icp project
//! bundle to the Internet Computer as the user, through the icp CLI's own
//! project library (`icp-project`, the code behind `icp deploy`). Next to it,
//! `icp_cycles_balance`: the balance those deploys create canisters from.
//!
//! The tool takes a bundle (the `.tar.gz` that `icp project bundle` writes),
//! the name of an environment the bundle declares, and optionally the canister
//! ids an earlier deploy produced; it answers with the deploy's status and the
//! resulting canister-id mapping. Canisters the mapping does not name are
//! created (funded from the user's cycles-ledger balance), the rest are
//! upgraded in place; every phase of `icp deploy` runs — including the sync
//! steps that upload a frontend canister's assets.
//!
//! Calls are signed as the user's **CLI identity**: their default Internet
//! Identity account at [`CLI_ORIGIN`] (`https://cli.id.ai`), the origin
//! `icp identity link web` derives at. It is the principal the icp CLI already
//! deploys as on the user's machine, so canisters created here are the ones
//! `icp` lists and controls, and the cycles that fund them are the CLI's. This
//! is deliberately NOT the management identity the canister lifecycle tools
//! act as (the default account at the server's own origin): a canister a
//! deploy creates is controlled by the CLI principal, and reaching it through
//! the lifecycle tools means adding their principal as a controller first.
//!
//! This crate is composed into the local server only. It depends on
//! `icp-project` straight from the icp-cli repository, which crates.io does
//! not allow, so it cannot be part of the published `imcp2-core`/`imcp2`
//! crates (see `Cargo.toml`).
//!
//! The bundle is untrusted input, and the rule it is held to is the
//! library's own: `icp_project::untrusted`, the one `icp --untrusted`
//! applies (dfinity/icp-cli#871, on #866 for the confined filesystem this
//! crate reads it through and #868 for what `icp project bundle` writes;
//! issue #865). This crate pins that stack, composes the rule as the CLI
//! does, and adds the bounds on the archive itself and the checks on the
//! bundle's shape (see [`host`]).

use std::{collections::BTreeMap, sync::Arc};

use base64::Engine;
use camino::Utf8PathBuf;
use candid::Principal;
use ic_agent::{identity::DelegatedIdentity, Identity};
use imcp2_core::{cycles_balance_of, identities::Identities, CyclesBalance, SessionResolver};
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, ContentBlock},
    schemars,
    service::RequestContext,
    tool, tool_router, ErrorData as McpError, RoleServer,
};
use serde::{Deserialize, Serialize};
