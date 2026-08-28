//! imcp2-core — the transport/OAuth-agnostic components of the IMCP2 Internet
//! Computer MCP server, from which a serving binary is composed:
//!
//!   * [`tools::IcTools`] — the served MCP tool surface: [`tools::IcCanisterTools`]
//!     (canister reads and writes in textual Candid, app/canister discovery,
//!     OQL), an [`rmcp`] `ServerHandler` ready to serve over whichever
//!     transport the binary picks (streamable-HTTP in the hosted `imcp2`
//!     server, stdio in a local one). The protocol/meta half
//!     ([`tools::IcProtocolTools`] — dashboard lookups, the IC skills tools,
//!     canister management) is deferred from the default composition; we
//!     anticipate it will come in a future version.
//!   * [`identities`] — the Internet Identity session engine: the per-connection
//!     session-key grant (registered with II via `mcp_register_v2`) and the
//!     short-lived per-app account delegations minted from it on demand.
//!   * [`iiconnect`] — the II connect-handshake primitives (the `/mcp` connect
//!     link, the pinned fragment-reading callback page, the delegation-chain
//!     parser, the `#4091` auth-callback allow-list path), parameterised on
//!     plain values so each binary wraps them in its own HTTP handlers.
//!
//! How a tool call finds the II session it acts as is the one seam between
//! deployments, and **authentication itself stays in the embedding binary**:
//! each binary injects a [`SessionResolver`] reporting the already-validated
//! session for a call — the hosted server's reads what its bearer-token
//! middleware stashed on the request, a single-user local server's returns
//! the one session its login flow established. The tool implementations are
//! identical in both.
//!
//! The IC [`Agent`] is **inherited from the embedding application**, not built
//! here: the binary passes in its own agent, so anonymous canister calls go
//! through the host's boundary-node client and the whole process links a
//! single `ic-agent`.
//!
//! **Who may write** is decided in one place for every deployment:
//! `authorization` gates `canister_update_call` on the application being
//! registered under the [ICP service-discoverability protocol] with its
//! developer's acceptance of the ICP MCP Developer Terms on file, and
//! `compliance` refuses value-moving calls inside that surface. Both are
//! part of the shared tool implementation, so a binary composing these
//! components cannot opt out of them.
//!
//! [ICP service-discoverability protocol]: https://docs.internetcomputer.org/guides/frontends/service-discoverability/

pub mod identities;
pub mod iiconnect;
pub mod skills;
pub mod tools;

mod architecture;
mod authorization;
mod calls;
mod compliance;
mod discover;
mod management;

pub use authorization::{DEVELOPER_TERMS_URL, DEVELOPER_TERMS_VERSION};
pub use identities::{IiInstance, SessionGauges};
pub use tools::{IcCanisterTools, IcProtocolTools, IcTools, SessionResolver};
/// The IC [`Agent`] type the components are built around, re-exported so
/// callers construct the injected agent from the exact `ic-agent` version this
/// crate links.
pub use ic_agent::{self, Agent};

/// A sensible default IC API boundary node (the public mainnet endpoint) for
/// callers that just want `Agent::builder().with_url(IC_URL).build()`. A host
/// with its own boundary-node routing supplies an agent built against that
/// instead.
pub const IC_URL: &str = "https://icp-api.io";
