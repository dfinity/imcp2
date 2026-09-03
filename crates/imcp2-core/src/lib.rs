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

pub mod identities;
pub mod iiconnect;
pub mod public_fetch;
pub mod skills;
pub mod tools;

mod calls;
mod compliance;
mod discover;
mod discoverability;
mod management;

// End-to-end tests for the canister tools, against real canisters in PocketIC.
// In-crate (not tests/) so they can use the feature-gated optional `pocket-ic`
// dependency and the crate internals; gated so the default build compiles
// neither them nor `pocket-ic`. See the module docs to run them.
#[cfg(all(test, feature = "e2e"))]
mod e2e_canister_tools;

/// The IC [`Agent`] type the components are built around, re-exported so
/// callers construct the injected agent from the exact `ic-agent` version this
/// crate links.
pub use ic_agent::{self, Agent};
pub use identities::{IiInstance, SessionGauges};
pub use tools::{IcCanisterTools, IcProtocolTools, IcTools, SessionResolver};

/// A sensible default IC API boundary node (the public mainnet endpoint) for
/// callers that just want `Agent::builder().with_url(IC_URL).build()`. A host
/// with its own boundary-node routing supplies an agent built against that
/// instead.
pub const IC_URL: &str = "https://icp-api.io";
