//! `imcp2-local` — the Internet Computer MCP server for **local deployments**:
//! a single-user binary an AI tool (Claude Desktop/Code, Codex, Cursor, …)
//! spawns and talks to over **stdio**. It serves the same tool surface as the
//! hosted `imcp2` server against the same **mainnet** and **production
//! Internet Identity**, and drops the hosted server's entire OAuth 2.1
//! authorization server: a single-user process reached over a pipe needs no
//! bearer tokens — the OS process boundary is the auth gate.
//!
//! Signing in is a built-in browser handshake (see `login`): the
//! `authenticate` tool returns an id.ai link, a transient loopback listener
//! receives II's callback, and the redeemed session lives in memory only.
//!
//! stdout is the JSON-RPC channel; ALL diagnostics go to stderr.
//!
//! Environment:
//!   * `IMCP2_IC_URL` — IC API endpoint (default `https://icp-api.io`).
//!   * `IMCP2_FETCH_ROOT_KEY` — truthy opts in to trusting the endpoint's
//!     fetched root key, ONLY honoured when `IMCP2_IC_URL` targets loopback
//!     (a local replica / PocketIC for integration tests); refused otherwise,
//!     so a mis-set environment can never make a binary trust a fetched key
//!     against mainnet.
//!   * `II_URL_PROD` / `II_CANISTER_ID_PROD` — override production Internet
//!     Identity (e.g. to point a test build at beta II or a PocketIC-deployed
//!     II canister).
//!   * `IMCP2_MANAGEMENT_ORIGIN` — the derivation origin of the canister-
//!     management identity (default `https://mcp.internetcomputer.org`, the
//!     hosted server's origin, so the same anchor gets the SAME controller/
//!     funder principal locally and hosted — canisters created through one
//!     stay manageable through the other).
//!   * `IMCP2_NO_OPEN` — truthy disables the best-effort browser auto-open on
//!     sign-in (the link is always returned in-band regardless).

mod login;
mod server;

use imcp2_core::{identities::Identities, skills, IcTools, IiInstance, SessionSlot, SessionSource};
use rmcp::ServiceExt;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn truthy(var: &str) -> bool {
    std::env::var(var)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn ic_url() -> String {
    std::env::var("IMCP2_IC_URL").unwrap_or_else(|_| imcp2_core::IC_URL.to_string())
}

/// See the crate docs: defaults to the hosted server's origin so management
/// principals stay continuous across the two deployments.
fn management_origin() -> String {
    std::env::var("IMCP2_MANAGEMENT_ORIGIN")
        .unwrap_or_else(|_| "https://mcp.internetcomputer.org".to_string())
}

/// Whether `url` targets a loopback host — the only endpoints
/// `IMCP2_FETCH_ROOT_KEY` may be honoured for.
fn is_loopback_url(url: &str) -> bool {
    match url::Url::parse(url) {
        Ok(u) => match u.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
            None => false,
        },
        Err(_) => false,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // stderr only: stdout carries the MCP JSON-RPC stream, and every client
    // routes a stdio server's stderr to a log file/panel, never the chat.
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".to_string().into()),
        )
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    let ic_url = ic_url();
    let agent = imcp2_core::Agent::builder().with_url(&ic_url).build()?;
    if truthy("IMCP2_FETCH_ROOT_KEY") {
        // The guard, not a convenience: fetching a root key means TRUSTING the
        // endpoint, which is only ever right for a local test replica.
        anyhow::ensure!(
            is_loopback_url(&ic_url),
            "IMCP2_FETCH_ROOT_KEY is only honoured when IMCP2_IC_URL targets loopback \
             (a local replica); refusing to trust a fetched root key for {ic_url}"
        );
        agent.fetch_root_key().await?;
        tracing::info!(
            "trusting the fetched root key of {ic_url} (local-replica test configuration)"
        );
    }
    tracing::info!("built ic-agent against {ic_url}");

    let instance = IiInstance::prod().map_err(anyhow::Error::msg)?;
    tracing::info!(ii = %instance.ii_url, "using Internet Identity instance \"{}\"", instance.name);
    let identities = Identities::new(instance, management_origin(), agent.clone());

    // The single-user session seam: the login flow fills (and on re-login
    // replaces) the slot; every tool call reads it.
    let slot = SessionSlot::new();
    let tools = IcTools::new(
        agent,
        identities.clone(),
        skills::SkillsCatalog::new(),
        SessionSource::Singleton(slot.clone()),
    );
    let auto_open = !truthy("IMCP2_NO_OPEN");
    let login = login::LoginDriver::new(identities, slot, auto_open);

    let service = server::LocalServer::new(tools, login, auto_open)
        .serve(rmcp::transport::stdio())
        .await?;
    tracing::info!("imcp2-local serving MCP over stdio");
    // Runs until the client closes the pipe (or the service errors).
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    // The root-key guard must accept every loopback shape a test harness
    // reasonably uses and refuse everything else — mainnet above all. A truthy
    // IMCP2_FETCH_ROOT_KEY against a non-loopback endpoint aborts startup
    // rather than degrading to "just don't fetch".
    #[test]
    fn fetch_root_key_guard_accepts_only_loopback() {
        for ok in [
            "http://127.0.0.1:4943",
            "http://localhost:4943",
            "http://[::1]:4943",
            "https://127.0.0.1:8080/api",
        ] {
            assert!(super::is_loopback_url(ok), "{ok} should count as loopback");
        }
        for bad in [
            "https://icp-api.io",
            "https://ic0.app",
            // RFC 5737 TEST-NET-1: a routable-looking address that is NOT
            // loopback — private/LAN replicas must be refused too.
            "http://192.0.2.1:4943",
            "http://replica.internal:4943",
            "not a url",
        ] {
            assert!(
                !super::is_loopback_url(bad),
                "{bad} must not count as loopback"
            );
        }
    }
}
