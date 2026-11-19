//! `imcp2-local` — the Internet Computer MCP server for **local deployments**:
//! a single-user binary an AI tool (Claude Desktop/Code, Codex, Cursor, …)
//! spawns and talks to over **stdio**. It serves the same tool surface as the
//! hosted `imcp2` server against the same **mainnet** and **production
//! Internet Identity**, and drops the hosted server's entire OAuth 2.1
//! authorization server: a single-user process reached over a pipe needs no
//! bearer tokens — the OS process boundary is the auth gate.
//!
//! On top of the core surface it serves `icp_deploy_bundle` (from
//! `imcp2_core::deploy`): deploying an icp project bundle through the icp CLI's own
//! project library, as the user's default II account at `https://cli.id.ai`
//! — the principal `icp identity link web` links the CLI to, so `icp` and
//! this tool deploy as the same controller when the CLI's selected identity
//! is that link (a local key or another account is another principal).
//! A deploy's working directory lives under the OS's local data directory
//! (`imcp2-local/deploys/`) until the deploy returns, so one cut off mid-way
//! leaves the ids it created where the README says to look.
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
//!     stay manageable through the other). Not used by the deploy tools,
//!     which act at `https://cli.id.ai`.
//!   * `IMCP2_NO_OPEN` — truthy disables the best-effort browser auto-open on
//!     sign-in (the link is always returned in-band regardless).

mod login;
mod server;
mod setup;

// The PocketIC-backed end-to-end login test (the design's local-replica test
// configuration). Compiled only for `cargo test --features e2e`.
#[cfg(all(test, feature = "e2e"))]
mod e2e_local_login;

use imcp2_core::deploy::{DeploySlots, IcDeployTools, STOP_GRACE};
use imcp2_core::{identities::Identities, IcTools, IiInstance};
use login::SessionSlot;
use rmcp::ServiceExt;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// How long past [`STOP_GRACE`] the process waits for a stopped deploy to
/// have ended: the grace is the deploy's own, and what comes after it —
/// reading the ids back, cutting its directory down to the record — takes a
/// moment more. The hosted server waits as long.
const STOP_MARGIN: std::time::Duration = std::time::Duration::from_secs(5);

const HELP: &str = "\
imcp2-local — Internet Computer MCP server for local use (stdio)

Run with no arguments to serve MCP over stdio (this is what an AI client's
registration invokes). Subcommands:

  setup            Register this binary with the AI tools installed on this
                   machine (Claude Desktop, Claude Code, Codex, Cursor,
                   Antigravity; prints Perplexity's UI steps).
  setup --remove   Undo those registrations.
  setup --print    Only show the per-client steps; write nothing.
  --version, -V    Print the version.
  --help, -h       This text.

Environment (serving): IMCP2_IC_URL, IMCP2_FETCH_ROOT_KEY (loopback only),
II_URL_PROD / II_CANISTER_ID_PROD, IMCP2_MANAGEMENT_ORIGIN, IMCP2_NO_OPEN —
see the crate documentation for details.
";

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None => serve(),
        Some("setup") => setup::run(&args[1..]),
        Some("--version" | "-V") => {
            println!("imcp2-local {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("--help" | "-h" | "help") => {
            print!("{HELP}");
            Ok(())
        }
        Some(other) => anyhow::bail!("unknown argument {other:?}\n\n{HELP}"),
    }
}

fn truthy(var: &str) -> bool {
    std::env::var(var)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
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

/// Serve MCP over stdio — the no-argument path an AI client's registration
/// invokes.
#[tokio::main]
async fn serve() -> anyhow::Result<()> {
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

    // The same 60-second session reaper the hosted server runs: expired
    // grants, abandoned sign-in keys, and their cached delegations leave
    // memory promptly instead of accumulating over a long-lived process.
    // (No shutdown plumbing needed: the task ends with the runtime.)
    {
        let identities = identities.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                identities.reap_expired_sessions().await;
            }
        });
    }

    // The single-user authentication layer, owned by THIS binary: the login
    // flow fills (and on re-login replaces) the slot, and the resolver it
    // hands core answers every tool call's "which session?" from it.
    let slot = SessionSlot::new();
    let tools = IcTools::new(agent, identities.clone(), slot.resolver());
    // A deploy cut off mid-run leaves the ids it created in its working
    // directory, where the README says to look; with no local data directory
    // to keep it under there is nowhere to say, so the server does not start
    // rather than keeping records somewhere the user is not told of.
    let Some(data) = dirs::data_local_dir() else {
        anyhow::bail!(
            "no local data directory for this user, so a deploy cut off mid-run would have \
             nowhere to leave the canister ids it created: set HOME (on Linux, or \
             XDG_DATA_HOME) and start again"
        );
    };
    // The deploy slot is kept here as well as in the tools, to wait on as
    // the process ends (below).
    let slots = DeploySlots::new(1);
    let deploy = IcDeployTools::new(identities.clone(), slot.resolver())
        .with_slots(slots.clone())
        .deploys_in(&data.join("imcp2-local").join("deploys"))
        .map_err(anyhow::Error::msg)?;
    let auto_open = !truthy("IMCP2_NO_OPEN");
    let login = login::LoginDriver::new(identities, slot, auto_open);

    // From here a signal — a client or service manager stopping the server,
    // or Ctrl-C in a terminal — is taken in hand rather than left to kill
    // the process, so that a running deploy is stopped and waited for.
    let stop = shutdown_signal();
    tokio::pin!(stop);
    let service = tokio::select! {
        service = server::LocalServer::new(tools, deploy, login, auto_open)
            .serve(rmcp::transport::stdio()) => service?,
        () = &mut stop => {
            tracing::info!("asked to stop before a client had connected");
            exit_on_a_signal();
        }
    };
    tracing::info!("imcp2-local serving MCP over stdio");
    let cancel = service.cancellation_token();
    // Runs until the client closes the pipe (or the service errors), or the
    // process is told to stop.
    let waiting = service.waiting();
    tokio::pin!(waiting);
    let quit = tokio::select! {
        ended = &mut waiting => Some(ended),
        () = &mut stop => {
            tracing::info!("asked to stop");
            None
        }
    };
    // A deploy may still be running: rmcp waits only seconds for the calls
    // in flight as it ends, and returning here would end the runtime under a
    // deploy waiting on a canister call — one that may have created, and
    // funded, a canister only its answer names. So every call still running
    // is cancelled (a deploy stops at its next step and keeps its record of
    // the canisters it created), and the deploy is waited for, for as long
    // as a stopped deploy takes to end and no longer, however the service
    // ended.
    cancel.cancel();
    if !deploys_ended(&slots).await {
        tracing::warn!("a deploy had not ended when the server stopped waiting for it");
    }
    match quit {
        Some(ended) => {
            ended?;
            Ok(())
        }
        None => {
            // The service is given a moment to send what its calls answered
            // and close, and no longer: see `exit_on_a_signal`.
            let _ = tokio::time::timeout(STOP_MARGIN, waiting).await;
            exit_on_a_signal();
        }
    }
}

/// Whether the deploys running in `slots` have ended, waiting for as long as
/// a stopped deploy is given to end ([`STOP_GRACE`], and a margin) and no
/// longer.
async fn deploys_ended(slots: &DeploySlots) -> bool {
    tokio::time::timeout(STOP_GRACE + STOP_MARGIN, slots.idle()).await.is_ok()
}

/// End the process once a signal has been handled. Not a return from
/// `serve`: the transport reads stdin on a thread of the runtime that cannot
/// be interrupted, and with the pipe still open — which is how a signal
/// finds it — a return would wait on that read for as long as the client
/// keeps the pipe, the signal ignored in effect.
fn exit_on_a_signal() -> ! {
    std::process::exit(0)
}

/// A future that resolves when the process is asked to stop: SIGINT
/// (Ctrl-C) or, on Unix, SIGTERM, which is what a client or service manager
/// sends. The handlers are installed by the call, not by the first poll, so
/// no signal from then on is left to its default of killing the process. A
/// signal whose handler cannot be installed is not waited on, and keeps that
/// default.
fn shutdown_signal() -> impl std::future::Future<Output = ()> {
    #[cfg(unix)]
    let signals = {
        use tokio::signal::unix::{signal, SignalKind};
        [("SIGINT", SignalKind::interrupt()), ("SIGTERM", SignalKind::terminate())].map(
            |(name, kind)| {
                signal(kind)
                    .map_err(|e| tracing::warn!("could not install a handler for {name}: {e}"))
                    .ok()
            },
        )
    };
    async move {
        #[cfg(unix)]
        {
            let received = |signal: Option<tokio::signal::unix::Signal>| async move {
                match signal {
                    Some(mut signal) => {
                        signal.recv().await;
                    }
                    None => std::future::pending().await,
                }
            };
            let [interrupt, terminate] = signals;
            tokio::select! {
                () = received(interrupt) => {}
                () = received(terminate) => {}
            }
        }
        #[cfg(not(unix))]
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

#[cfg(test)]
mod tests {
    // As the process ends, a deploy still running is waited for — it is
    // recording the canisters it created — and one that will not end is
    // given a stopped deploy's time and no more, so it cannot hold the
    // process.
    #[tokio::test(start_paused = true)]
    async fn an_ending_server_waits_for_its_deploy_and_not_for_ever() {
        use super::{deploys_ended, DeploySlots, IcDeployTools, STOP_GRACE, STOP_MARGIN};
        let agent = imcp2_core::Agent::builder().with_url("http://127.0.0.1:9").build().unwrap();
        let identities = imcp2_core::identities::Identities::new(
            imcp2_core::IiInstance::prod().expect("prod II"),
            "https://mcp.internetcomputer.org".into(),
            agent,
        );
        let slots = DeploySlots::new(1);
        let tools = IcDeployTools::new(identities, super::SessionSlot::new().resolver())
            .with_slots(slots.clone());
        assert!(deploys_ended(&slots).await, "nothing is running");

        let running = tools.claim().unwrap();
        let ending = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            drop(running);
        });
        let started = tokio::time::Instant::now();
        assert!(deploys_ended(&slots).await, "the deploy ended within its time");
        assert_eq!(started.elapsed().as_secs(), 10, "and was waited for");
        ending.await.unwrap();

        let _stuck = tools.claim().unwrap();
        let started = tokio::time::Instant::now();
        assert!(!deploys_ended(&slots).await);
        assert_eq!(started.elapsed(), STOP_GRACE + STOP_MARGIN);
    }

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
            assert!(!super::is_loopback_url(bad), "{bad} must not count as loopback");
        }
    }
}
