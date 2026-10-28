//! One deploy, start to finish: extract the bundle, load its project, seed the
//! id store, run the project library's `deploy` operation as the user, and
//! read the resulting ids back — reporting what happened either way.
//!
//! The operation is the icp CLI's own (`icp deploy`): build (here: verify the
//! bundled wasms), create what does not exist, wire canister ids into each
//! other's environment variables, apply settings, check Candid compatibility
//! on upgrades, install, sync. Nothing is re-implemented; this module only
//! supplies what the CLI's command layer would — the host, the signing
//! identity, the parameters — and turns the progress stream into a log.

use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    sync::Arc,
};

use camino::Utf8PathBuf;
use candid::Principal;
use ic_agent::{Agent, Identity};
use icp_canister_interfaces::engine_canister::engine_canister_id;
use icp_events::{EventKind, TaskId, TaskOutcome};
use icp_project::{
    calls::CanisterCalls,
    defer::Deferred,
    host::EnvironmentSelection,
    operations::{
        deploy::{deploy, resolve_targets, DeployParams, DeployReport},
        task::Task,
    },
};

use crate::{calls::AgentCalls, host};

/// Where the bundle bytes come from.
pub enum BundleSource {
    /// The archive itself.
    Bytes(Vec<u8>),
    /// An absolute path to the archive on this machine.
    Path(Utf8PathBuf),
}

// By hand so a request never prints megabytes of archive.
impl fmt::Debug for BundleSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BundleSource::Bytes(bytes) => write!(f, "Bytes({} bytes)", bytes.len()),
            BundleSource::Path(path) => write!(f, "Path({path})"),
        }
    }
}

/// Everything one deploy is given.
#[derive(Debug)]
pub struct DeployRequest {
    pub bundle: BundleSource,
    /// The environment, by name, among those the bundle's manifest declares.
    pub environment: String,
    /// Canister ids to start from: a canister named here is upgraded in place
    /// instead of created. Each name must be a canister of the environment.
    pub canister_ids: BTreeMap<String, Principal>,
    /// `auto`, `install`, `reinstall` or `upgrade` — validated upstream by the
    /// install-mode resolution, as on the command line.
    pub mode: String,
    /// Cycles to fund each canister this deploy creates.
    pub cycles: u128,
    /// Subnet to create canisters on; the registry picks one otherwise.
    pub subnet: Option<Principal>,
    /// Refuse, rather than create, when a canister does not exist yet.
    pub no_create: bool,
    /// Skip the Candid interface compatibility check on upgrades.
    pub skip_candid_check: bool,
}

/// How a deploy ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Every phase succeeded.
    Deployed,
    /// A phase failed; `created` and `canister_ids` still hold whatever landed
    /// before it did.
    Failed,
    /// The environment lists no canisters, so there was nothing to do.
    NothingToDeploy,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Deployed => "deployed",
            Status::Failed => "failed",
            Status::NothingToDeploy => "nothing_to_deploy",
        }
    }
}

/// What a deploy did. Filled in as the run progresses rather than returned at
/// the end, so a canister created before a later phase failed is still
/// reported — its id is what the caller needs to pick the run back up.
#[derive(Debug)]
pub struct DeployOutcome {
    pub status: Status,
    pub environment: String,
    /// The network the environment targets.
    pub network: String,
    /// The canisters the deploy targeted, in manifest order.
    pub canisters: Vec<String>,
    /// Canisters created by this deploy, in creation order.
    pub created: Vec<(String, Principal)>,
    /// Every canister of the environment that has an id after the deploy —
    /// the ids passed in, the ids created, both.
    pub canister_ids: BTreeMap<String, Principal>,
    /// Why the deploy failed, with its cause chain, when it did.
    pub error: Option<String>,
    /// The phases and per-canister tasks the operation reported, with their
    /// outcomes, in completion order.
    pub log: Vec<String>,
}

/// An error made before the deploy could begin: the request itself was
/// unusable, so there is no outcome to report, only the reason.
#[derive(Debug)]
pub struct RequestError(pub String);

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RequestError {}

/// Render an error with its `source()` chain, outermost first: the project
/// library's errors say *what* failed at each layer and leave the *why* to
/// the cause beneath, so only the whole chain reads as an explanation.
pub fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// Run one deploy as `identity`.
///
/// `Err` means the request never got as far as a deploy (an unreadable
/// bundle, an environment the manifest does not declare, a canister name the
/// id mapping has that the environment does not); `Ok` carries the outcome of
/// one that ran, failed or not.
pub async fn deploy_bundle(
    identity: Arc<dyn Identity>,
    request: DeployRequest,
) -> Result<DeployOutcome, RequestError> {
    let bytes = match request.bundle {
        BundleSource::Bytes(bytes) => bytes,
        BundleSource::Path(path) => {
            if !path.is_absolute() {
                return Err(RequestError(format!(
                    "bundle_path must be an absolute path on this machine, got '{path}'"
                )));
            }
            let meta = tokio::fs::metadata(path.as_std_path())
                .await
                .map_err(|e| RequestError(format!("cannot read bundle '{path}': {e}")))?;
            if meta.len() > host::MAX_BUNDLE_BYTES as u64 {
                return Err(RequestError(format!(
                    "bundle '{path}' is {} bytes, above the {} byte limit",
                    meta.len(),
                    host::MAX_BUNDLE_BYTES
                )));
            }
            tokio::fs::read(path.as_std_path())
                .await
                .map_err(|e| RequestError(format!("cannot read bundle '{path}': {e}")))?
        }
    };

    // The scratch directory lives exactly as long as this function: the
    // bundle's files, the ids the deploy records, and the build artifacts all
    // go with it, whichever way the deploy ends.
    let scratch = tempfile::Builder::new()
        .prefix("imcp2-deploy-")
        .tempdir()
        .map_err(|e| RequestError(format!("cannot create a scratch directory: {e}")))?;
    let dir = Utf8PathBuf::from_path_buf(scratch.path().to_path_buf()).map_err(|p| {
        RequestError(format!("scratch directory path is not UTF-8: {}", p.display()))
    })?;
    {
        let dir = dir.clone();
        tokio::task::spawn_blocking(move || host::extract_bundle(&bytes, &dir))
            .await
            .map_err(|e| RequestError(format!("bundle extraction panicked: {e}")))?
            .map_err(RequestError)?;
    }

    let host = host::host_for(&dir);
    let selection = EnvironmentSelection::Named(request.environment.clone());
    let env = host.get_environment(&selection).await.map_err(|e| RequestError(error_chain(&e)))?;

    // Seed the id store with the mapping the caller passed: from here on the
    // operation sees those canisters as existing, exactly as it would see the
    // ids a previous `icp deploy` recorded in the project's `.icp` directory.
    for (name, id) in &request.canister_ids {
        host.set_canister_id_for_env(name, *id, &selection)
            .await
            .map_err(|e| RequestError(error_chain(&e)))?;
    }

    let canisters =
        resolve_targets(&host, &selection, &[]).await.map_err(|e| RequestError(error_chain(&e)))?;

    let mut outcome = DeployOutcome {
        status: Status::NothingToDeploy,
        environment: request.environment.clone(),
        network: env.network.name.clone(),
        canisters: canisters.clone(),
        created: Vec::new(),
        canister_ids: request.canister_ids.clone(),
        error: None,
        log: Vec::new(),
    };
    if canisters.is_empty() {
        return Ok(outcome);
    }

    let engine_registry = engine_canister_id().map_err(RequestError)?;
    let params = DeployParams {
        environment: selection.clone(),
        canisters,
        mode: request.mode,
        subnet: request.subnet,
        proxy: None,
        cycles: request.cycles,
        engine_registry,
        no_create: request.no_create,
        yes: request.skip_candid_check,
        args: None,
    };

    // The agent is made by the first phase that reaches the network, as the
    // CLI does: a deploy that fails to load its wasms never resolves a root
    // key. The identity is already unlocked — it is the session's — so what
    // is deferred here is only the network resolution.
    let network = env.network.clone();
    let host_for_agent = host.clone();
    let calls = Deferred::new(move || {
        let host = host_for_agent.clone();
        let network = network.clone();
        let identity = identity.clone();
        async move {
            let access =
                host.network.access(&network).await.map_err(|e| RequestError(error_chain(&e)))?;
            let agent = Agent::builder()
                .with_url(access.api_url.as_str())
                .with_arc_identity(identity)
                .build()
                .map_err(|e| {
                    RequestError(format!("cannot build an agent for {}: {e}", access.api_url))
                })?;
            agent.set_root_key(access.root_key);
            let calls: Arc<dyn CanisterCalls> =
                Arc::new(AgentCalls::new(agent).map_err(RequestError)?);
            Ok::<_, RequestError>(calls)
        }
    });

    // One reporter for the whole deploy; its events are turned into log lines
    // as they arrive, so a run that fails still reports every phase before it.
    let (reporter, receiver) = icp_events::channel::<Task>();
    let collector = tokio::spawn(collect_log(receiver));

    let mut report = DeployReport::default();
    let result = deploy(&host, &calls, &params, &reporter, &mut report).await;
    // The receiver ends only once every reporter handle is gone.
    drop(reporter);
    outcome.log = collector.await.unwrap_or_default();
    outcome.created = report.created;

    match result {
        Ok(()) => outcome.status = Status::Deployed,
        Err(e) => {
            outcome.status = Status::Failed;
            outcome.error = Some(error_chain(&e));
        }
    }

    // Whatever the store holds now: the seeded ids plus every id created before
    // a failure, which is what a retry needs to pass back in.
    match host.ids_by_environment(&selection).await {
        Ok(ids) => outcome.canister_ids = ids.into_iter().collect(),
        Err(e) => {
            // The created list is the fallback: those ids were reported before
            // being recorded, so they are known even when the store is not.
            for (name, id) in &outcome.created {
                outcome.canister_ids.insert(name.clone(), *id);
            }
            outcome.log.push(format!("reading the canister ids back failed: {}", error_chain(&e)));
        }
    }

    drop(scratch);
    Ok(outcome)
}

/// Turn the operation's event stream into one line per finished task:
/// `<what>: ok` / `failed: <why>` / `skipped: <why>`, with a task nested under
/// a phase indented beneath it. Output lines are not kept — a sync plugin's
/// retained stderr is the exception, since the operation asked for it to
/// survive — so the log stays a summary, not a transcript.
async fn collect_log(
    mut receiver: tokio::sync::mpsc::UnboundedReceiver<icp_events::Event<Task>>,
) -> Vec<String> {
    let mut log = Vec::new();
    let mut started: HashMap<TaskId, (String, bool)> = HashMap::new();
    while let Some(event) = receiver.recv().await {
        match event.kind {
            EventKind::TaskStarted { parent, task } => {
                started.insert(event.task_id, (describe(&task), parent.is_some()));
            }
            EventKind::TaskCompleted { outcome } => {
                let (label, nested) = started
                    .remove(&event.task_id)
                    .unwrap_or_else(|| (format!("task {:?}", event.task_id), false));
                let indent = if nested { "  " } else { "" };
                match outcome {
                    TaskOutcome::Succeeded { retained_output } => {
                        log.push(format!("{indent}{label}: ok"));
                        for line in retained_output {
                            log.push(format!("{indent}  {line}"));
                        }
                    }
                    TaskOutcome::Failed { message, causes } => {
                        let mut line = format!("{indent}{label}: failed: {message}");
                        for cause in causes {
                            line.push_str(": ");
                            line.push_str(&cause);
                        }
                        log.push(line);
                    }
                    TaskOutcome::Skipped { reason } => {
                        log.push(format!("{indent}{label}: skipped: {reason}"));
                    }
                }
            }
            _ => {}
        }
    }
    log
}

/// A task's one-line description, read off its serialized form so this stays
/// independent of the task vocabulary: a phase is its title, anything else is
/// its kind and the canister it acts on.
fn describe(task: &Task) -> String {
    let value = serde_json::to_value(task).unwrap_or_default();
    if let Some(title) = value.get("title").and_then(|v| v.as_str()) {
        return title.trim_end_matches(':').to_string();
    }
    let kind = value.get("kind").and_then(|v| v.as_str()).unwrap_or("task");
    let canister = value.get("canister").and_then(|v| v.as_str());
    let id = value.get("canister_id").and_then(|v| v.as_str());
    match (canister, id) {
        (Some(c), Some(id)) => format!("{kind} {c} ({id})"),
        (Some(c), None) => format!("{kind} {c}"),
        _ => kind.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_agent::identity::AnonymousIdentity;
    use sha2::{Digest, Sha256};
    use std::io::Write;

    /// A bundle as `icp project bundle` writes one: the rewritten manifest
    /// (every canister a pre-built step naming a bundled wasm by checksum) at
    /// the archive root, the wasm under `canisters/`. The `ic` and `local`
    /// networks and environments are implicit, as in every manifest.
    fn bundle(sha256: &str, wasm: &[u8]) -> Vec<u8> {
        let manifest = format!(
            "canisters:\n  - name: backend\n    build:\n      steps:\n        - type: pre-built\n          \
             path: canisters/backend.wasm\n          sha256: {sha256}\n"
        );
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        for (path, data) in [("icp.yaml", manifest.as_bytes()), ("canisters/backend.wasm", wasm)] {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(&mut header, path, data).unwrap();
        }
        let mut encoder = archive.into_inner().unwrap();
        encoder.flush().unwrap();
        encoder.finish().unwrap()
    }

    fn request(bytes: Vec<u8>, environment: &str) -> DeployRequest {
        DeployRequest {
            bundle: BundleSource::Bytes(bytes),
            environment: environment.into(),
            canister_ids: BTreeMap::new(),
            mode: "auto".into(),
            cycles: 1,
            subnet: None,
            // Every test here stays off the network: with nothing created,
            // the deploy stops at the create phase, after the build phase has
            // verified the bundled wasm.
            no_create: true,
            skip_candid_check: false,
        }
    }

    fn wasm() -> (Vec<u8>, String) {
        let wasm = wat::parse_str("(module)").unwrap();
        let sha = hex::encode(Sha256::digest(&wasm));
        (wasm, sha)
    }

    // The whole pipeline up to the network: extract, load the bundled
    // manifest through the project library, resolve the implicit `ic`
    // environment, verify the wasm against its recorded checksum (the build
    // phase of a bundle), then stop where `--no-create` stops `icp deploy`.
    // The outcome reports the failure, the targets, and the log of the phase
    // that succeeded before it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_bundle_deploys_up_to_the_create_phase_offline() {
        let (wasm, sha) = wasm();
        let outcome =
            deploy_bundle(Arc::new(AnonymousIdentity), request(bundle(&sha, &wasm), "ic"))
                .await
                .expect("the request is valid");
        assert_eq!(outcome.status, Status::Failed);
        assert_eq!(outcome.network, "ic");
        assert_eq!(outcome.canisters, ["backend"]);
        assert!(outcome.created.is_empty());
        assert!(outcome.canister_ids.is_empty());
        let error = outcome.error.as_deref().unwrap();
        assert!(error.contains("--no-create") && error.contains("backend"), "{error}");
        assert!(outcome.log.iter().any(|l| l == "Building canisters: ok"), "{:?}", outcome.log);
        assert!(outcome.log.iter().any(|l| l == "  build backend: ok"), "{:?}", outcome.log);
    }

    // The manifest's checksum is the bundle's integrity check: a wasm that
    // does not hash to it fails the build phase, and the error says so.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_wasm_that_does_not_match_its_checksum_fails_the_build() {
        let (wasm, _) = wasm();
        let wrong = "0".repeat(64);
        let outcome =
            deploy_bundle(Arc::new(AnonymousIdentity), request(bundle(&wrong, &wasm), "ic"))
                .await
                .expect("the request is valid");
        assert_eq!(outcome.status, Status::Failed);
        // The operation's error names the canisters that failed to build; the
        // cause is on the per-canister task, which the log carries.
        let error = outcome.error.as_deref().unwrap();
        assert!(error.contains("failed to build") && error.contains("backend"), "{error}");
        assert!(outcome.log.iter().any(|l| l.contains("checksum mismatch")), "{:?}", outcome.log);
        assert!(
            outcome.log.iter().any(|l| l.starts_with("  build backend: failed")),
            "{:?}",
            outcome.log
        );
    }

    // A deploy to `local` would need the icp CLI's managed network; the
    // refusal names the way out instead of failing on a missing descriptor.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_local_environment_is_refused_as_managed() {
        let (wasm, sha) = wasm();
        let mut request = request(bundle(&sha, &wasm), "local");
        request.no_create = false;
        let outcome = deploy_bundle(Arc::new(AnonymousIdentity), request)
            .await
            .expect("the request is valid");
        assert_eq!(outcome.status, Status::Failed);
        let error = outcome.error.as_deref().unwrap();
        assert!(error.contains("managed") && error.contains("`ic`"), "{error}");
    }

    // Before anything is deployed: an environment the bundle does not
    // declare, or an id for a canister the environment does not hold, is a
    // request error — nothing ran, so there is no outcome to report.
    #[tokio::test(flavor = "multi_thread")]
    async fn unknown_environments_and_canisters_are_request_errors() {
        let (wasm, sha) = wasm();
        let err =
            deploy_bundle(Arc::new(AnonymousIdentity), request(bundle(&sha, &wasm), "staging"))
                .await
                .expect_err("no such environment");
        assert!(err.0.contains("staging"), "{err}");

        let mut request = request(bundle(&sha, &wasm), "ic");
        request.canister_ids.insert("frontend".into(), Principal::management_canister());
        let err = deploy_bundle(Arc::new(AnonymousIdentity), request)
            .await
            .expect_err("no such canister");
        assert!(err.0.contains("frontend"), "{err}");
    }

    // The log is what the agent (and the user) read to learn how far a deploy
    // got: phases by title, canister tasks by kind and name, nested tasks
    // indented, every outcome spelled out.
    #[tokio::test]
    async fn the_event_stream_becomes_a_readable_log() {
        let (reporter, receiver) = icp_events::channel::<Task>();
        let collector = tokio::spawn(collect_log(receiver));
        let phase = reporter.task(Task::phase("Creating canisters:"));
        let create = phase.reporter().task(Task::create("backend"));
        create.finish(TaskOutcome::succeeded());
        let install =
            phase.reporter().task(Task::install("frontend", Principal::management_canister()));
        install.finish(TaskOutcome::Failed {
            message: "install_code rejected".into(),
            causes: vec!["canister is out of cycles".into()],
        });
        phase.finish(TaskOutcome::failed("one canister failed"));
        let check = reporter.task(Task::candid_check("backend", Principal::management_canister()));
        check.finish(TaskOutcome::Skipped { reason: "not an upgrade".into() });
        drop((reporter, phase, create, install, check));
        let log = collector.await.unwrap();
        assert_eq!(
            log,
            [
                "  create backend: ok",
                "  install frontend (aaaaa-aa): failed: install_code rejected: canister is out of cycles",
                "Creating canisters: failed: one canister failed",
                "candid_check backend (aaaaa-aa): skipped: not an upgrade",
            ]
        );
    }

    #[test]
    fn error_chains_read_outermost_first() {
        #[derive(Debug)]
        struct Outer(Inner);
        #[derive(Debug)]
        struct Inner;
        impl fmt::Display for Outer {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("failed to install canister 'backend'")
            }
        }
        impl fmt::Display for Inner {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("canister rejected the call")
            }
        }
        impl std::error::Error for Inner {}
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
        assert_eq!(
            error_chain(&Outer(Inner)),
            "failed to install canister 'backend': canister rejected the call"
        );
    }
}
