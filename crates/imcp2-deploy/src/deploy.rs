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

use camino::{Utf8Path, Utf8PathBuf};
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
    prelude::{IC_MAINNET_NETWORK_API_URL, IC_ROOT_KEY},
};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{calls::AgentCalls, host};

/// Where the bundle bytes come from.
pub enum BundleSource {
    /// The archive itself.
    Bytes(Vec<u8>),
    /// An absolute path to the archive on this machine.
    Path(Utf8PathBuf),
    /// An archive uploaded ahead of the call, by the id the upload answered
    /// with (see [`crate::Uploads`]). The tool turns it into a [`Self::Path`]
    /// before the deploy; one reaching the deploy as is, is a request error.
    Upload(String),
}

// By hand so a request never prints megabytes of archive.
impl fmt::Debug for BundleSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BundleSource::Bytes(bytes) => write!(f, "Bytes({} bytes)", bytes.len()),
            BundleSource::Path(path) => write!(f, "Path({path})"),
            BundleSource::Upload(id) => write!(f, "Upload({id})"),
        }
    }
}

/// The install modes `icp deploy --mode` takes, as the library spells them.
pub const INSTALL_MODES: [&str; 4] = ["auto", "install", "reinstall", "upgrade"];

/// Everything one deploy is given.
#[derive(Debug)]
pub struct DeployRequest {
    pub bundle: BundleSource,
    /// The environment, by name, among those the bundle's manifest declares.
    pub environment: String,
    /// Canister ids to start from: a canister named here is upgraded in place
    /// instead of created. Each name must be a canister of the environment.
    pub canister_ids: BTreeMap<String, Principal>,
    /// One of [`INSTALL_MODES`]: `auto`, `install`, `reinstall` or `upgrade`.
    /// Checked at entry: the library resolves the mode only once it installs,
    /// after the canisters have been created, and it panics on any other
    /// spelling rather than failing the deploy.
    pub mode: String,
    /// Cycles to fund each canister this deploy creates.
    pub cycles: u128,
    /// Subnet to create canisters on; the registry picks one otherwise.
    pub subnet: Option<Principal>,
    /// Refuse, rather than create, when a canister does not exist yet.
    pub no_create: bool,
    /// Skip the Candid interface compatibility check on upgrades.
    pub skip_candid_check: bool,
    /// Where the deploy's working directory is made (the system temporary
    /// directory when `None`). A run that returns removes it; a run that is
    /// cut off — the server stopped mid-deploy, the call cancelled — leaves
    /// it, and with it `.icp/data/mappings/<environment>.ids.json`, which
    /// records every canister the deploy created, so a caller who never got
    /// the answer can recover the ids instead of creating a second set.
    pub workdir: Option<Utf8PathBuf>,
}

/// How a running deploy is watched: where its progress goes as it happens,
/// and what tells it to stop.
#[derive(Clone, Debug, Default)]
pub struct Watch {
    /// Cancelled to interrupt the deploy. The run stops at its next step
    /// (a canister call already in flight completes on the network), and
    /// the outcome reports [`Status::Interrupted`] with everything that
    /// landed before the stop.
    pub stop: CancellationToken,
    /// Receives each log line as the run produces it, before the outcome
    /// collects them all; `None` keeps them for the outcome alone. A
    /// receiver that has gone away is not an error.
    pub lines: Option<mpsc::UnboundedSender<String>>,
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
    /// The run was stopped through [`Watch::stop`] before it finished;
    /// `created` and `canister_ids` hold whatever landed before the stop.
    Interrupted,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Deployed => "deployed",
            Status::Failed => "failed",
            Status::NothingToDeploy => "nothing_to_deploy",
            Status::Interrupted => "interrupted",
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

/// Run one deploy as `identity`, reporting to and stopped by `watch`.
///
/// `Err` means the request never got as far as a deploy (an unreadable
/// bundle, an environment the manifest does not declare, a canister name the
/// id mapping has that the environment does not); `Ok` carries the outcome of
/// one that ran — finished, failed or interrupted.
pub async fn deploy_bundle(
    identity: Arc<dyn Identity>,
    request: DeployRequest,
    watch: Watch,
) -> Result<DeployOutcome, RequestError> {
    if !INSTALL_MODES.contains(&request.mode.as_str()) {
        return Err(RequestError(format!(
            "mode must be one of {}, got '{}'",
            INSTALL_MODES.map(|m| format!("'{m}'")).join(", "),
            request.mode
        )));
    }
    let bytes = match request.bundle {
        BundleSource::Bytes(bytes) => bytes,
        BundleSource::Path(path) => read_bundle_file(&path, host::MAX_BUNDLE_BYTES).await?,
        BundleSource::Upload(id) => {
            return Err(RequestError(format!(
                "the upload '{id}' was not resolved to a file before the deploy"
            )))
        }
    };

    // The working directory holds the bundle's files, the ids the deploy
    // records, and the build artifacts. Until the deploy starts it is a
    // temporary directory, gone with any early return; from then on it is
    // kept on purpose and removed only once the outcome — the ids above all —
    // has been assembled, so a run that is cut off leaves its record behind.
    let parent = match &request.workdir {
        Some(dir) => {
            std::fs::create_dir_all(dir).map_err(|e| {
                RequestError(format!("cannot create the deploy directory '{dir}': {e}"))
            })?;
            dir.as_std_path().to_path_buf()
        }
        None => std::env::temp_dir(),
    };
    let scratch = deploy_directory(&parent)
        .map_err(|e| RequestError(format!("cannot create a scratch directory: {e}")))?;
    let dir = Utf8PathBuf::from_path_buf(scratch.path().to_path_buf()).map_err(|p| {
        RequestError(format!("scratch directory path is not UTF-8: {}", p.display()))
    })?;
    let fs = {
        let dir = dir.clone();
        tokio::task::spawn_blocking(move || host::extract_bundle(&bytes, &dir))
            .await
            .map_err(|e| RequestError(format!("bundle extraction panicked: {e}")))?
            .map_err(RequestError)?
    };

    let host = host::host_for(fs.clone());
    // The load is where the untrusted rule holds (a script step, a module or
    // plugin fetched from a URL or not a regular file under the root, a
    // recipe: the project does not load), so it is the first thing a bundle outside the
    // rule fails. It reads the manifest and, through the metered view, every
    // file a canister names, with the filesystem's own blocking reads: like
    // extraction it runs off the runtime's workers, and the loader keeps
    // what it loaded for every later ask.
    {
        let project = host.project.clone();
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || handle.block_on(project.load()))
            .await
            .map_err(|e| RequestError(format!("project load panicked: {e}")))?
            .map_err(|e| RequestError(error_chain(&e)))?;
    }
    let selection = EnvironmentSelection::Named(request.environment.clone());
    let env = host.get_environment(&selection).await.map_err(|e| RequestError(error_chain(&e)))?;
    // Before any phase runs: a bundle that is not one — a wasm that is
    // missing or does not hash to its checksum, a network other than the IC
    // — is refused here, not at the phase that would reach it after
    // canisters have been created. The check reads, hashes and gunzips every
    // module, up to a gigabyte of them, so like extraction it runs off the
    // runtime's workers.
    {
        let fs = fs.clone();
        let network = env.network.clone();
        let canisters: Vec<_> = env.canisters.values().cloned().collect();
        tokio::task::spawn_blocking(move || {
            host::check_bundle(
                &fs,
                &network,
                canisters.iter().map(|(dir, canister)| (dir.as_path(), canister)),
            )
        })
        .await
        .map_err(|e| RequestError(format!("bundle check panicked: {e}")))?
        .map_err(RequestError)?;
    }

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
    // CLI does: a deploy that fails to load its wasms never builds one. The
    // network is the Internet Computer — `check_bundle` held the environment
    // to it — so the agent is the mainnet one, as the balance check's is.
    let calls = Deferred::new(move || {
        let identity = identity.clone();
        async move {
            let agent = mainnet_agent(identity).map_err(RequestError)?;
            let calls: Arc<dyn CanisterCalls> =
                Arc::new(AgentCalls::new(agent).map_err(RequestError)?);
            Ok::<_, RequestError>(calls)
        }
    });

    // One reporter for the whole deploy; its events are turned into log lines
    // as they arrive, so a run that fails still reports every phase before it.
    let (reporter, receiver) = icp_events::channel::<Task>();
    let collector = tokio::spawn(collect_log(receiver, watch.lines));

    // From here the directory outlives this future (see above).
    let workdir = scratch.keep();
    let mut report = DeployReport::default();
    // The run is dropped the moment the stop is asked for: it ends at its
    // next await, which is the next canister call or plugin step. `biased`
    // so a stop asked for before the run begins is honoured without a step.
    let result = {
        let run = deploy(&host, &calls, &params, &reporter, &mut report);
        tokio::pin!(run);
        tokio::select! {
            biased;
            _ = watch.stop.cancelled() => None,
            result = &mut run => Some(result),
        }
    };
    // The receiver ends only once every reporter handle is gone.
    drop(reporter);
    outcome.log = collector.await.unwrap_or_default();
    outcome.created = report.created;

    match result {
        Some(Ok(())) => outcome.status = Status::Deployed,
        Some(Err(e)) => {
            outcome.status = Status::Failed;
            outcome.error = Some(error_chain(&e));
        }
        None => {
            outcome.status = Status::Interrupted;
            outcome.error = Some(
                "the deploy was interrupted before it finished (the call was cancelled or \
                 the client went away); `canister_ids` holds every canister it had created"
                    .into(),
            );
        }
    }

    // Whatever the store holds now: the seeded ids plus every id created before
    // a failure, which is what a retry needs to pass back in.
    match host.ids_by_environment(&selection).await {
        Ok(ids) => outcome.canister_ids = ids.into_iter().collect(),
        Err(e) => {
            outcome.log.push(format!("reading the canister ids back failed: {}", error_chain(&e)));
        }
    }
    // A created id is reported before it is recorded, so the created list is
    // the authority: it fills in whatever the store failed to record — or to
    // read back — because a mapping missing a canister that exists would have
    // the retry create it again.
    for (name, id) in &outcome.created {
        outcome.canister_ids.insert(name.clone(), *id);
    }

    // The outcome carries everything the directory recorded; the directory
    // has done its job. Not after an interruption: the one who asked for it
    // may be a client that went away and will never read this outcome, so
    // the directory stays as the record, as it does for a run that is cut
    // off (see [`DeployRequest::workdir`]).
    drop(host);
    if outcome.status == Status::Interrupted {
        outcome.log.push(format!(
            "interrupted; the deploy directory '{}' is kept, with the ids it recorded",
            workdir.display()
        ));
    } else if let Err(e) = tokio::fs::remove_dir_all(&workdir).await {
        outcome
            .log
            .push(format!("removing the deploy directory '{}' failed: {e}", workdir.display()));
    }
    Ok(outcome)
}

/// An agent for the Internet Computer signing as `identity`: the mainnet
/// endpoint and the pinned root key, the one network a deploy reaches. The
/// balance check uses the same, so what it reports is what a deploy spends.
pub fn mainnet_agent(identity: Arc<dyn Identity>) -> Result<Agent, String> {
    let agent = Agent::builder()
        .with_url(IC_MAINNET_NETWORK_API_URL)
        .with_arc_identity(identity)
        .build()
        .map_err(|e| format!("cannot build an agent for the Internet Computer: {e}"))?;
    agent.set_root_key(IC_ROOT_KEY.to_vec());
    Ok(agent)
}

/// Read the bundle at `path`, which must be an absolute path to a regular
/// file of at most `limit` bytes, and nothing else: a device or a pipe reports
/// a length that says nothing about what a read of it produces (`/dev/zero`
/// is 0 bytes long and endless; a FIFO blocks on open), so the size check
/// means something for a regular file only. The path is checked before it
/// is opened, so a pipe is never opened; the open file is checked again, so
/// a file replaced or grown between the two is still read to the limit and
/// no further.
async fn read_bundle_file(path: &Utf8Path, limit: usize) -> Result<Vec<u8>, RequestError> {
    use tokio::io::AsyncReadExt;
    if !path.is_absolute() {
        return Err(RequestError(format!(
            "bundle_path must be an absolute path on this machine, got '{path}'"
        )));
    }
    let cannot = |e: std::io::Error| RequestError(format!("cannot read bundle '{path}': {e}"));
    let too_large = |len: u64| {
        RequestError(format!("bundle '{path}' is {len} bytes, above the {limit} byte limit"))
    };
    let not_regular = || RequestError(format!("bundle '{path}' is not a regular file"));
    let meta = tokio::fs::metadata(path.as_std_path()).await.map_err(cannot)?;
    if !meta.is_file() {
        return Err(not_regular());
    }
    if meta.len() > limit as u64 {
        return Err(too_large(meta.len()));
    }
    let file = tokio::fs::File::open(path.as_std_path()).await.map_err(cannot)?;
    let meta = file.metadata().await.map_err(cannot)?;
    if !meta.is_file() {
        return Err(not_regular());
    }
    if meta.len() > limit as u64 {
        return Err(too_large(meta.len()));
    }
    // One byte past the limit is enough to tell that the file outgrew it.
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(limit as u64 + 1).read_to_end(&mut bytes).await.map_err(cannot)?;
    if bytes.len() > limit {
        return Err(too_large(bytes.len() as u64));
    }
    Ok(bytes)
}

/// Turn the operation's event stream into one line per finished task:
/// `<what>: ok` / `failed: <why>` / `skipped: <why>`, with a task nested under
/// a phase indented beneath it. Output lines are not kept — a sync plugin's
/// retained stderr is the exception, since the operation asked for it to
/// survive — so the log stays a summary, not a transcript. Each line also
/// goes to `lines` the moment it is made, for a watcher that reads along.
async fn collect_log(
    mut receiver: tokio::sync::mpsc::UnboundedReceiver<icp_events::Event<Task>>,
    lines: Option<mpsc::UnboundedSender<String>>,
) -> Vec<String> {
    let mut log = Vec::new();
    let mut push = |line: String| {
        if let Some(lines) = &lines {
            let _ = lines.send(line.clone());
        }
        log.push(line);
    };
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
                        push(format!("{indent}{label}: ok"));
                        for line in retained_output {
                            push(format!("{indent}  {line}"));
                        }
                    }
                    TaskOutcome::Failed { message, causes } => {
                        let mut line = format!("{indent}{label}: failed: {message}");
                        for cause in causes {
                            line.push_str(": ");
                            line.push_str(&cause);
                        }
                        push(line);
                    }
                    TaskOutcome::Skipped { reason } => {
                        push(format!("{indent}{label}: skipped: {reason}"));
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

/// A fresh directory for one deploy under `parent`, randomly named, and on
/// Unix readable by its owner alone: the bundle's files and the ids the
/// deploy records are the user's business, and the parent (the user's local
/// data directory, or the system temporary directory) may be more open.
fn deploy_directory(parent: &std::path::Path) -> std::io::Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("imcp2-deploy-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    builder.tempdir_in(parent)
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
        archive(&[("icp.yaml", manifest.as_bytes()), ("canisters/backend.wasm", wasm)])
    }

    fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        for (path, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(&mut header, path, *data).unwrap();
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
            workdir: None,
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
    // Each deploy gets its own fresh directory, and on Unix one no other
    // user of the machine can read: the parent may be world-readable.
    #[test]
    fn a_deploy_directory_is_fresh_and_private() {
        let parent = tempfile::tempdir().unwrap();
        let a = deploy_directory(parent.path()).unwrap();
        let b = deploy_directory(parent.path()).unwrap();
        assert_ne!(a.path(), b.path());
        assert!(a.path().starts_with(parent.path()));
        assert!(a.path().file_name().unwrap().to_str().unwrap().starts_with("imcp2-deploy-"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(a.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "mode {mode:o}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_bundle_deploys_up_to_the_create_phase_offline() {
        let (wasm, sha) = wasm();
        let outcome = deploy_bundle(
            Arc::new(AnonymousIdentity),
            request(bundle(&sha, &wasm), "ic"),
            Watch::default(),
        )
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
    // does not hash to it is refused before any phase, as a request error
    // that names the canister and both digests.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_wasm_that_does_not_match_its_checksum_is_refused_up_front() {
        let (wasm, _) = wasm();
        let wrong = "0".repeat(64);
        let err = deploy_bundle(
            Arc::new(AnonymousIdentity),
            request(bundle(&wrong, &wasm), "ic"),
            Watch::default(),
        )
        .await
        .expect_err("a checksum mismatch is refused");
        assert!(err.0.contains("backend") && err.0.contains("checksum mismatch"), "{err}");
        assert!(err.0.contains(&wrong), "{err}");
    }

    // Only the IC: a deploy to `local` names the icp CLI's managed network,
    // and is refused up front with the way out; a connected testnet is not
    // the IC either.
    #[tokio::test(flavor = "multi_thread")]
    async fn environments_off_the_ic_network_are_refused() {
        let (wasm, sha) = wasm();
        let mut local = request(bundle(&sha, &wasm), "local");
        local.no_create = false;
        let err = deploy_bundle(Arc::new(AnonymousIdentity), local, Watch::default())
            .await
            .expect_err("a managed network is refused");
        assert!(err.0.contains("not the Internet Computer") && err.0.contains("`ic`"), "{err}");

        let manifest = format!(
            "networks:\n  - name: testnet\n    mode: connected\n    url: https://testnet.example\n    \
             root-key: fetch\nenvironments:\n  - name: staging\n    network: testnet\n\
             canisters:\n  - name: backend\n    build:\n      steps:\n        - type: pre-built\n          \
             path: canisters/backend.wasm\n          sha256: {sha}\n"
        );
        let bytes =
            archive(&[("icp.yaml", manifest.as_bytes()), ("canisters/backend.wasm", &wasm)]);
        let err =
            deploy_bundle(Arc::new(AnonymousIdentity), request(bytes, "staging"), Watch::default())
                .await
                .expect_err("a testnet is refused");
        assert!(err.0.contains("testnet") && err.0.contains("not the Internet Computer"), "{err}");
    }

    // Before anything is deployed: an environment the bundle does not
    // declare, or an id for a canister the environment does not hold, is a
    // request error — nothing ran, so there is no outcome to report.
    #[tokio::test(flavor = "multi_thread")]
    async fn unknown_environments_and_canisters_are_request_errors() {
        let (wasm, sha) = wasm();
        let err = deploy_bundle(
            Arc::new(AnonymousIdentity),
            request(bundle(&sha, &wasm), "staging"),
            Watch::default(),
        )
        .await
        .expect_err("no such environment");
        assert!(err.0.contains("staging"), "{err}");

        let mut request = request(bundle(&sha, &wasm), "ic");
        request.canister_ids.insert("frontend".into(), Principal::management_canister());
        let err = deploy_bundle(Arc::new(AnonymousIdentity), request, Watch::default())
            .await
            .expect_err("no such canister");
        assert!(err.0.contains("frontend"), "{err}");
    }

    // A bundle never carries a script step, and this server never runs one:
    // the untrusted rule the project is loaded under refuses it at the load,
    // as a request error naming the step, before any phase — so no canister
    // is created ahead of a sync step that would then be refused.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_script_step_is_refused_before_any_phase_runs() {
        let manifest = "canisters:\n  - name: backend\n    build:\n      steps:\n        \
                        - type: script\n          command: touch /tmp/pwned\n";
        let bytes = archive(&[("icp.yaml", manifest.as_bytes())]);
        let err =
            deploy_bundle(Arc::new(AnonymousIdentity), request(bytes, "ic"), Watch::default())
                .await
                .expect_err("a script step is refused");
        assert!(
            err.0.contains("canister 'backend' has a build step that is not a pre-built module")
                && err.0.contains("touch /tmp/pwned"),
            "{err}"
        );
    }

    // A canister directory the manifest spells absolutely resolves inside the
    // bundle for every reader that goes through the bundle filesystem — the
    // loader finds the `canister.yaml` it looks for there — but the
    // sync-plugin runtime takes the directory as a host path and would make
    // `/etc` its sandbox root. Refused before any phase.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_canister_directory_outside_the_root_is_refused() {
        let (wasm, sha) = wasm();
        let canister = format!(
            "name: backend\nbuild:\n  steps:\n    - type: pre-built\n      path: backend.wasm\n      \
             sha256: {sha}\n"
        );
        let bytes = archive(&[
            ("icp.yaml", b"canisters:\n  - /etc\n"),
            ("etc/canister.yaml", canister.as_bytes()),
            ("etc/backend.wasm", &wasm),
        ]);
        let err =
            deploy_bundle(Arc::new(AnonymousIdentity), request(bytes, "ic"), Watch::default())
                .await
                .expect_err("a canister directory outside the root is refused");
        // The confined filesystem finds nothing at `/etc`, so the loader does
        // not find the canister: the spelling itself is the refusal.
        assert!(err.0.contains("canister manifest") && err.0.contains("'/etc'"), "{err}");
    }

    // A manifest may declare a connected network that claims the mainnet root
    // key over an endpoint of its own; an environment on it is refused like
    // every network that is not the reserved `ic`.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_network_claiming_mainnet_elsewhere_is_refused() {
        let (wasm, sha) = wasm();
        let manifest = format!(
            "networks:\n  - name: mainnet2\n    mode: connected\n    url: http://127.0.0.1:4943\n    \
             root-key: mainnet\nenvironments:\n  - name: elsewhere\n    network: mainnet2\n\
             canisters:\n  - name: backend\n    build:\n      steps:\n        - type: pre-built\n          \
             path: canisters/backend.wasm\n          sha256: {sha}\n"
        );
        let bytes =
            archive(&[("icp.yaml", manifest.as_bytes()), ("canisters/backend.wasm", &wasm)]);
        let err = deploy_bundle(
            Arc::new(AnonymousIdentity),
            request(bytes, "elsewhere"),
            Watch::default(),
        )
        .await
        .expect_err("a network that is not `ic` is refused");
        assert!(err.0.contains("mainnet2") && err.0.contains("not the Internet Computer"), "{err}");
    }

    // A gzip-compressed module is held to what it expands to, since the
    // library gunzips it in memory to read its interface: one that hashes
    // correctly but expands past the module limit is refused before any
    // phase.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_gzipped_wasm_that_expands_past_the_module_limit_is_refused() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&vec![0u8; host::MAX_WASM_BYTES as usize + 1]).unwrap();
        let gz = encoder.finish().unwrap();
        let sha = hex::encode(Sha256::digest(&gz));
        let err = deploy_bundle(
            Arc::new(AnonymousIdentity),
            request(bundle(&sha, &gz), "ic"),
            Watch::default(),
        )
        .await
        .expect_err("an over-large gzipped module is refused");
        assert!(err.0.contains("backend") && err.0.contains("expands past"), "{err}");
    }

    // Two canisters whose names differ only in case would share build
    // output on a case-insensitive disk; refused before any phase.
    #[tokio::test(flavor = "multi_thread")]
    async fn canister_names_that_differ_only_in_case_are_refused() {
        let (wasm, sha) = wasm();
        let manifest = format!(
            "canisters:\n  - name: backend\n    build:\n      steps:\n        - type: pre-built\n          \
             path: canisters/backend.wasm\n          sha256: {sha}\n  - name: Backend\n    build:\n      \
             steps:\n        - type: pre-built\n          path: canisters/backend.wasm\n          \
             sha256: {sha}\n"
        );
        let bytes =
            archive(&[("icp.yaml", manifest.as_bytes()), ("canisters/backend.wasm", &wasm)]);
        let err =
            deploy_bundle(Arc::new(AnonymousIdentity), request(bytes, "ic"), Watch::default())
                .await
                .expect_err("case-colliding names are refused");
        assert!(err.0.contains("differ only in letter case"), "{err}");
    }

    // A `bundle_path` is read only when it is a regular file: a directory
    // here, and by the same check a device or a pipe, whose length says
    // nothing about what reading it would produce.
    // A deploy works under the directory it is given and removes its own
    // when it returns, so a run that is cut off is the only one to leave a
    // record there.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_deploy_works_under_its_directory_and_removes_it_when_done() {
        let (wasm, sha) = wasm();
        let parent = tempfile::tempdir().unwrap();
        let workdir = Utf8PathBuf::from_path_buf(parent.path().join("deploys")).unwrap();
        let mut request = request(bundle(&sha, &wasm), "ic");
        request.workdir = Some(workdir.clone());
        let outcome =
            deploy_bundle(Arc::new(AnonymousIdentity), request, Watch::default()).await.unwrap();
        assert_eq!(outcome.status, Status::Failed, "{:?}", outcome.log);
        assert!(workdir.is_dir(), "the parent is made");
        let left: Vec<_> = std::fs::read_dir(&workdir).unwrap().collect();
        assert!(left.is_empty(), "the run's own directory is removed: {left:?}");
    }

    // The library resolves the mode at install, after creation, and panics on
    // a spelling it does not know: refused at entry instead, before anything
    // is read.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unknown_mode_is_refused_at_entry() {
        let mut bad = request(Vec::new(), "ic");
        bad.mode = "yolo".into();
        let err =
            deploy_bundle(Arc::new(AnonymousIdentity), bad, Watch::default()).await.unwrap_err();
        assert!(err.0.contains("mode must be one of"), "{}", err.0);
        assert!(err.0.contains("'yolo'"), "{}", err.0);
    }

    // The file is read to the limit and one byte past it, never to its end:
    // a file that grows between the size check and the read is still bounded.
    #[tokio::test]
    async fn a_bundle_file_is_read_to_its_limit_and_no_further() {
        let dir = tempfile::tempdir().unwrap();
        let path = Utf8PathBuf::from_path_buf(dir.path().join("b.tar.gz")).unwrap();
        std::fs::write(&path, [7u8; 32]).unwrap();
        assert_eq!(read_bundle_file(&path, 32).await.unwrap().len(), 32);
        let err = read_bundle_file(&path, 16).await.unwrap_err();
        assert!(err.0.contains("above the 16 byte limit"), "{}", err.0);
        let err = read_bundle_file(Utf8Path::new("relative/b.tar.gz"), 32).await.unwrap_err();
        assert!(err.0.contains("absolute"), "{}", err.0);
        let err = read_bundle_file(&path.with_file_name("missing"), 32).await.unwrap_err();
        assert!(err.0.contains("cannot read bundle"), "{}", err.0);
    }

    // The Candid a bundle carries is parsed by the library without a depth
    // guard, on the worker thread: an argument or an interface nested past
    // the bound is refused before any phase, not left to overflow the stack
    // at install or at the upgrade check.
    #[tokio::test(flavor = "multi_thread")]
    async fn candid_nested_past_the_bound_is_refused_up_front() {
        let deep = format!("({}null)", "opt ".repeat(200));
        let (wasm, sha) = wasm();
        let manifest = format!(
            "canisters:\n  - name: backend\n    init_args:\n      value: '{deep}'\n    build:\n      \
             steps:\n        - type: pre-built\n          path: canisters/backend.wasm\n          \
             sha256: {sha}\n"
        );
        let bytes =
            archive(&[("icp.yaml", manifest.as_bytes()), ("canisters/backend.wasm", &wasm)]);
        let err =
            deploy_bundle(Arc::new(AnonymousIdentity), request(bytes, "ic"), Watch::default())
                .await
                .expect_err("a deeply nested init_args value is refused");
        assert!(err.0.contains("`init_args` is nested too deeply"), "{err}");

        let interface = format!("service : {{ f : ({}null) -> () }}", "opt ".repeat(200));
        let wasm = wat::parse_str(format!(
            "(module (@custom \"icp:public candid:service\" \"{interface}\"))"
        ))
        .unwrap();
        let sha = hex::encode(Sha256::digest(&wasm));
        let bytes = bundle(&sha, &wasm);
        let err =
            deploy_bundle(Arc::new(AnonymousIdentity), request(bytes, "ic"), Watch::default())
                .await
                .expect_err("a deeply nested interface is refused");
        assert!(err.0.contains("`candid:service` interface"), "{err}");
        assert!(err.0.contains("nested too deeply"), "{err}");

        // A module with an ordinary interface deploys as before.
        let wasm = wat::parse_str(
            "(module (@custom \"icp:public candid:service\" \"service : { f : () -> () }\"))",
        )
        .unwrap();
        let sha = hex::encode(Sha256::digest(&wasm));
        let outcome = deploy_bundle(
            Arc::new(AnonymousIdentity),
            request(bundle(&sha, &wasm), "ic"),
            Watch::default(),
        )
        .await
        .unwrap();
        assert!(outcome.log.iter().any(|l| l == "Building canisters: ok"), "{:?}", outcome.log);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_bundle_path_that_is_not_a_regular_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        let mut local = request(Vec::new(), "ic");
        local.bundle = BundleSource::Path(path);
        let err =
            deploy_bundle(Arc::new(AnonymousIdentity), local, Watch::default()).await.unwrap_err();
        assert!(err.0.contains("not a regular file"), "{}", err.0);
    }

    // The manifest can name only what the archive carried: a variable file
    // the bundle does not hold is refused at load — before any phase, since
    // the value would otherwise be sent to the canister as a setting — and so
    // is a wasm, whether the path is absolute or climbing: the vet asks the
    // bundle's filesystem whether a regular file is there, and nothing
    // outside the root is. Nothing on the machine is reached for, whatever
    // exists at that spelling.
    #[tokio::test(flavor = "multi_thread")]
    async fn paths_the_bundle_does_not_hold_are_refused() {
        let (wasm, sha) = wasm();
        let manifest = format!(
            "canisters:\n  - name: backend\n    settings:\n      environment_variables:\n        \
             SECRET:\n          path: /etc/hostname\n    build:\n      steps:\n        \
             - type: pre-built\n          path: canisters/backend.wasm\n          sha256: {sha}\n"
        );
        let bytes =
            archive(&[("icp.yaml", manifest.as_bytes()), ("canisters/backend.wasm", &wasm)]);
        let err =
            deploy_bundle(Arc::new(AnonymousIdentity), request(bytes, "ic"), Watch::default())
                .await
                .expect_err("a variable file outside the bundle is refused");
        assert!(err.0.contains("SECRET"), "{err}");
        assert!(err.0.contains("'/etc/hostname' is outside"), "{err}");

        for path in ["/etc/hostname", "../../../../etc/hostname"] {
            let manifest = format!(
                "canisters:\n  - name: backend\n    build:\n      steps:\n        - type: pre-built\n          \
                 path: {path}\n          sha256: {sha}\n"
            );
            let bytes = archive(&[("icp.yaml", manifest.as_bytes())]);
            let err =
                deploy_bundle(Arc::new(AnonymousIdentity), request(bytes, "ic"), Watch::default())
                    .await
                    .expect_err("a wasm outside the bundle is refused");
            assert!(
                err.0.contains("etc/hostname")
                    && err.0.contains("not a regular file in the project"),
                "{path}: {err}"
            );
        }
    }

    // The log is what the agent (and the user) read to learn how far a deploy
    // got: phases by title, canister tasks by kind and name, nested tasks
    // indented, every outcome spelled out.
    #[tokio::test]
    async fn the_event_stream_becomes_a_readable_log() {
        let (reporter, receiver) = icp_events::channel::<Task>();
        let collector = tokio::spawn(collect_log(receiver, None));
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

    // A watcher reads each line as the run makes it — the same lines, in the
    // same order, the outcome collects at the end.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_log_is_streamed_as_it_is_made() {
        let (wasm, sha) = wasm();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let watch = Watch { stop: CancellationToken::new(), lines: Some(tx) };
        let outcome =
            deploy_bundle(Arc::new(AnonymousIdentity), request(bundle(&sha, &wasm), "ic"), watch)
                .await
                .unwrap();
        assert_eq!(outcome.status, Status::Failed);
        let mut streamed = Vec::new();
        while let Some(line) = rx.recv().await {
            streamed.push(line);
        }
        assert_eq!(streamed, outcome.log);
        assert!(streamed.iter().any(|l| l == "Building canisters: ok"), "{streamed:?}");
    }

    // A stop asked for before the run begins ends it without a step, and
    // the directory stays behind as the record, since whoever asked may
    // never read the answer.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_interrupted_deploy_stops_and_keeps_its_directory() {
        let (wasm, sha) = wasm();
        let parent = tempfile::tempdir().unwrap();
        let mut request = request(bundle(&sha, &wasm), "ic");
        request.workdir = Some(Utf8PathBuf::from_path_buf(parent.path().to_path_buf()).unwrap());
        let stop = CancellationToken::new();
        stop.cancel();
        let watch = Watch { stop, lines: None };
        let outcome = deploy_bundle(Arc::new(AnonymousIdentity), request, watch).await.unwrap();
        assert_eq!(outcome.status, Status::Interrupted);
        assert_eq!(outcome.canisters, ["backend"]);
        assert!(outcome.created.is_empty());
        let error = outcome.error.as_deref().unwrap();
        assert!(error.contains("interrupted"), "{error}");
        assert!(!outcome.log.iter().any(|l| l.starts_with("Building")), "{:?}", outcome.log);
        let kept: Vec<_> = std::fs::read_dir(parent.path()).unwrap().flatten().collect();
        assert_eq!(kept.len(), 1, "the deploy directory is kept");
        assert!(outcome.log.last().unwrap().contains("is kept"), "{:?}", outcome.log);
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
