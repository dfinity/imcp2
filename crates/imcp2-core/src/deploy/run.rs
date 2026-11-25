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
    future::Future,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
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
use tracing::{Instrument, Span};

use crate::deploy::{
    calls::{AgentCalls, Creations, UntilStopped},
    host::{self, AllowedPlugins, BundleLimits, PluginLimits},
};

/// Where the bundle bytes come from.
pub enum BundleSource {
    /// The archive itself.
    Bytes(Vec<u8>),
    /// An absolute path to the archive on this machine: the one the agent
    /// named.
    Path(Utf8PathBuf),
    /// A bundle already extracted, by an upload store as the archive
    /// arrived (see [`crate::deploy::Uploads`]): its directory, which the deploy
    /// takes for its own, and what it extracted to, in bytes.
    Extracted { dir: Utf8PathBuf, bytes: u64 },
}

// By hand so a request never prints megabytes of archive.
impl fmt::Debug for BundleSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BundleSource::Bytes(bytes) => write!(f, "Bytes({} bytes)", bytes.len()),
            BundleSource::Path(path) => write!(f, "Path({path})"),
            BundleSource::Extracted { dir, bytes } => write!(f, "Extracted({dir}, {bytes} bytes)"),
        }
    }
}

/// The install modes `icp deploy --mode` takes, as the library spells them.
pub const INSTALL_MODES: [&str; 4] = ["auto", "install", "reinstall", "upgrade"];

/// Everything one deploy is given.
#[derive(Debug)]
pub struct DeployRequest {
    pub bundle: BundleSource,
    /// How large a bundle this deploy takes: its archive, what it extracts
    /// to, and what its directory may come to.
    pub limits: BundleLimits,
    /// Which sync plugins this deploy runs: any the bundle brings, on the
    /// user's own machine; the ones the server knows, where it deploys for
    /// others.
    pub plugins: AllowedPlugins,
    /// What each sync plugin run is held to: the icp CLI's defaults, unless
    /// the server sets its own.
    pub plugin_limits: PluginLimits,
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
    /// directory when `None`). A run that created no canister removes it as
    /// it returns. One that was interrupted, or that created a canister
    /// however it ended, leaves it, cut down to its record
    /// (`.icp/data/mappings/<environment>.ids.json`, every canister the
    /// deploy created), so a caller who never got the answer can recover the
    /// ids instead of creating a second set; the bundle's own files, which
    /// the caller still has, go. The answer is not yet delivered when this
    /// returns — the client can still go away while it is sent — so a
    /// finished run that created canisters keeps its record too, until it
    /// expires ([`remove_old_deploy_records`]). One cut off with the process
    /// leaves it whole, for [`prune_abandoned_deploys`] to cut down at the
    /// next start.
    pub workdir: Option<Utf8PathBuf>,
}

/// How a running deploy is watched: where its progress goes as it happens,
/// and what tells it to stop.
#[derive(Clone, Debug, Default)]
pub struct Watch {
    /// Cancelled to interrupt the deploy. The run stops at its next step:
    /// a canister call already in flight is waited for and its result
    /// recorded (a canister it created is in the outcome), no further call
    /// is made, and the outcome reports [`Status::Interrupted`] with
    /// everything that landed. Cancelled while the bundle is still being
    /// read and checked — before anything was created — there is no outcome,
    /// only the refusal that says so.
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
    /// The balance the cycles ledger reported as it refused to create a
    /// canister because the balance did not cover it, when it did: the
    /// user's cycles ran short. From the ledger's own answer
    /// ([`Creations`]), never from the wording of an error.
    pub short_of_cycles: Option<u128>,
    /// Whether a call creating a canister ended without a verdict, having
    /// gone unanswered or failed after it was sent: that canister may exist
    /// without being in `canister_ids`, and `error` says so. From the calls
    /// themselves ([`Creations`]): the error is the first failure alone, and
    /// the log gives any other a line that does not say it.
    pub uncertain_creation: bool,
}

/// An error made before the deploy could begin: the request itself was
/// unusable, so there is no outcome to report, only the reason.
#[derive(Debug)]
pub struct RequestError(pub String);

/// What a deploy stopped before it began says. It is still a
/// [`RequestError`] — nothing was created, and there is no outcome — but it
/// is not the request's fault, and [`RequestError::was_interrupted`] tells
/// it from one that is.
const INTERRUPTED_BEFORE_IT_BEGAN: &str =
    "the deploy was interrupted before it began (the call was cancelled, the client went away, \
     or the server is stopping); nothing was created";

/// What a refusal that is the server's own fault begins with: see
/// [`RequestError::server_fault`].
const SERVER_FAULT: &str = "this server could not prepare the deploy";

impl RequestError {
    /// A deploy that could not begin for a reason that is the server's: its
    /// directory could not be made, a step of its own failed. Nothing was
    /// created and the request may be fine, so it says so — the caller can
    /// try again, which is no use after a refusal of the bundle — and
    /// [`Self::is_server_fault`] tells it from one.
    pub fn server_fault(what: impl fmt::Display) -> Self {
        Self(format!("{SERVER_FAULT}, and nothing was created; try again later ({what})"))
    }

    /// Whether this is a [`Self::server_fault`].
    pub fn is_server_fault(&self) -> bool {
        self.0.starts_with(SERVER_FAULT)
    }

    /// The refusal of a deploy that was stopped while its bundle was still
    /// being read and checked.
    pub fn interrupted() -> Self {
        Self(INTERRUPTED_BEFORE_IT_BEGAN.into())
    }

    /// Whether this is [`Self::interrupted`]: a stop, not a request or a
    /// bundle that was refused.
    pub fn was_interrupted(&self) -> bool {
        self.0 == INTERRUPTED_BEFORE_IT_BEGAN
    }
}

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
    // Nobody to deploy for, nothing read: the bundle's extraction, the
    // project's loading and the bundle's checking each do up to a gigabyte
    // of work, so the stop is looked at before each of them.
    let stopped = || match watch.stop.is_cancelled() {
        true => Err(RequestError::interrupted()),
        false => Ok(()),
    };
    stopped()?;
    let limits = request.limits;
    let plugins = request.plugins.clone();
    // An archive is read as it is extracted, never whole: one named by path
    // is opened here, held to the archive limit by its size before a byte
    // of it is read.
    let bundle = match request.bundle {
        BundleSource::Bytes(bytes) => Bundle::Archive(Box::new(std::io::Cursor::new(bytes))),
        BundleSource::Path(path) => {
            Bundle::Archive(Box::new(open_bundle_file(&path, limits.archive_bytes).await?))
        }
        BundleSource::Extracted { dir, bytes } => Bundle::Extracted { dir, bytes },
    };

    // The working directory holds the bundle's files, the ids the deploy
    // records, and the build artifacts. Until the deploy starts it is a
    // temporary directory, gone with any early return; from then on it is
    // kept on purpose and removed only once the outcome — the ids above all —
    // has been assembled, so a run that is cut off leaves its record behind.
    let parent = match &request.workdir {
        Some(dir) => {
            std::fs::create_dir_all(dir).map_err(|e| {
                RequestError::server_fault(format!(
                    "cannot create the deploy directory '{dir}': {e}"
                ))
            })?;
            dir.as_std_path().to_path_buf()
        }
        None => std::env::temp_dir(),
    };
    stopped()?;
    let scratch = deploy_directory(&parent).map_err(|e| {
        RequestError::server_fault(format!("cannot create a scratch directory: {e}"))
    })?;
    let dir = Utf8PathBuf::from_path_buf(scratch.path().to_path_buf()).map_err(|p| {
        RequestError::server_fault(format!("scratch directory path is not UTF-8: {}", p.display()))
    })?;
    // The extraction owns the directory while it runs: a blocking task is
    // not stopped when this future is dropped, and one that outlived the
    // directory would write its files back under a path nothing removes.
    // A bundle that arrived extracted is moved in instead, whole: its
    // directory becomes this one.
    let (scratch, fs, bundle_bytes) = {
        let dir = dir.clone();
        let (scratch, bundle) = tokio::task::spawn_blocking(move || {
            // What the server could not write or move is its own failure,
            // not the bundle's.
            let bundle = match bundle {
                Bundle::Archive(archive) => host::extract_bundle_from(archive, &dir, &limits)
                    .map(|extracted| (extracted.fs, extracted.bytes))
                    .map_err(|e| match e {
                        host::ExtractError::Storage(_) => RequestError::server_fault(e),
                        refused => RequestError(refused.to_string()),
                    }),
                Bundle::Extracted { dir: from, bytes } => std::fs::rename(&from, &dir)
                    .map_err(|e| format!("the uploaded bundle could not be moved in: {e}"))
                    .and_then(|()| host::open_bundle(&dir))
                    .map(|fs| (fs, bytes))
                    .map_err(RequestError::server_fault),
            };
            (scratch, bundle)
        })
        .await
        .map_err(|e| RequestError::server_fault(format!("bundle extraction panicked: {e}")))?;
        let (fs, bytes) = bundle?;
        (scratch, fs, bytes)
    };

    stopped()?;
    let host = host::host_for(fs.clone(), &limits, request.plugin_limits);
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
            .map_err(|e| RequestError::server_fault(format!("project load panicked: {e}")))?
            .map_err(|e| RequestError(error_chain(&e)))?;
    }
    stopped()?;
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
                bundle_bytes,
                &limits,
                &plugins,
            )
        })
        .await
        .map_err(|e| RequestError::server_fault(format!("bundle check panicked: {e}")))?
        .map_err(RequestError)?;
    }

    stopped()?;

    // Seed the id store with the mapping the caller passed: from here on the
    // operation sees those canisters as existing, exactly as it would see the
    // ids a previous `icp deploy` recorded in the project's `.icp` directory.
    // Every name is checked first, as the store would check each, and the
    // mapping is then written whole, once — the store's own register reads
    // and rewrites the file per entry — and off the runtime's workers. The
    // file is the store's for an environment on the IC, a connected network
    // (`check_bundle` held it to that), in a directory the bundle could not
    // have put an `.icp` in.
    if let Some(name) = request.canister_ids.keys().find(|name| !env.canisters.contains_key(*name))
    {
        return Err(RequestError(format!(
            "canister '{name}' not found in environment '{}'",
            request.environment
        )));
    }
    if !request.canister_ids.is_empty() {
        let (dir, name, ids) = (dir.clone(), env.name.clone(), request.canister_ids.clone());
        tokio::task::spawn_blocking(move || seed_ids(&dir, &name, &ids))
            .await
            .map_err(|e| RequestError::server_fault(format!("seeding the ids panicked: {e}")))?
            .map_err(|e| {
                RequestError::server_fault(format!("could not record the canister ids passed: {e}"))
            })?;
    }
    stopped()?;

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
        short_of_cycles: None,
        uncertain_creation: false,
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
    //
    // The calls stop being made when the deploy is told to stop, and say
    // whether any was made at all: see [`run_until_stopped`].
    // They also note what the calls that create canisters come to: the
    // cycles ledger refusing one for lack of cycles, which is how a deploy
    // knows the user's balance ran short, and one ending without a verdict.
    let begun = Arc::new(AtomicBool::new(false));
    let creations = Creations::default();
    let calls = Deferred::new({
        let (stop, begun, creations) = (watch.stop.clone(), begun.clone(), creations.clone());
        move || {
            let (identity, stop) = (identity.clone(), stop.clone());
            let (begun, creations) = (begun.clone(), creations.clone());
            async move {
                let agent = mainnet_agent(identity).map_err(RequestError)?;
                let calls = AgentCalls::new(agent).map_err(RequestError)?;
                let calls = UntilStopped::new(calls, stop, begun).noting(creations);
                let calls: Arc<dyn CanisterCalls> = Arc::new(calls);
                Ok::<_, RequestError>(calls)
            }
        }
    });

    // One reporter for the whole deploy; its events are turned into log lines
    // as they arrive, so a run that fails still reports every phase before it.
    let (reporter, receiver) = icp_events::channel::<Task>();
    // The collector logs each line too, under the span the caller put the
    // deploy in (the session), so the server's own log has the events.
    let lines = watch.lines;
    let collector = tokio::spawn(collect_log(receiver, lines.clone()).instrument(Span::current()));
    tracing::info!(
        dir = %dir,
        environment = %request.environment,
        canisters = ?outcome.canisters,
        "deploy started"
    );

    // From here the directory outlives this future (see above).
    let workdir = scratch.keep();
    let mut report = DeployReport::default();
    let result = run_until_stopped(
        deploy(&host, &calls, &params, &reporter, &mut report),
        &watch.stop,
        &begun,
        STOP_GRACE,
    )
    .await;
    // The receiver ends only once every reporter handle is gone.
    drop(reporter);
    outcome.log = collector.await.unwrap_or_default();
    outcome.created = report.created;
    outcome.short_of_cycles = creations.short_of_cycles();
    outcome.uncertain_creation = creations.uncertain();

    let interrupted = "the deploy was interrupted before it finished (the call was cancelled, the \
                       client went away or the server is stopping); `canister_ids` holds every \
                       canister it is known to have created";
    match result {
        Some(Ok(())) => outcome.status = Status::Deployed,
        // Stopped, the run ends in an error: the refusal of the call it went
        // on to make, or what a call in flight came back with. The first is
        // the interruption and nothing more. The second is said, since it is
        // what the caller has to go on — above all a call that went
        // unanswered, which may have created a canister nothing lists.
        Some(Err(e)) if watch.stop.is_cancelled() => {
            outcome.status = Status::Interrupted;
            let ended = error_chain(&e);
            tracing::info!(%ended, "the interrupted run ended");
            outcome.error = Some(interrupted_with(interrupted, &ended));
        }
        // Not stopped, and failed: the error is the answer, with the same
        // warning when a call went unanswered — the caller's next move is a
        // retry, and a retry creates what the mapping does not list.
        Some(Err(e)) => {
            outcome.status = Status::Failed;
            outcome.error = Some(failed_with(&error_chain(&e)));
        }
        None => {
            outcome.status = Status::Interrupted;
            outcome.error = Some(if begun.load(Ordering::SeqCst) {
                // The one case in which the list may be short, said plainly:
                // the caller is about to decide whether to create again.
                format!(
                    "{interrupted} — except that a call was still unanswered {} seconds after \
                     the stop and was given up on: if it was creating a canister, that canister \
                     may exist without being listed, so check before deploying again",
                    STOP_GRACE.as_secs()
                )
            } else {
                interrupted.into()
            });
        }
    }

    // A creation that ended without a verdict is said in the error
    // whichever failure the error is of: the run's error is its first
    // failure alone.
    outcome.error = outcome.error.map(|e| warned_of_creation(e, outcome.uncertain_creation));

    // What this function itself has to say goes where the run's lines went:
    // to the watcher as it is said, and into the outcome's log.
    let note = |log: &mut Vec<String>, line: String| {
        forward(&lines, &line);
        log.push(line);
    };

    // Whatever the store holds now: the seeded ids plus every id created before
    // a failure, which is what a retry needs to pass back in.
    let stored = match host.ids_by_environment(&selection).await {
        Ok(ids) => Some(ids.into_iter().collect()),
        Err(e) => {
            let line = format!("reading the canister ids back failed: {}", error_chain(&e));
            note(&mut outcome.log, line);
            None
        }
    };
    let seeded = std::mem::take(&mut outcome.canister_ids);
    outcome.canister_ids = ids_for_a_retry(seeded, stored.clone(), &outcome.created);

    // The outcome carries everything the directory recorded, but it has not
    // reached the caller yet: it is sent after this returns, and a client
    // that goes away while it is sent never reads it. So a run that created
    // a canister keeps the directory as the record — cut down to it, since
    // the bundle's files are the caller's to send again and a directory per
    // run would otherwise hold a bundle each (see [`DeployRequest::workdir`]).
    // Only a run that created nothing has nothing to lose by removing it.
    drop(host);
    match &outcome.error {
        None => tracing::info!(
            status = outcome.status.as_str(),
            created = ?outcome.created,
            "deploy finished"
        ),
        Some(error) => tracing::warn!(
            status = outcome.status.as_str(),
            created = ?outcome.created,
            %error,
            "deploy did not finish"
        ),
    }
    // Nor after a run that finished once a stop had been asked for: it ran
    // to its end in the time it was given, but whoever asked for the stop may
    // be the client, gone, and the ids it never read are in the record alone.
    let stopped = watch.stop.is_cancelled();
    let interrupted = outcome.status == Status::Interrupted || stopped;
    if keeps_its_record(interrupted, &outcome.created) {
        // The record is for a caller this answer never reaches, so it is
        // brought up to the answer first: a canister that was created and
        // that the store did not record is in neither otherwise.
        if !outcome.created.is_empty() {
            let (dir, name, ids) = (dir.clone(), env.name.clone(), outcome.canister_ids.clone());
            let completed =
                tokio::task::spawn_blocking(move || complete_record(&dir, &name, stored, &ids))
                    .await
                    .unwrap_or_else(|e| Err(format!("the write panicked: {e}")));
            match completed {
                Ok(false) => {}
                Ok(true) => {
                    let line = "the ids the deploy's record was missing were added to it".into();
                    note(&mut outcome.log, line);
                }
                Err(e) => {
                    let line = format!(
                        "the deploy's record could not be completed ({e}): `canister_ids` in \
                         this answer is the only full list of what was created"
                    );
                    note(&mut outcome.log, line);
                }
            }
        }
        let pruning = workdir.clone();
        let pruned = tokio::task::spawn_blocking(move || prune_to_record(&pruning)).await;
        if let Ok(Err(e)) = &pruned {
            tracing::warn!(dir = %workdir.display(), %e, "could not cut the directory down");
        }
        if interrupted {
            let line = format!(
                "{}; the deploy directory '{}' is kept, with the ids it recorded",
                if outcome.status == Status::Interrupted {
                    "interrupted"
                } else {
                    "asked to stop as it finished"
                },
                workdir.display()
            );
            note(&mut outcome.log, line);
        } else {
            // Said to the server's log alone: a caller reading this outcome
            // has the ids already, and the record is for one that does not.
            tracing::info!(
                dir = %workdir.display(),
                "the deploy created canisters; its directory is kept with the ids it recorded"
            );
        }
    } else if let Err(e) = tokio::fs::remove_dir_all(&workdir).await {
        let line = format!("removing the deploy directory '{}' failed: {e}", workdir.display());
        note(&mut outcome.log, line);
    }
    Ok(outcome)
}

/// How long a deploy that was told to stop is given to end of its own
/// accord: for the calls it had in flight to be answered and recorded.
/// Within what a stopping server has before it is killed (the native unit's
/// `TimeoutStopSec` is thirty seconds). A server that stops its deploys
/// waits this long, and a little more, for them to have ended before it
/// exits.
pub const STOP_GRACE: Duration = Duration::from_secs(20);

/// What an interrupted deploy says of itself when its run ended in `ended`
/// (an error chain). The refusal of a call the stop prevented is the
/// interruption itself and adds nothing; anything else is what a call in
/// flight came back with, and is passed on — with the warning it calls for
/// when a call went unanswered, since that call may have taken effect.
fn interrupted_with(interrupted: &str, ended: &str) -> String {
    if ended.contains(crate::deploy::calls::STOPPING) && !went_unanswered(ended) {
        return interrupted.to_string();
    }
    let mut said = format!("{interrupted}. The run ended with: {ended}");
    if went_unanswered(ended) {
        said.push_str(UNANSWERED);
    }
    said
}

/// Whether `text`, an error chain or a line of a deploy's log, says that a
/// call went unanswered: one that may have taken effect all the same.
pub(super) fn went_unanswered(text: &str) -> bool {
    text.contains("went unanswered")
}

/// What follows an error chain in which a call went unanswered: the call may
/// have taken effect all the same.
const UNANSWERED: &str = ". A call went unanswered: if it was creating a canister, that canister \
                          may exist without being listed, so check before deploying again";

/// What follows a deploy's error when a call creating a canister ended
/// without a verdict, unanswered or failed after it was sent.
const UNCERTAIN_CREATION: &str = ". A call creating a canister ended without a verdict: that \
                                  canister may exist without being listed, so check before \
                                  deploying again";

/// `error`, a deploy's, with the warning a creation that ended without a
/// verdict calls for, when one did and the error does not carry a warning
/// of the kind already. The error is the run's first failure: canisters are
/// created at once, and a second creation that timed out is not in it.
fn warned_of_creation(error: String, uncertain_creation: bool) -> String {
    let warned = error.contains(UNANSWERED) || error.contains(UNCERTAIN_CREATION);
    match uncertain_creation && !warned {
        true => format!("{error}{UNCERTAIN_CREATION}"),
        false => error,
    }
}

/// What a deploy that failed says of itself when its run ended in `ended`
/// (an error chain): the chain, and the warning it calls for when a call
/// went unanswered — a timeout or a dropped connection after the call was
/// sent says nothing of whether it took effect.
fn failed_with(ended: &str) -> String {
    match went_unanswered(ended) {
        true => format!("{ended}{UNANSWERED}"),
        false => ended.to_string(),
    }
}

/// Run a deploy until it ends or `stop` is cancelled, and say how it ended;
/// `None` is a run that was dropped.
///
/// A stop does not drop a run that has made a call (`begun`, which
/// [`UntilStopped`] sets): a call in flight may already have created a
/// canister, and only the run going on to its answer records which. The
/// calls refuse to begin another once stopped, so the run ends by itself
/// within a step; it is given `grace` to, and dropped after that, so that a
/// call that is never answered cannot hold a stopping server. A run that has
/// made no call has nothing to lose, and is dropped at once. `biased` so
/// that a stop asked for before the run begins is honoured without a step.
async fn run_until_stopped<T>(
    run: impl Future<Output = T>,
    stop: &CancellationToken,
    begun: &AtomicBool,
    grace: Duration,
) -> Option<T> {
    tokio::pin!(run);
    tokio::select! {
        biased;
        _ = stop.cancelled() => {}
        result = &mut run => return Some(result),
    }
    if !begun.load(Ordering::SeqCst) {
        return None;
    }
    tokio::time::timeout(grace, run).await.ok()
}

/// The mapping a deploy hands back, which is what a retry passes in: what
/// the id store holds — or, when it could not be read back, the ids the
/// caller seeded it with — and over that every canister this run created.
/// A created id is reported before it is recorded, so the created list is
/// the authority: it fills in whatever the store failed to record or to
/// read back, because a mapping missing a canister that exists would have
/// the retry create, and fund, a second one.
fn ids_for_a_retry(
    seeded: BTreeMap<String, Principal>,
    stored: Option<BTreeMap<String, Principal>>,
    created: &[(String, Principal)],
) -> BTreeMap<String, Principal> {
    let mut ids = stored.unwrap_or(seeded);
    ids.extend(created.iter().cloned());
    ids
}

/// Send one log line where the deploy's lines go: the server's log, under
/// the caller's span, and the watcher, if there is one and it still listens.
fn forward(lines: &Option<mpsc::UnboundedSender<String>>, line: &str) {
    tracing::info!("{line}");
    if let Some(lines) = lines {
        let _ = lines.send(line.to_string());
    }
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

/// A bundle on its way into a deploy's directory: an archive still to be
/// extracted, or a directory one already was extracted into.
enum Bundle {
    Archive(Box<dyn std::io::Read + Send>),
    Extracted { dir: Utf8PathBuf, bytes: u64 },
}

/// Open the archive at `path` for reading, if it is one this deploy may
/// read: an absolute path to a regular file of at most `limit` bytes, and
/// nothing else. A device or a pipe reports a length that says nothing
/// about what a read of it produces (`/dev/zero` is 0 bytes long and
/// endless; a FIFO blocks on open), so the path is checked before it is
/// opened and a pipe never is. The file is looked at again once open — what
/// a path names can change between the two — and the size is a first
/// refusal only: the extraction counts what it reads, so a file that grows
/// is still held to the limit.
async fn open_bundle_file(path: &Utf8Path, limit: u64) -> Result<std::fs::File, RequestError> {
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
    if meta.len() > limit {
        return Err(too_large(meta.len()));
    }
    let file = tokio::fs::File::open(path.as_std_path()).await.map_err(cannot)?;
    let meta = file.metadata().await.map_err(cannot)?;
    if !meta.is_file() {
        return Err(not_regular());
    }
    if meta.len() > limit {
        return Err(too_large(meta.len()));
    }
    Ok(file.into_std().await)
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
        forward(&lines, &line);
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

/// What every deploy directory's name starts with.
const DEPLOY_DIR_PREFIX: &str = "imcp2-deploy-";

/// The path, inside a deploy directory, of the record a cut-off deploy
/// leaves: the id mappings, one file per environment.
const RECORD_PATH: [&str; 3] = [".icp", "data", "mappings"];

/// Whether a deploy's directory stays, cut down to its record, as the
/// deploy returns: after an interruption, and after any run that created a
/// canister, whose ids the caller may never receive (see
/// [`DeployRequest::workdir`]).
fn keeps_its_record(interrupted: bool, created: &[(String, Principal)]) -> bool {
    interrupted || !created.is_empty()
}

/// Write `ids` as the id store's mapping for `environment` on a connected
/// network, under the project root `dir`: the file the store's register
/// writes one entry at a time, written once.
fn seed_ids(
    dir: &Utf8Path,
    environment: &str,
    ids: &BTreeMap<String, Principal>,
) -> Result<(), String> {
    let mappings = RECORD_PATH.iter().fold(dir.to_path_buf(), |path, part| path.join(part));
    std::fs::create_dir_all(&mappings).map_err(|e| e.to_string())?;
    let file = mappings.join(format!("{environment}.ids.json"));
    icp_project::fs::json::save(&file, ids).map_err(|e| e.to_string())
}

/// Bring a deploy's record up to `ids`, the mapping its answer carries, when
/// what the store holds (`stored`; `None` when it could not be read) is not
/// that already, and say whether it had to be written.
fn complete_record(
    dir: &Utf8Path,
    environment: &str,
    stored: Option<BTreeMap<String, Principal>>,
    ids: &BTreeMap<String, Principal>,
) -> Result<bool, String> {
    if stored.as_ref() == Some(ids) {
        return Ok(false);
    }
    seed_ids(dir, environment, ids).map(|()| true)
}

/// Cut a deploy directory down to its record: everything goes but
/// `.icp/data/mappings`, the ids the deploy created. The bundle's files, the
/// build scratch and the artifact store are most of a directory and none of
/// what a retry needs.
///
/// Each part of the record's path is gone into only as a directory of the
/// deploy's own. One that is a link (a directory somebody else made, under a
/// parent others can write to, may hold one) is removed like anything else
/// that is not the record: followed, it would have what it points at emptied.
fn prune_to_record(workdir: &std::path::Path) -> std::io::Result<()> {
    let mut dir = workdir.to_path_buf();
    for keep in RECORD_PATH {
        for entry in std::fs::read_dir(&dir)?.flatten() {
            // A link is removed, never followed: its type is its own.
            let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
            if is_dir && entry.file_name() == keep {
                continue;
            }
            let path = entry.path();
            if is_dir {
                std::fs::remove_dir_all(&path)?;
            } else {
                std::fs::remove_file(&path)?;
            }
        }
        dir.push(keep);
        if !std::fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir()) {
            break;
        }
    }
    Ok(())
}

/// The deploy directories under `parent`: those [`deploy_directory`] named.
fn deploy_directories(parent: &std::path::Path) -> Vec<std::path::PathBuf> {
    let Ok(entries) = std::fs::read_dir(parent) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| e.file_name().to_str().is_some_and(|n| n.starts_with(DEPLOY_DIR_PREFIX)))
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.path())
        .collect()
}

/// Cut every deploy directory under `parent` down to its record (see
/// [`DeployRequest::workdir`]), and say how many there were. For a server to
/// call as it starts, before it runs a deploy: each directory there then is
/// one a deploy was cut off in when an earlier process stopped, still
/// holding its whole bundle. Not for a server with a deploy running, whose
/// directory it would empty.
pub fn prune_abandoned_deploys(parent: &std::path::Path) -> usize {
    let dirs = deploy_directories(parent);
    for dir in &dirs {
        if let Err(e) = prune_to_record(dir) {
            tracing::warn!(dir = %dir.display(), %e, "could not cut the directory down");
        }
    }
    dirs.len()
}

/// Remove the deploy directories under `parent` last changed more than
/// `older_than` ago, and say how many went: a record nobody came for. Safe
/// beside running deploys so long as `older_than` is longer than a deploy
/// lasts, as days are.
pub fn remove_old_deploy_records(
    parent: &std::path::Path,
    older_than: std::time::Duration,
) -> usize {
    let old = |dir: &std::path::PathBuf| {
        std::fs::metadata(dir)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|at| at.elapsed().ok())
            .is_some_and(|age| age > older_than)
    };
    deploy_directories(parent)
        .into_iter()
        .filter(old)
        .filter(|dir| std::fs::remove_dir_all(dir).is_ok())
        .count()
}

/// A fresh directory for one deploy under `parent`, randomly named, and on
/// Unix readable by its owner alone: the bundle's files and the ids the
/// deploy records are the user's business, and the parent (the user's local
/// data directory, or the system temporary directory) may be more open.
fn deploy_directory(parent: &std::path::Path) -> std::io::Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(DEPLOY_DIR_PREFIX);
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
            limits: BundleLimits::LOCAL,
            plugins: AllowedPlugins::Any,
            plugin_limits: PluginLimits::default(),
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

    // A file over the archive limit is refused by its size, unopened; one
    // that grows past it after the check is stopped by the extraction, which
    // counts what it reads (`host`'s tests).
    #[tokio::test]
    async fn a_bundle_file_over_the_limit_is_refused_by_its_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = Utf8PathBuf::from_path_buf(dir.path().join("b.tar.gz")).unwrap();
        std::fs::write(&path, [7u8; 32]).unwrap();
        assert_eq!(open_bundle_file(&path, 32).await.unwrap().metadata().unwrap().len(), 32);
        let err = open_bundle_file(&path, 16).await.unwrap_err();
        assert!(err.0.contains("above the 16 byte limit"), "{}", err.0);
        let err = open_bundle_file(Utf8Path::new("relative/b.tar.gz"), 32).await.unwrap_err();
        assert!(err.0.contains("absolute"), "{}", err.0);
        let err = open_bundle_file(&path.with_file_name("missing"), 32).await.unwrap_err();
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

    // An uploaded bundle reaches its deploy already extracted: the store
    // extracted it as it arrived, and the deploy takes that directory for
    // its own — moved, not copied or extracted again — and runs from it as
    // from one it extracted itself. The room the store holds for the deploy
    // is given back when the deploy has returned.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_uploaded_bundle_is_deployed_from_where_it_was_extracted() {
        let (wasm, sha) = wasm();
        let state = tempfile::tempdir().unwrap();
        let limits = BundleLimits::new(1 << 20, 1 << 20);
        let uploads = crate::deploy::Uploads::new(state.path().join("deploys/uploads"), limits);
        let ticket = uploads.mint("s").await.ticket;
        let archive = std::io::Cursor::new(bundle(&sha, &wasm));
        let received = uploads.receive(&ticket, None, archive).await.unwrap();
        let taken = uploads.take(&received.upload_id, "s").await.unwrap();
        let uploaded = taken.dir().to_path_buf();
        assert!(uploaded.join("canisters/backend.wasm").is_file());
        assert_eq!(uploads.held().bytes, 1 << 20, "a running deploy holds the limit");

        let mut request = request(Vec::new(), "ic");
        request.bundle = BundleSource::Extracted {
            dir: Utf8PathBuf::from_path_buf(uploaded.clone()).unwrap(),
            bytes: taken.bytes(),
        };
        request.limits = limits;
        let workdirs = state.path().join("deploys");
        request.workdir = Some(Utf8PathBuf::from_path_buf(workdirs.clone()).unwrap());
        let outcome = deploy_bundle(Arc::new(AnonymousIdentity), request, Watch::default())
            .await
            .expect("the request is valid");
        // As far as a deploy gets offline: built from the bundle, then
        // stopped where `no_create` stops it.
        assert_eq!(outcome.status, Status::Failed);
        assert!(outcome.log.iter().any(|l| l == "Building canisters: ok"), "{:?}", outcome.log);
        assert!(!uploaded.exists(), "the bundle was moved into the deploy's directory");
        // The deploy's directory went with the deploy; the store's stays.
        let left: Vec<_> = std::fs::read_dir(&workdirs)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, ["uploads"]);
        drop(taken);
        assert_eq!(uploads.held().bytes, 0);
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

    // The server's log has every line the deploy makes, under the span the
    // caller runs it in — the collector is a task of its own, so the span
    // has to be carried to it on purpose.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_log_is_written_to_the_server_log_under_the_callers_span() {
        let sink = server_log();

        let (wasm, sha) = wasm();
        let span = tracing::info_span!("deploy", session = "sess-1");
        let outcome = deploy_bundle(
            Arc::new(AnonymousIdentity),
            request(bundle(&sha, &wasm), "ic"),
            Watch::default(),
        )
        .instrument(span)
        .await
        .unwrap();
        assert_eq!(outcome.status, Status::Failed);
        let written = String::from_utf8(sink.written.lock().unwrap().clone()).unwrap();
        // Other tests' deploys write to the sink too; this one's lines are
        // the ones under its span.
        let own: Vec<&str> =
            written.lines().filter(|l| l.contains("deploy{session=\"sess-1\"}")).collect();
        let has = |needle: &str| own.iter().any(|l| l.contains(needle));
        assert!(has("deploy started"), "{own:?}");
        assert!(has("Building canisters: ok"), "{own:?}");
        assert!(has("deploy did not finish") && has("status=\"failed\""), "{own:?}");
    }

    // A stop asked for before the deploy begins costs nothing: the bundle
    // is not extracted, no directory is made, and the refusal says nothing
    // was created.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_deploy_stopped_before_it_begins_reads_nothing() {
        let (wasm, sha) = wasm();
        let parent = tempfile::tempdir().unwrap();
        let mut request = request(bundle(&sha, &wasm), "ic");
        request.workdir = Some(Utf8PathBuf::from_path_buf(parent.path().to_path_buf()).unwrap());
        let stop = CancellationToken::new();
        stop.cancel();
        let watch = Watch { stop, lines: None };
        let refused = deploy_bundle(Arc::new(AnonymousIdentity), request, watch).await.unwrap_err();
        assert!(refused.0.contains("interrupted before it began"), "{refused}");
        assert!(refused.0.contains("nothing was created"), "{refused}");
        // A stop, which a server counts apart from a bundle it refused.
        assert!(refused.was_interrupted());
        assert!(!RequestError("no such environment".into()).was_interrupted());
        // And a failure of the server's own is told from both.
        let fault = RequestError::server_fault("cannot create a scratch directory: no space");
        assert!(fault.is_server_fault() && !fault.was_interrupted());
        assert!(fault.0.contains("try again later") && fault.0.contains("no space"), "{fault}");
        assert!(!refused.is_server_fault());
        assert!(!RequestError("no such environment".into()).is_server_fault());
        assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0, "no directory is made");
    }

    // A stop asked for once the checks have passed ends the run without a
    // step, and the directory stays behind as the record, since whoever
    // asked may never read the answer — cut down to the record: the bundle's
    // files go.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_interrupted_deploy_stops_and_keeps_its_record() {
        let (wasm, sha) = wasm();
        let parent = tempfile::tempdir().unwrap();
        let mut request = request(bundle(&sha, &wasm), "ic");
        request.workdir = Some(Utf8PathBuf::from_path_buf(parent.path().to_path_buf()).unwrap());
        // Stopped at the moment the deploy says it has started: the checks
        // are behind it and no step has begun. The server log is where it
        // says so, and the log's writer runs inside the very poll that goes
        // on to the first step, so the stop is in place before that step.
        let stop = CancellationToken::new();
        server_log().stop_when_started("to-interrupt", stop.clone());
        let (tx, mut rx) = mpsc::unbounded_channel();
        let watch = Watch { stop: stop.clone(), lines: Some(tx) };
        let outcome = deploy_bundle(Arc::new(AnonymousIdentity), request, watch)
            .instrument(tracing::info_span!("deploy", session = "to-interrupt"))
            .await
            .unwrap();
        assert!(stop.is_cancelled(), "the deploy got as far as starting");
        assert_eq!(outcome.status, Status::Interrupted);
        assert_eq!(outcome.canisters, ["backend"]);
        assert!(outcome.created.is_empty());
        let error = outcome.error.as_deref().unwrap();
        assert!(error.contains("interrupted"), "{error}");
        assert!(!outcome.log.iter().any(|l| l.starts_with("Building")), "{:?}", outcome.log);
        let kept: Vec<_> = std::fs::read_dir(parent.path()).unwrap().flatten().collect();
        assert_eq!(kept.len(), 1, "the deploy directory is kept");
        assert!(outcome.log.last().unwrap().contains("is kept"), "{:?}", outcome.log);
        // Cut down to the record: the manifest and the wasm are gone.
        let left: Vec<_> = std::fs::read_dir(kept[0].path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(left.iter().all(|name| name == ".icp"), "{left:?}");
        // The watcher is told where the record is, not the outcome's reader
        // alone: it may be the only one still there.
        let mut streamed = Vec::new();
        while let Some(line) = rx.recv().await {
            streamed.push(line);
        }
        assert_eq!(streamed, outcome.log);
    }

    // What a stop does to a run depends on whether the run has made a call.
    // One that has made none has nothing to lose and is dropped where it is;
    // one that has is let run on to its end — its calls now refuse to begin,
    // so that is soon — for the answer of a call in flight to be recorded;
    // and one that still has not ended after the grace is dropped after all.
    #[tokio::test]
    async fn a_stop_waits_for_a_run_that_has_made_a_call_and_not_for_ever() {
        let grace = Duration::from_millis(200);
        let ends_soon = || async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            "recorded"
        };
        let stop = CancellationToken::new();
        stop.cancel();

        let begun = AtomicBool::new(false);
        assert_eq!(run_until_stopped(ends_soon(), &stop, &begun, grace).await, None);

        let begun = AtomicBool::new(true);
        assert_eq!(run_until_stopped(ends_soon(), &stop, &begun, grace).await, Some("recorded"));

        let started = std::time::Instant::now();
        let never = std::future::pending::<&str>();
        assert_eq!(run_until_stopped(never, &stop, &begun, grace).await, None);
        assert!(started.elapsed() >= grace);

        // Not stopped, a run simply runs.
        let running = CancellationToken::new();
        assert_eq!(run_until_stopped(ends_soon(), &running, &begun, grace).await, Some("recorded"));
    }

    // An interrupted deploy's answer does not claim more than is known. The
    // refusal of the call the stop prevented is only the interruption; an
    // error a call in flight came back with is passed on, and one that went
    // unanswered comes with the warning that its canister may exist.
    #[test]
    fn an_interrupted_deploy_says_what_its_run_ended_with() {
        let base = "interrupted";
        let refused = format!("call to 'x' on aaaaa-aa failed: {}", crate::deploy::calls::STOPPING);
        assert_eq!(interrupted_with(base, &refused), base);
        let rejected = interrupted_with(base, "call to 'x' on aaaaa-aa was rejected: no");
        assert!(rejected.contains("The run ended with: call to 'x'"), "{rejected}");
        assert!(!rejected.contains("may exist"), "{rejected}");
        let unanswered = "call to 'create_canister' on aaaaa-aa went unanswered: timed out";
        for ended in [unanswered.to_string(), format!("{unanswered}; then: {refused}")] {
            let said = interrupted_with(base, &ended);
            assert!(said.contains("went unanswered"), "{said}");
            assert!(said.contains("may exist without being listed"), "{said}");
        }
    }

    // A creation that ended without a verdict beside the failure the error
    // is of is said too, once: the error is the first failure alone, and the
    // warning is what keeps the caller from creating that canister a second
    // time. An error that already warns of an unanswered call is left as it
    // is.
    #[test]
    fn a_creation_without_a_verdict_beside_the_first_failure_is_warned_of() {
        let refused = "failed to create canister: Insufficient cycles.".to_string();
        assert_eq!(warned_of_creation(refused.clone(), false), refused);
        let warned = warned_of_creation(refused.clone(), true);
        assert!(warned.starts_with(&refused), "{warned}");
        assert!(warned.contains("may exist without being listed"), "{warned}");
        assert!(warned.contains("check before deploying again"), "{warned}");
        assert_eq!(warned_of_creation(warned.clone(), true), warned, "said once");
        let unanswered = failed_with("call to 'create_canister' on aaaaa-aa went unanswered");
        assert_eq!(warned_of_creation(unanswered.clone(), true), unanswered, "said already");
    }

    // A deploy that failed with a call unanswered was not stopped, and its
    // caller will try again: it is told that the call may have taken effect.
    // Any other failure is the error chain and nothing more.
    #[test]
    fn a_failed_deploy_warns_of_a_call_that_went_unanswered() {
        let rejected = "call to 'install_code' on aaaaa-aa was rejected: no";
        assert_eq!(failed_with(rejected), rejected);
        let unanswered = "call to 'create_canister' on aaaaa-aa went unanswered: timed out";
        let said = failed_with(unanswered);
        assert!(said.starts_with(unanswered), "{said}");
        assert!(said.contains("may exist without being listed"), "{said}");
    }

    // The record a deploy leaves is the mapping its answer carries: where
    // the store recorded less (a write of its own failed) or could not be
    // read back, the record is written up to it, and left alone otherwise.
    #[test]
    fn the_record_is_brought_up_to_the_mapping_the_answer_carries() {
        let dir = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        let file = dir.path().join(".icp/data/mappings/ic.ids.json");
        let read = || -> BTreeMap<String, Principal> {
            serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap()
        };
        let seeded: BTreeMap<String, Principal> =
            [("backend".to_string(), Principal::from_slice(&[1, 1, 1]))].into();
        let mut all = seeded.clone();
        all.insert("frontend".to_string(), Principal::from_slice(&[2, 1, 1]));
        seed_ids(&root, "ic", &seeded).unwrap();

        assert_eq!(complete_record(&root, "ic", Some(seeded.clone()), &seeded), Ok(false));
        assert_eq!(complete_record(&root, "ic", Some(seeded.clone()), &all), Ok(true));
        assert_eq!(read(), all);
        // Not read back: written, whatever it held.
        seed_ids(&root, "ic", &seeded).unwrap();
        assert_eq!(complete_record(&root, "ic", None, &all), Ok(true));
        assert_eq!(read(), all);
    }

    // A run that created a canister keeps its record however it ended: its
    // answer, the one other place the ids are, may never reach the caller.
    #[test]
    fn a_run_that_created_a_canister_keeps_its_record() {
        let created = [("backend".to_string(), Principal::management_canister())];
        assert!(keeps_its_record(false, &created), "finished, or failed, having created one");
        assert!(keeps_its_record(true, &created));
        assert!(keeps_its_record(true, &[]), "interrupted: a call may have created one");
        assert!(!keeps_its_record(false, &[]), "nothing created, nothing to keep");
    }

    // The mapping a caller passes is written once, as the file the id store
    // reads: the store itself, looking at the project root, finds every id.
    #[test]
    fn the_seeded_mapping_is_the_one_the_id_store_reads() {
        use icp_project::{
            manifest::{ProjectRootLocate, ProjectRootLocateError},
            store_id::{Access, AccessImpl},
        };
        struct Root(Utf8PathBuf);
        impl ProjectRootLocate for Root {
            fn locate(&self) -> Result<Utf8PathBuf, ProjectRootLocateError> {
                Ok(self.0.clone())
            }
            fn locate_member(&self) -> Result<Utf8PathBuf, ProjectRootLocateError> {
                Ok(self.0.clone())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        let ids: BTreeMap<String, Principal> = (0..50u8)
            .map(|n| (format!("canister-{n}"), Principal::from_slice(&[n, 1, 1])))
            .collect();
        seed_ids(&root, "ic", &ids).unwrap();
        let store = AccessImpl::new(Arc::new(Root(root)));
        // Connected, the IC: the data store, not the cache.
        assert_eq!(store.lookup_by_environment(false, "ic").unwrap(), ids);
    }

    #[test]
    fn the_mapping_for_a_retry_holds_every_created_canister() {
        let id = |n: u8| Principal::from_slice(&[n]);
        let map = |ids: &[(&str, u8)]| -> BTreeMap<String, Principal> {
            ids.iter().map(|(name, n)| (name.to_string(), id(*n))).collect()
        };
        let seeded = map(&[("backend", 1)]);
        let created = [("frontend".to_string(), id(2)), ("worker".to_string(), id(3))];

        // The store recorded one creation and missed the other.
        let partial = map(&[("backend", 1), ("frontend", 2)]);
        assert_eq!(
            ids_for_a_retry(seeded.clone(), Some(partial), &created),
            map(&[("backend", 1), ("frontend", 2), ("worker", 3)])
        );
        // The store could not be read back: the seeded ids stand, with the
        // created ones over them.
        assert_eq!(
            ids_for_a_retry(seeded.clone(), None, &created),
            map(&[("backend", 1), ("frontend", 2), ("worker", 3)])
        );
        // Nothing created: the store's word, or the seed's.
        assert_eq!(ids_for_a_retry(seeded.clone(), Some(map(&[("backend", 1)])), &[]), seeded);
        assert_eq!(ids_for_a_retry(seeded.clone(), None, &[]), seeded);
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

    /// The server log, captured: everything the test binary's deploys write,
    /// and a way to stop one deploy the moment it logs that it has started.
    #[derive(Clone, Default)]
    struct ServerLog {
        written: Arc<std::sync::Mutex<Vec<u8>>>,
        /// A session to look for, and the token to cancel when the deploy
        /// under that session's span says "deploy started".
        stops: Arc<std::sync::Mutex<Vec<(String, CancellationToken)>>>,
    }

    impl ServerLog {
        fn stop_when_started(&self, session: &str, stop: CancellationToken) {
            self.stops.lock().unwrap().push((format!("session=\"{session}\""), stop));
        }
    }

    impl std::io::Write for ServerLog {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.lock().unwrap().extend_from_slice(buf);
            let line = String::from_utf8_lossy(buf);
            if line.contains("deploy started") {
                for (session, stop) in self.stops.lock().unwrap().iter() {
                    if line.contains(session.as_str()) {
                        stop.cancel();
                    }
                }
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for ServerLog {
        type Writer = ServerLog;
        fn make_writer(&'a self) -> ServerLog {
            self.clone()
        }
    }

    /// The one subscriber of the test binary, installed on first use.
    /// Process-wide: a deploy's collector runs on another worker thread,
    /// which a thread-local default would not reach — and a callsite first
    /// hit on a thread without that default would be cached as uninteresting
    /// for every thread. What other tests write goes to it too, unread.
    fn server_log() -> ServerLog {
        static LOG: std::sync::OnceLock<ServerLog> = std::sync::OnceLock::new();
        LOG.get_or_init(|| {
            let log = ServerLog::default();
            let subscriber =
                tracing_subscriber::fmt().with_ansi(false).with_writer(log.clone()).finish();
            tracing::subscriber::set_global_default(subscriber).expect("one global subscriber");
            log
        })
        .clone()
    }

    /// A directory as a deploy leaves it mid-run: the bundle, the artifact
    /// store, and the ids it had recorded.
    fn a_deploy_directory(parent: &std::path::Path) -> std::path::PathBuf {
        let dir = deploy_directory(parent).unwrap().keep();
        for (path, contents) in [
            ("icp.yaml", "canisters: []"),
            ("canisters/backend.wasm", "wasm"),
            (".icp/cache/artifacts/backend", "artifact"),
            (".icp/data/other/thing", "other"),
            (".icp/data/mappings/ic.ids.json", "{\"backend\": \"aaaaa-aa\"}"),
        ] {
            let path = dir.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, contents).unwrap();
        }
        dir
    }

    fn files_under(dir: &std::path::Path) -> Vec<String> {
        let mut found = Vec::new();
        let mut pending = vec![dir.to_path_buf()];
        while let Some(at) = pending.pop() {
            for entry in std::fs::read_dir(&at).unwrap().flatten() {
                if entry.file_type().unwrap().is_dir() {
                    pending.push(entry.path());
                } else {
                    let relative = entry.path().strip_prefix(dir).unwrap().to_path_buf();
                    found.push(relative.to_string_lossy().into_owned());
                }
            }
        }
        found.sort();
        found
    }

    // What a server does as it starts: every directory a deploy was cut off
    // in keeps the ids it recorded and nothing else, and what is not a
    // deploy's directory is left alone.
    #[test]
    fn an_abandoned_deploy_directory_is_cut_down_to_its_record() {
        let parent = tempfile::tempdir().unwrap();
        let cut_off = a_deploy_directory(parent.path());
        // One that had recorded nothing yet.
        let empty = deploy_directory(parent.path()).unwrap().keep();
        std::fs::write(empty.join("icp.yaml"), "canisters: []").unwrap();
        std::fs::create_dir(parent.path().join("uploads")).unwrap();
        std::fs::write(parent.path().join("uploads/x.tar.gz"), "upload").unwrap();

        assert_eq!(prune_abandoned_deploys(parent.path()), 2);
        assert_eq!(files_under(&cut_off), [".icp/data/mappings/ic.ids.json"]);
        assert!(files_under(&empty).is_empty());
        assert_eq!(files_under(&parent.path().join("uploads")), ["x.tar.gz"]);
        // Again changes nothing.
        assert_eq!(prune_abandoned_deploys(parent.path()), 2);
        assert_eq!(files_under(&cut_off), [".icp/data/mappings/ic.ids.json"]);
    }

    // A part of the record's path that is a link is not gone into: what it
    // points at is somebody else's, and stays as it was. The link goes, like
    // anything in a deploy directory that is not the record.
    #[cfg(unix)]
    #[test]
    fn pruning_removes_a_link_where_the_record_would_be_and_never_follows_it() {
        let parent = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        // The link at each depth of the record's path, to a directory with
        // a file at every level pruning would empty if it went in.
        for depth in 0..RECORD_PATH.len() {
            let dir = deploy_directory(parent.path()).unwrap().keep();
            let (own, linked) = RECORD_PATH.split_at(depth);
            let at = own.iter().fold(dir.clone(), |path, part| path.join(part));
            std::fs::create_dir_all(&at).unwrap();
            let target = elsewhere.path().join(format!("depth-{depth}"));
            let mut level = target.clone();
            for part in linked {
                std::fs::create_dir_all(&level).unwrap();
                std::fs::write(level.join("not-the-deploys"), "kept").unwrap();
                level.push(part);
            }
            let untouched = files_under(elsewhere.path());
            std::os::unix::fs::symlink(&target, at.join(linked[0])).unwrap();

            prune_to_record(&dir).unwrap();
            assert!(std::fs::symlink_metadata(at.join(linked[0])).is_err(), "depth {depth}");
            assert_eq!(files_under(elsewhere.path()), untouched, "depth {depth}");
        }
    }

    // A record nobody came for goes once it is old; a recent one, and
    // anything that is not a deploy's directory, stays.
    #[test]
    fn an_old_deploy_record_is_removed_and_a_recent_one_kept() {
        let parent = tempfile::tempdir().unwrap();
        let dir = a_deploy_directory(parent.path());
        std::fs::create_dir(parent.path().join("uploads")).unwrap();
        let day = std::time::Duration::from_secs(24 * 60 * 60);
        assert_eq!(remove_old_deploy_records(parent.path(), day), 0);
        assert!(dir.is_dir());
        assert_eq!(remove_old_deploy_records(parent.path(), std::time::Duration::ZERO), 1);
        assert!(!dir.exists());
        assert!(parent.path().join("uploads").is_dir());
    }
}
