//! Bundles uploaded ahead of a deploy, for a server the agent cannot hand a
//! file to.
//!
//! An MCP tool call carries JSON the model writes, and a model cannot write
//! an archive, so a server on another machine than the agent's needs the
//! bytes to arrive some other way. This is that way: `icp_deploy_upload`
//! mints a ticket inside an authenticated tool call, the agent presents it on
//! an ordinary `PUT` of the archive (the one thing the ticket is good for),
//! and the upload id that `PUT` answers with is what `icp_deploy_bundle`
//! takes as `bundle_upload`. The ticket derives its authority from the bearer
//! token presented on the tool call — the same chain of trust as any tool
//! call — scoped down to one `PUT`:
//!
//!   * 256 bits of randomness, single use (taken before a byte of the body
//!     is read), and gone after [`TICKET_TTL`];
//!   * one pending ticket per session — minting another drops the previous;
//!   * bound to the session that minted it: the upload it produces is
//!     deployable by that session alone, so an id leaking elsewhere is useless;
//!   * a declared length over the archive limit is refused unread, so a
//!     ticket flood costs a lookup each.
//!
//! **The archive is extracted as it arrives, and never kept.** The body is
//! fed to the bundle extractor ([`crate::deploy::host::extract_bundle_from`]) a
//! chunk at a time, on a thread of its own, and what the store holds for the
//! deploy is the extracted bundle: a directory of its own under the store's,
//! readable by the server's user alone. So the archive is nowhere whole —
//! not in memory, not on disk — and both of its sizes are held while it is
//! still arriving: the compressed bytes read, and what they have inflated to
//! ([`BundleLimits`]). The byte that passes either stops the read, and the
//! request is answered then, with whatever had been written removed. An
//! archive that is not a bundle is refused here too, before any deploy is
//! asked for, and so is a bundle that carries a sync plugin the server does
//! not run ([`AllowedPlugins`]): the project is loaded once it has arrived,
//! and each plugin it names held to the list by the hash of its module.
//!
//! An upload is held for [`UPLOAD_TTL`] for its deploy to begin; the deploy
//! that takes it takes the directory for its own (a rename, nothing copied),
//! and one never taken is swept at expiry.
//!
//! What the store may hold is bounded, whatever a session does with its
//! tickets. The bound is on extracted bytes, since those are what the
//! server keeps — in memory, where its state directory is a RAM filesystem:
//!
//!   * a session has one upload at a time: a `PUT` while another of the
//!     session's is still arriving is refused, and one that is let in
//!     replaces the bundle the session was holding;
//!   * every bundle counts against one budget for the whole store. One that
//!     is arriving is charged the most it may extract to
//!     ([`BundleLimits::extracted_bytes`]), reserved before a byte of the
//!     body is read: its size is not known until it has all arrived. One
//!     that is waiting is charged what it did extract to. And one with its
//!     deploy is charged the limit again, for as long as the deploy runs:
//!     the deploy's directory grows beyond the bundle (the copy of each
//!     canister's module the build keeps), and the limit is what
//!     [`crate::deploy::host::check_bundle`] holds that directory to. Past the
//!     budget a `PUT` is refused, and so is a deploy that would have to grow
//!     into room that is not there;
//!   * a body that stops arriving ([`UPLOAD_IDLE`]) or takes too long in all
//!     ([`UPLOAD_TIME`]) is given up on, and a `PUT` that fails or is
//!     abandoned leaves nothing: the partial bundle goes with it, and its
//!     reservation;
//!   * the directory is the store's own: what an earlier process left in it
//!     is removed when the store is made, since nothing could deploy it. One
//!     that was there already is made the server's user's alone like one the
//!     store makes, and refused if it cannot be: under a directory another
//!     user can write to, a bundle could be swapped for another tree between
//!     its upload and its deploy.
//!
//! A bundle that lapses or is replaced is removed off the lock the store's
//! state is under, on a thread that may block: removing a tree is as slow as
//! the tree is large, and every session's calls wait on that lock. Its bytes
//! stay charged until it is gone, so the budget is of what is on disk, not of
//! what is still meant to be. An arrival or a deploy that finds a lapsed
//! bundle counts it as room and sees it gone before it writes; one that
//! comes while another call's removal is still running may be refused for
//! the moment that takes.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use camino::Utf8PathBuf;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_util::sync::CancellationToken;

use crate::deploy::host::{self, AllowedPlugins, BundleLimits, ExtractError, VetError};

/// The default cap on an uploaded archive, compressed, in bytes: a real
/// bundle is a manifest, a few modules and a frontend's assets, well inside
/// this.
pub const DEFAULT_MAX_UPLOAD_BYTES: usize = 64 * 1024 * 1024;
/// The default cap on what an uploaded bundle extracts to, and on what its
/// deploy's directory comes to, in bytes.
pub const DEFAULT_MAX_EXTRACTED_BYTES: usize = 128 * 1024 * 1024;
/// The default budget for every bundle a store has at once, as a multiple of
/// what one may extract to: a server sets its own from how many deploys it
/// runs at once (one arriving or waiting besides).
pub const DEFAULT_STORED_BUNDLES: usize = 3;
/// How long a ticket is good for: minutes, enough to run one `curl`.
pub const TICKET_TTL: Duration = Duration::from_secs(5 * 60);
/// How long an upload waits for its deploy to begin. Minutes: the deploy is
/// the agent's next call, and a waiting bundle is held in full.
pub const UPLOAD_TTL: Duration = Duration::from_secs(5 * 60);
/// How long a body may go without a byte arriving before it is given up on.
pub const UPLOAD_IDLE: Duration = Duration::from_secs(30);
/// How long a body may take to arrive in all: an upload holds its
/// reservation and a thread for as long as it lasts.
pub const UPLOAD_TIME: Duration = Duration::from_secs(10 * 60);
/// The request header a `PUT` presents its ticket in — a header rather than
/// the path, so the ticket stays out of a proxy's access log.
pub const TICKET_HEADER: &str = "x-deploy-upload-ticket";

/// The store: a directory of extracted bundles and the tickets and uploads
/// outstanding. Cheap to clone; one per directory, shared by every endpoint
/// of the process that receives into it.
#[derive(Clone)]
pub struct Uploads {
    inner: Arc<Inner>,
}

struct Inner {
    dir: PathBuf,
    limits: BundleLimits,
    /// The sync plugins a bundle may carry: the ones a server that deploys
    /// for others knows, unless [`Uploads::allowing`] says otherwise.
    plugins: std::sync::OnceLock<AllowedPlugins>,
    max_total_bytes: u64,
    /// [`UPLOAD_IDLE`] and [`UPLOAD_TIME`], which a test shortens.
    patience: (Duration, Duration),
    state: Mutex<State>,
    /// Whatever the server holds for as long as anything works in the
    /// directory (see [`Uploads::held_with`]): kept here, it lives as long as
    /// the store and every thread that extracts or removes a bundle for it.
    lease: std::sync::OnceLock<Arc<dyn std::any::Any + Send + Sync>>,
    /// Cancelled when the server begins to stop: see [`Uploads::stop`].
    stopping: CancellationToken,
}

impl Inner {
    /// The state, whatever a panic elsewhere left of the lock: every change
    /// to it is made whole before the lock is released.
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[derive(Default)]
struct State {
    tickets: HashMap<String, Ticket>,
    uploads: HashMap<String, Upload>,
    /// The sessions with a `PUT` arriving: one each.
    receiving: HashSet<String>,
    /// What counts against the budget: see the module docs.
    bytes: u64,
}

struct Ticket {
    session: String,
    expires: Instant,
}

struct Upload {
    session: String,
    dir: PathBuf,
    bytes: u64,
    expires: Instant,
}

/// A ticket just minted, and how long it is good for.
#[derive(Debug)]
pub struct Minted {
    pub ticket: String,
    pub expires_in: Duration,
}

/// A bundle just received: the id its deploy names, what it extracted to and
/// what its archive was, in bytes, and how long the store holds it.
#[derive(Debug)]
pub struct Received {
    pub upload_id: String,
    pub bytes: u64,
    pub archive_bytes: u64,
    pub expires_in: Duration,
}

/// Why a `PUT` was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum ReceiveError {
    /// No such ticket, or one already used or expired.
    UnknownTicket,
    /// The archive is over the cap on one, compressed (the value).
    TooLarge(u64),
    /// The archive extracts to more than a bundle may (the value).
    ExtractsTooLarge(u64),
    /// Another upload of the session's is still arriving.
    Busy,
    /// The store is holding as much as it may, across every session.
    Full,
    /// The body could not be read: the client's side of the transfer.
    Body(String),
    /// What arrived is not a bundle.
    NotABundle(String),
    /// The bundle carries a sync plugin this server does not run.
    PluginNotAllowed(String),
    /// The bundle could not be stored (the directory not made, a file not
    /// written): the server's fault, not the request's.
    Storage(String),
    /// The server is stopping: the upload was refused, or given up on as it
    /// arrived.
    Stopping,
}

impl std::fmt::Display for ReceiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiveError::UnknownTicket => f.write_str(
                "unknown, used or expired upload ticket; call icp_deploy_upload for a new one",
            ),
            ReceiveError::TooLarge(max) => write!(
                f,
                "the bundle archive is over the {max}-byte limit this server takes; make the \
                 bundle smaller"
            ),
            ReceiveError::ExtractsTooLarge(max) => write!(
                f,
                "the bundle extracts to more than the {max} bytes this server takes; make the \
                 bundle smaller (fewer or smaller assets, gzip-compressed modules)"
            ),
            ReceiveError::Busy => f.write_str(
                "another upload for this session is still arriving; wait for it to finish, \
                 then call icp_deploy_upload for a new ticket",
            ),
            ReceiveError::Full => f.write_str(
                "this server is holding as many uploaded bundles as it can right now; call \
                 icp_deploy_upload for a new ticket and try again in a few minutes",
            ),
            ReceiveError::Body(e) => write!(f, "could not read the archive: {e}"),
            ReceiveError::NotABundle(e) | ReceiveError::PluginNotAllowed(e) => f.write_str(e),
            ReceiveError::Storage(e) => write!(f, "could not store the bundle: {e}"),
            ReceiveError::Stopping => f.write_str(
                "this server is restarting; nothing was kept. Wait a minute, call \
                 icp_deploy_upload for a new ticket and upload again",
            ),
        }
    }
}

impl From<ExtractError> for ReceiveError {
    fn from(e: ExtractError) -> Self {
        match e {
            ExtractError::ArchiveTooLarge(max) => Self::TooLarge(max),
            ExtractError::ExtractsTooLarge(max) => Self::ExtractsTooLarge(max),
            ExtractError::Source(why) => Self::Body(why),
            ExtractError::NotABundle(why) => Self::NotABundle(why),
            ExtractError::Storage(why) => Self::Storage(why),
        }
    }
}

/// Why an upload was not handed to a deploy.
#[derive(Debug, PartialEq, Eq)]
pub enum TakeError {
    /// The session has no such upload: never made, expired, replaced, or
    /// deployed already.
    NoSuchUpload,
    /// The upload is there, and stays, but the store has no room for its
    /// deploy to run in.
    NoRoom,
}

/// An upload handed to its deploy: the bundle's directory, for the deploy to
/// take as its own, and its hold on the store's budget — the room a running
/// deploy is charged — released when this is dropped, whichever way the
/// deploy ends. A directory the deploy never took goes then too.
pub struct TakenUpload {
    dir: PathBuf,
    bytes: u64,
    charged: u64,
    store: Arc<Inner>,
}

impl TakenUpload {
    /// The directory the bundle was extracted into.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// What the bundle extracted to, in bytes.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl std::fmt::Debug for TakenUpload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TakenUpload").field("dir", &self.dir).finish_non_exhaustive()
    }
}

impl Drop for TakenUpload {
    fn drop(&mut self) {
        // Gone already when the deploy moved it in, which is the usual case.
        let _ = std::fs::remove_dir_all(&self.dir);
        let mut state = self.store.state();
        state.bytes = state.bytes.saturating_sub(self.charged);
    }
}

/// A bundle arriving: the session's one `PUT`, its directory and its
/// reservation. Dropped before [`Self::finish`] — the body failed, or was
/// given up on — it takes the partial bundle and the reservation with it.
/// It is owned by the thread that extracts, not by the request: a request
/// that is abandoned stops nothing by being dropped, and the extraction ends
/// when its body does.
struct Receiving {
    store: Arc<Inner>,
    session: String,
    dir: PathBuf,
    reserved: u64,
    finished: bool,
}

impl Receiving {
    /// The bundle arrived whole, `bytes` of it extracted: hold it for its
    /// deploy.
    fn finish(mut self, upload_id: &str, bytes: u64) {
        let mut state = self.store.state();
        state.receiving.remove(&self.session);
        state.bytes = state.bytes.saturating_sub(self.reserved) + bytes;
        state.uploads.insert(
            upload_id.to_string(),
            Upload {
                session: self.session.clone(),
                dir: self.dir.clone(),
                bytes,
                expires: Instant::now() + UPLOAD_TTL,
            },
        );
        self.finished = true;
    }
}

impl Drop for Receiving {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let _ = std::fs::remove_dir_all(&self.dir);
        let mut state = self.store.state();
        state.receiving.remove(&self.session);
        state.bytes = state.bytes.saturating_sub(self.reserved);
    }
}

/// A bundle the store has stopped holding — lapsed, or replaced — and has
/// yet to remove. Its bytes stay charged while its directory is there: the
/// drop removes the directory and then releases them. It takes the state's
/// lock to do so, and may take as long as the tree is large, so it is never
/// dropped under that lock, and where there is a choice, on a thread that
/// may block ([`clear`]).
struct Leaving {
    store: Arc<Inner>,
    dir: PathBuf,
    bytes: u64,
}

impl Drop for Leaving {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
        let mut state = self.store.state();
        state.bytes = state.bytes.saturating_sub(self.bytes);
    }
}

/// Remove `leaving` on a thread that may block, when there is a runtime to
/// lend one, and here when there is not.
fn clear(leaving: Vec<Leaving>) {
    if leaving.is_empty() {
        return;
    }
    match tokio::runtime::Handle::try_current() {
        Ok(runtime) => drop(runtime.spawn_blocking(move || drop(leaving))),
        Err(_) => drop(leaving),
    }
}

/// What an upload store holds at a moment; see [`Uploads::held`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Held {
    /// The bytes counted against the budget: see the module docs.
    pub bytes: u64,
    /// The budget.
    pub max_bytes: u64,
    /// The bundles waiting for their deploy.
    pub uploads: usize,
    /// The bundles arriving.
    pub receiving: usize,
}

impl Uploads {
    /// A store extracting its bundles under `dir`, each within `limits`, and
    /// [`DEFAULT_STORED_BUNDLES`] of the largest in all; see
    /// [`Self::with_budget`].
    pub fn new(dir: PathBuf, limits: BundleLimits) -> Self {
        let budget = limits.extracted_bytes.saturating_mul(DEFAULT_STORED_BUNDLES as u64);
        Self::with_budget(dir, limits, budget)
    }

    /// A store extracting its bundles under `dir` (made now, readable by the
    /// server's user alone), each within `limits`, and holding at most
    /// `max_total_bytes` of them in all, extracted (at least one bundle's
    /// worth). The directory is canonicalized: a relative `dir` is resolved
    /// against the working directory here, so the path of a received bundle
    /// is absolute, as the deploy that takes it requires. Should the
    /// directory not be makable now, it is tried again at each upload, which
    /// reports the failure.
    ///
    /// The directory is this store's alone, one store per process: bundles
    /// already in it were received by a process that has gone, with the
    /// tickets and sessions they belonged to, so they are removed here.
    pub fn with_budget(dir: PathBuf, limits: BundleLimits, max_total_bytes: u64) -> Self {
        let dir = make_private_dir(&dir)
            .and_then(|()| dir.canonicalize())
            .or_else(|_| std::path::absolute(&dir))
            .unwrap_or(dir);
        let left = remove_leftovers(&dir);
        if left > 0 {
            tracing::info!(dir = %dir.display(), left, "removed uploads an earlier run left");
        }
        let max_total_bytes = max_total_bytes.max(limits.extracted_bytes);
        Self {
            inner: Arc::new(Inner {
                dir,
                limits,
                plugins: std::sync::OnceLock::new(),
                max_total_bytes,
                patience: (UPLOAD_IDLE, UPLOAD_TIME),
                state: Mutex::default(),
                lease: std::sync::OnceLock::new(),
                stopping: CancellationToken::new(),
            }),
        }
    }

    /// Take bundles that carry these sync plugins, in place of the ones a
    /// store takes unless told ([`AllowedPlugins::known`]): for a server to
    /// say as it makes the store, before a bundle arrives. The first word
    /// stands.
    pub fn allowing(self, plugins: AllowedPlugins) -> Self {
        let _ = self.inner.plugins.set(plugins);
        self
    }

    /// Hold `lease` for as long as anything works in this store's directory:
    /// the store and its clones, and every thread extracting or removing a
    /// bundle, which can outlive the request that started it. For a server
    /// whose lock on the directory says it is the directory's one owner: a
    /// second store made over it once the lock is free would clear a bundle
    /// an earlier one is still writing. The first word stands.
    pub fn held_with(self, lease: Arc<dyn std::any::Any + Send + Sync>) -> Self {
        let _ = self.inner.lease.set(lease);
        self
    }

    /// Say that the server is stopping: an upload asked for from now on is
    /// refused, and one arriving is given up on at its next read, its bundle
    /// removed — rather than holding a stopping server for as long as a body
    /// may take to arrive. Returns at once.
    pub fn stop(&self) {
        self.inner.stopping.cancel();
    }

    /// The sync plugins a bundle may carry here: what an upload is held to
    /// as it arrives, and what its deploy is held to again.
    pub fn plugins(&self) -> AllowedPlugins {
        self.inner.plugins.get_or_init(AllowedPlugins::known).clone()
    }

    /// How large a bundle this store takes.
    pub fn limits(&self) -> BundleLimits {
        self.inner.limits
    }

    /// What the store holds now, against what it may.
    pub fn held(&self) -> Held {
        let state = self.inner.state();
        Held {
            bytes: state.bytes,
            max_bytes: self.inner.max_total_bytes,
            uploads: state.uploads.len(),
            receiving: state.receiving.len(),
        }
    }

    /// Drop expired tickets, and expired uploads with their bundles. Every
    /// operation does this first; a server calls it on a timer as well, so
    /// an idle store does not hold what has lapsed. The bundles are removed
    /// on a thread that may block when this is called on a runtime (they,
    /// and their bytes, may outlast the call by that removal), and before
    /// it returns when it is not.
    pub fn sweep(&self) {
        self.locked(|_, _| ());
    }

    /// Run `f` on the state, swept, under its lock. `f` is handed the
    /// bundles that sweep found lapsed, and may add to them, or take the
    /// ones it must see gone before it goes on; what it leaves is removed
    /// once the lock is released ([`clear`]), never under it.
    fn locked<T>(&self, f: impl FnOnce(&mut State, &mut Vec<Leaving>) -> T) -> T {
        // Declared before the guard, so dropped after it, however this ends.
        let mut leaving = Vec::new();
        let out = {
            let mut state = self.inner.state();
            sweep(&self.inner, &mut state, &mut leaving);
            f(&mut state, &mut leaving)
        };
        clear(leaving);
        out
    }

    /// Mint a ticket for `session`, dropping any it already holds.
    pub async fn mint(&self, session: &str) -> Minted {
        self.locked(|state, _| {
            state.tickets.retain(|_, t| t.session != session);
            let ticket = random_token();
            state.tickets.insert(
                ticket.clone(),
                Ticket { session: session.to_string(), expires: Instant::now() + TICKET_TTL },
            );
            tracing::info!(session, "upload ticket minted");
            Minted { ticket, expires_in: TICKET_TTL }
        })
    }

    /// Receive a bundle on `ticket`: the ticket is spent first, a declared
    /// length over the archive limit is refused unread, room is reserved
    /// (see the module docs), and the body is extracted as it is read, up
    /// to the limits and no further.
    ///
    /// The extraction runs on a thread of its own, which owns the body: it
    /// goes on to the body's end whether or not the caller is still waiting,
    /// and cleans up after itself either way. A caller that goes away loses
    /// only the answer.
    pub async fn receive(
        &self,
        ticket: &str,
        declared_len: Option<u64>,
        body: impl AsyncRead + Unpin + Send + 'static,
    ) -> Result<Received, ReceiveError> {
        let limits = self.inner.limits;
        let upload_id = random_token();
        // A ticket the store never minted is refused before anything else is
        // looked at: the route is outside the bearer gate, and a sweep is
        // work over every ticket and upload under the lock every session's
        // calls wait on. A known ticket's expiry is looked at by the sweep.
        if !self.inner.state().tickets.contains_key(ticket) {
            tracing::info!("upload refused: no such ticket (spent, expired or unknown)");
            return Err(ReceiveError::UnknownTicket);
        }
        let (receiving, making_way) = self.locked(|state, lapsed| {
            if self.inner.stopping.is_cancelled() {
                tracing::info!("upload refused: the server is stopping");
                return Err(ReceiveError::Stopping);
            }
            let Some(Ticket { session, .. }) = state.tickets.remove(ticket) else {
                tracing::info!("upload refused: no such ticket (spent, expired or unknown)");
                return Err(ReceiveError::UnknownTicket);
            };
            if declared_len.is_some_and(|len| len > limits.archive_bytes) {
                let max = limits.archive_bytes;
                tracing::warn!(session, ?declared_len, max, "upload refused: declared too large");
                return Err(ReceiveError::TooLarge(max));
            }
            if state.receiving.contains(&session) {
                tracing::warn!(session, "upload refused: another is arriving for the session");
                return Err(ReceiveError::Busy);
            }
            // The bundle the session was holding gives way to this one, so
            // its bytes are room this one may use — but it goes only once
            // this one is let in: a refusal leaves the session what it had.
            let (replaced, giving_way): (Vec<String>, u64) = state
                .uploads
                .iter()
                .filter(|(_, u)| u.session == session)
                .fold((Vec::new(), 0), |(mut ids, bytes), (id, u)| {
                    ids.push(id.clone());
                    (ids, bytes + u.bytes)
                });
            // So are the bytes of the bundles that have lapsed: charged
            // still, since they are still there, and removed with the one
            // replaced before a byte of this one is written.
            let lapsing: u64 = lapsed.iter().map(|l| l.bytes).sum();
            // Its size is known only once it has arrived: the most it may
            // extract to is held for it until then.
            let reserved = limits.extracted_bytes;
            let held = state.bytes.saturating_sub(giving_way).saturating_sub(lapsing);
            if held + reserved > self.inner.max_total_bytes {
                tracing::warn!(session, held = state.bytes, "upload refused: the store is full");
                return Err(ReceiveError::Full);
            }
            let mut making_way = std::mem::take(lapsed);
            making_way
                .extend(replaced.iter().filter_map(|id| remove_upload(&self.inner, state, id)));
            state.bytes += reserved;
            state.receiving.insert(session.clone());
            let receiving = Receiving {
                store: self.inner.clone(),
                session,
                dir: self.inner.dir.join(&upload_id),
                reserved,
                finished: false,
            };
            Ok((receiving, making_way))
        })?;
        let session = receiving.session.clone();
        let (root, (idle, time)) = (self.inner.dir.clone(), self.inner.patience);
        let stop = self.inner.stopping.clone();
        let runtime = tokio::runtime::Handle::current();
        let plugins = self.plugins();
        let id = upload_id.clone();
        // The guard goes to the thread with the body: see `Receiving`.
        let extracting = tokio::task::spawn_blocking(move || {
            // The room this bundle was let in on is made first: what the
            // session was holding, and what had lapsed.
            drop(making_way);
            make_private_dir(&root)
                .and_then(|()| make_new_private_dir(&receiving.dir))
                .map_err(|e| ReceiveError::Storage(e.to_string()))?;
            let dir = Utf8PathBuf::from_path_buf(receiving.dir.clone()).map_err(|p| {
                ReceiveError::Storage(format!("the upload path '{}' is not UTF-8", p.display()))
            })?;
            let vetting = runtime.clone();
            let body =
                Arriving { body, runtime, idle, deadline: Instant::now() + time, time, stop };
            let extracted = host::extract_bundle_from(body, &dir, &limits)?;
            // All of it has arrived and is a bundle's shape: now whether it
            // is one this server will deploy. Said here, on the upload, and
            // the bundle not kept, rather than at the deploy it would fail.
            vetting.block_on(host::vet_plugins(&extracted.fs, &limits, &plugins)).map_err(|e| {
                match e {
                    VetError::NotABundle(why) => ReceiveError::NotABundle(why),
                    VetError::PluginNotAllowed(why) => ReceiveError::PluginNotAllowed(why),
                }
            })?;
            receiving.finish(&id, extracted.bytes);
            Ok::<_, ReceiveError>((extracted.bytes, extracted.archive_bytes))
        });
        let outcome = extracting
            .await
            .unwrap_or_else(|e| {
                Err(ReceiveError::Storage(format!("the extraction did not finish: {e}")))
            })
            // A body cut off because the server is stopping is said as that,
            // not as a transfer that failed.
            .map_err(|e| match e {
                ReceiveError::Body(_) if self.inner.stopping.is_cancelled() => {
                    ReceiveError::Stopping
                }
                e => e,
            });
        match outcome {
            Ok((bytes, archive_bytes)) => {
                tracing::info!(session, upload_id, bytes, archive_bytes, "bundle uploaded");
                Ok(Received { upload_id, bytes, archive_bytes, expires_in: UPLOAD_TTL })
            }
            Err(e) => {
                match &e {
                    ReceiveError::Storage(_) => tracing::error!(session, %e, "upload failed"),
                    _ => tracing::warn!(session, %e, "upload refused"),
                }
                Err(e)
            }
        }
    }

    /// Hand `upload_id` to its deploy, if `session` is the one that uploaded
    /// it and there is room for the deploy to run: the bundle's directory,
    /// and its hold on the budget until the returned handle drops. A deploy
    /// is charged the most its directory may come to, not what its bundle
    /// extracted to (see the module docs), so the hold grows here; an upload
    /// refused for want of that room is left as it was, to be asked for
    /// again.
    pub async fn take(&self, upload_id: &str, session: &str) -> Result<TakenUpload, TakeError> {
        let (taken, making_way) = self.locked(|state, lapsed| {
            let Some(bytes) =
                state.uploads.get(upload_id).filter(|u| u.session == session).map(|u| u.bytes)
            else {
                tracing::info!(session, upload_id, "no such upload for the session");
                return Err(TakeError::NoSuchUpload);
            };
            let charged = self.inner.limits.extracted_bytes.max(bytes);
            // What has lapsed is room, as it is for an arrival: removed
            // before the deploy is handed its bundle.
            let lapsing: u64 = lapsed.iter().map(|l| l.bytes).sum();
            let held = state.bytes.saturating_sub(lapsing);
            if held + (charged - bytes) > self.inner.max_total_bytes {
                tracing::warn!(session, upload_id, held, "no room to deploy the upload");
                return Err(TakeError::NoRoom);
            }
            state.bytes += charged - bytes;
            tracing::info!(session, upload_id, "upload taken by a deploy");
            let upload = state.uploads.remove(upload_id).expect("looked up above, under the lock");
            let taken = TakenUpload { dir: upload.dir, bytes, charged, store: self.inner.clone() };
            Ok((taken, std::mem::take(lapsed)))
        })?;
        if !making_way.is_empty() {
            // Dropped where it runs, or with the closure if it never does.
            let _ = tokio::task::spawn_blocking(move || drop(making_way)).await;
        }
        Ok(taken)
    }
}

/// A request body as the extractor reads it: a blocking reader over an
/// asynchronous one, on a thread that may block. Each read waits for the
/// next chunk, but not for ever: a body that stops arriving, or that has
/// taken too long in all, ends in an error, and the extraction with it.
struct Arriving<R> {
    body: R,
    runtime: tokio::runtime::Handle,
    idle: Duration,
    deadline: Instant,
    time: Duration,
    /// The store's [`Uploads::stop`]: a body still arriving then is given up
    /// on at its next read.
    stop: CancellationToken,
}

impl<R: AsyncRead + Unpin> std::io::Read for Arriving<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let timed_out = |why: String| std::io::Error::new(std::io::ErrorKind::TimedOut, why);
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(timed_out(format!(
                "the upload took longer than the {} seconds one may",
                self.time.as_secs()
            )));
        }
        let wait = self.idle.min(left);
        let (body, stop) = (&mut self.body, &self.stop);
        let read = self.runtime.block_on(async {
            tokio::select! {
                biased;
                _ = stop.cancelled() => None,
                read = tokio::time::timeout(wait, body.read(buf)) => Some(read),
            }
        });
        match read {
            // Not `Interrupted`, which readers take as "try again".
            None => Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "the server is stopping",
            )),
            Some(Ok(read)) => read,
            Some(Err(_)) => Err(timed_out(format!(
                "no data arrived for {} seconds, or the upload ran out of time",
                wait.as_secs()
            ))),
        }
    }
}

/// Drop expired tickets, and stop holding expired uploads: their bundles
/// are added to `leaving`, for the caller to remove once the lock is
/// released.
fn sweep(store: &Arc<Inner>, state: &mut State, leaving: &mut Vec<Leaving>) {
    let now = Instant::now();
    state.tickets.retain(|_, t| t.expires > now);
    let expired: Vec<String> =
        state.uploads.iter().filter(|(_, u)| u.expires <= now).map(|(id, _)| id.clone()).collect();
    leaving.extend(expired.iter().filter_map(|id| remove_upload(store, state, id)));
}

/// Stop holding an upload. Its bundle, and its share of the budget, go when
/// what this returns is dropped, which is not to be under the lock.
fn remove_upload(store: &Arc<Inner>, state: &mut State, upload_id: &str) -> Option<Leaving> {
    let upload = state.uploads.remove(upload_id)?;
    Some(Leaving { store: store.clone(), dir: upload.dir, bytes: upload.bytes })
}

/// Remove every upload directly under `dir` — what a store names its
/// bundles (and what an earlier version named its archives), and nothing
/// else — and say how many there were.
fn remove_leftovers(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let is_id = |id: &str| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit());
    entries
        .flatten()
        .filter(|entry| {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { return false };
            // A link is removed, never followed.
            let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
            if is_dir && is_id(name) {
                std::fs::remove_dir_all(entry.path()).is_ok()
            } else if !is_dir && name.strip_suffix(".tar.gz").is_some_and(is_id) {
                std::fs::remove_file(entry.path()).is_ok()
            } else {
                false
            }
        })
        .count()
}

/// `dir`, created if missing, and on Unix its owner's alone — one that was
/// there already too, which is made so, or refused if it cannot be (it is
/// another user's). Under a directory others can write to, a bundle's own
/// could be renamed away and another tree put in its place.
fn make_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        if !dir.is_dir() {
            // The mode is less the umask, which only takes bits away.
            return std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir);
        }
        if std::fs::metadata(dir)?.permissions().mode() & 0o777 == 0o700 {
            return Ok(());
        }
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!(
                    "the upload directory '{}' is open to other users and could not be made                      private: {e}",
                    dir.display()
                ),
            )
        })
    }
    #[cfg(not(unix))]
    {
        if dir.is_dir() {
            return Ok(());
        }
        std::fs::create_dir_all(dir)
    }
}

/// `dir`, created now and not before, and on Unix readable by its owner
/// alone: a bundle's own directory, which nothing else has written into.
fn make_new_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(dir)
    }
    #[cfg(not(unix))]
    std::fs::create_dir(dir)
}

/// 256 random bits, hex-encoded: a ticket or an upload id.
fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("the OS random source to be available");
    hex::encode(bytes)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    /// A bundle archive: a manifest, and `filler` bytes of something else.
    /// It extracts to the manifest's length and the filler's.
    pub(crate) fn bundle(filler: usize) -> Vec<u8> {
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        for (path, data) in [("icp.yaml", MANIFEST.to_vec()), ("assets/blob", vec![7u8; filler])] {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(&mut header, path, &data[..]).unwrap();
        }
        archive.into_inner().unwrap().finish().unwrap()
    }

    const MANIFEST: &[u8] = b"canisters: []\n";

    /// What [`bundle`] extracts to, as it is counted: the manifest, the
    /// filler, and the directory the filler is in.
    fn extracted(filler: usize) -> u64 {
        host::occupies(MANIFEST.len() as u64) + host::occupies(filler as u64) + host::ENTRY_BYTES
    }

    /// What the smallest bundle extracts to: the unit the budget tests count in.
    const U: u64 = 2 * (host::BLOCK_BYTES + host::ENTRY_BYTES) + host::ENTRY_BYTES;

    /// Limits small enough to pass: `archive` bytes compressed, `extracted`
    /// extracted.
    fn limits(archive: u64, extracted: u64) -> BundleLimits {
        BundleLimits::new(archive, extracted)
    }

    fn store(limits: BundleLimits) -> (tempfile::TempDir, Uploads) {
        let dir = tempfile::tempdir().unwrap();
        let uploads = Uploads::new(dir.path().join("uploads"), limits);
        (dir, uploads)
    }

    async fn put(
        uploads: &Uploads,
        session: &str,
        body: Vec<u8>,
    ) -> Result<Received, ReceiveError> {
        let t = uploads.mint(session).await;
        uploads.receive(&t.ticket, Some(body.len() as u64), std::io::Cursor::new(body)).await
    }

    /// What is under the store's directory.
    fn kept(uploads: &Uploads) -> usize {
        std::fs::read_dir(&uploads.inner.dir).map(|entries| entries.count()).unwrap_or(0)
    }

    // The archive is extracted as it arrives: what the store holds, and
    // hands the deploy, is the bundle's directory, and the archive is
    // nowhere. A store given a relative directory (a server started with a
    // relative state directory) hands out absolute paths: the deploy that
    // takes an upload takes no other kind.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_bundle_is_extracted_as_it_arrives() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        // The directory spelled relative to the working directory: up to the
        // root, then down to it.
        let cwd = std::env::current_dir().unwrap();
        let mut relative = PathBuf::new();
        relative.extend(cwd.components().skip(1).map(|_| ".."));
        relative.push(dir.path().strip_prefix("/").unwrap());
        assert!(relative.is_relative(), "{}", relative.display());
        let uploads = Uploads::new(relative.join("uploads"), limits(1 << 20, 1 << 20));

        let archive = bundle(100);
        let received = put(&uploads, "sess", archive.clone()).await.unwrap();
        assert_eq!(received.bytes, extracted(100));
        assert_eq!(received.archive_bytes, archive.len() as u64);
        assert_eq!(uploads.inner.state().bytes, extracted(100), "settled to what it extracted to");

        let taken = uploads.take(&received.upload_id, "sess").await.unwrap();
        assert!(taken.dir().is_absolute(), "{}", taken.dir().display());
        assert!(taken.dir().starts_with(dir.path().canonicalize().unwrap()));
        assert_eq!(taken.bytes(), extracted(100));
        assert_eq!(std::fs::read(taken.dir().join("icp.yaml")).unwrap(), MANIFEST);
        assert_eq!(std::fs::read(taken.dir().join("assets/blob")).unwrap(), vec![7u8; 100]);
        let mode = std::fs::metadata(taken.dir()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "the bundle is the server's user's alone");
        // Nothing but the bundle's directory: no archive was kept.
        assert_eq!(kept(&uploads), 1);
        let bundle_dir = taken.dir().to_path_buf();
        drop(taken);
        assert!(!bundle_dir.exists(), "a bundle its deploy never moved goes with the handle");
        assert_eq!(uploads.inner.state().bytes, 0);
    }

    #[tokio::test]
    async fn a_ticket_receives_one_bundle_for_its_session_alone() {
        let (_dir, uploads) = store(limits(1 << 20, 1 << 20));
        let minted = uploads.mint("sess-a").await;
        assert_eq!(minted.ticket.len(), 64, "256 bits, hex");
        let body = || std::io::Cursor::new(bundle(10));
        let received = uploads.receive(&minted.ticket, None, body()).await.unwrap();

        // Single use: the same ticket again is unknown.
        let again = uploads.receive(&minted.ticket, None, body()).await;
        assert_eq!(again.unwrap_err(), ReceiveError::UnknownTicket);

        // The upload is deployable by the session that made it alone, once.
        let other = uploads.take(&received.upload_id, "sess-b").await.unwrap_err();
        assert_eq!(other, TakeError::NoSuchUpload);
        let taken = uploads.take(&received.upload_id, "sess-a").await.unwrap();
        let twice = uploads.take(&received.upload_id, "sess-a").await.unwrap_err();
        assert_eq!(twice, TakeError::NoSuchUpload);
        drop(taken);
    }

    #[tokio::test]
    async fn minting_again_drops_the_previous_ticket_and_unknown_tickets_cost_nothing() {
        let (_dir, uploads) = store(limits(1 << 20, 1 << 20));
        let first = uploads.mint("sess").await;
        let second = uploads.mint("sess").await;
        let body = || std::io::Cursor::new(bundle(1));
        let refused = uploads.receive(&first.ticket, None, body()).await;
        assert_eq!(refused.unwrap_err(), ReceiveError::UnknownTicket);
        assert!(uploads.receive(&second.ticket, None, body()).await.is_ok());
        let unknown = uploads.receive("0".repeat(64).as_str(), None, body()).await;
        assert_eq!(unknown.unwrap_err(), ReceiveError::UnknownTicket);
    }

    // The archive limit: a declared length over it is refused before a byte
    // is read, and an undeclared body is stopped at the byte that passes it.
    // Either way the ticket is spent and nothing is kept.
    #[tokio::test]
    async fn an_archive_over_the_limit_is_refused_and_nothing_kept() {
        let archive = bundle(2000);
        let (_dir, uploads) = store(limits(archive.len() as u64 - 1, 1 << 20));

        // A body that would fail if it were read: it is not.
        struct Unread;
        impl AsyncRead for Unread {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                _: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                panic!("a body declared too large is not read")
            }
        }
        let t = uploads.mint("s").await;
        let declared = uploads.receive(&t.ticket, Some(archive.len() as u64), Unread).await;
        assert_eq!(declared.unwrap_err(), ReceiveError::TooLarge(archive.len() as u64 - 1));
        let again = uploads.receive(&t.ticket, None, std::io::Cursor::new(Vec::new())).await;
        assert_eq!(again.unwrap_err(), ReceiveError::UnknownTicket, "the ticket was spent");

        let t = uploads.mint("s").await;
        let streamed =
            uploads.receive(&t.ticket, None, std::io::Cursor::new(archive.clone())).await;
        assert_eq!(streamed.unwrap_err(), ReceiveError::TooLarge(archive.len() as u64 - 1));
        assert_eq!(kept(&uploads), 0);
        assert_eq!(uploads.inner.state().bytes, 0);
        assert!(uploads.inner.state().receiving.is_empty());
    }

    // The limit that matters where the bundle is kept in memory: what the
    // archive inflates to. An archive far inside the archive limit that
    // extracts past it is stopped while it is still arriving — the rest of
    // the body is never read — and what had been written is removed.
    #[tokio::test]
    async fn a_bundle_that_extracts_past_the_limit_is_stopped_as_it_arrives() {
        // Compresses a thousandfold: a megabyte of one byte.
        let archive = bundle(1 << 20);
        assert!(archive.len() < 16 * 1024, "{}", archive.len());
        let (_dir, uploads) = store(limits(1 << 20, 64 * 1024));

        // The archive, then a tail that fails the test if it is reached.
        struct Tail {
            head: std::io::Cursor<Vec<u8>>,
        }
        impl AsyncRead for Tail {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                let before = buf.filled().len();
                let read = std::pin::Pin::new(&mut self.head).poll_read(cx, buf);
                assert!(buf.filled().len() > before, "read past the bundle that was refused");
                read
            }
        }
        let t = uploads.mint("s").await;
        let body = Tail { head: std::io::Cursor::new(archive) };
        let refused = uploads.receive(&t.ticket, None, body).await.unwrap_err();
        assert_eq!(refused, ReceiveError::ExtractsTooLarge(64 * 1024));
        assert!(refused.to_string().contains("extracts to more than"), "{refused}");
        assert_eq!(kept(&uploads), 0, "what had been extracted is removed");
        assert_eq!(uploads.inner.state().bytes, 0);

        // One that fits, to the block, is taken; a byte into the next is not.
        let (_dir, uploads) = store(limits(1 << 20, extracted(4096)));
        assert_eq!(put(&uploads, "s", bundle(4096)).await.unwrap().bytes, extracted(4096));
        let over = put(&uploads, "t", bundle(4097)).await.unwrap_err();
        assert_eq!(over, ReceiveError::ExtractsTooLarge(extracted(4096)));
    }

    // What arrives is held to being a bundle while it arrives: the refusal
    // comes on the upload, not on the deploy it would have failed.
    #[tokio::test]
    async fn what_is_not_a_bundle_is_refused_on_arrival() {
        let (_dir, uploads) = store(limits(1 << 20, 1 << 20));
        let refused = put(&uploads, "s", b"not an archive".to_vec()).await.unwrap_err();
        assert!(matches!(&refused, ReceiveError::NotABundle(why) if why.contains(".tar.gz")));

        // An archive, with no manifest in it.
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&[0u8; 1024]).unwrap();
        let refused = put(&uploads, "s", encoder.finish().unwrap()).await.unwrap_err();
        assert!(matches!(&refused, ReceiveError::NotABundle(why) if why.contains("icp.yaml")));
        assert_eq!(kept(&uploads), 0);
        assert_eq!(uploads.inner.state().bytes, 0);
    }

    // A bundle that carries a sync plugin the server does not run is
    // refused as it arrives, and not kept: the plugin is a program the
    // server would run for it. A store takes the plugins a server that
    // deploys for others knows unless it is told which; told this one's
    // hash, it takes the bundle.
    #[tokio::test]
    async fn a_bundle_with_a_plugin_the_server_does_not_run_is_refused_on_arrival() {
        use sha2::{Digest, Sha256};
        let plugin = b"\0asm a plugin nobody vouched for";
        let sha = hex::encode(Sha256::digest(plugin));
        let module = b"\0asm\x01\0\0\0";
        let canister = format!(
            "name: frontend\nbuild:\n  steps:\n    - type: pre-built\n      path: frontend.wasm\n      \
             sha256: {}\nsync:\n  steps:\n    - type: plugin\n      path: sync.wasm\n",
            hex::encode(Sha256::digest(module))
        );
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        for (path, data) in [
            ("icp.yaml", &b"canisters:\n  - canisters/frontend\n"[..]),
            ("canisters/frontend/canister.yaml", canister.as_bytes()),
            ("canisters/frontend/frontend.wasm", &module[..]),
            ("canisters/frontend/sync.wasm", &plugin[..]),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(&mut header, path, data).unwrap();
        }
        let archive = archive.into_inner().unwrap().finish().unwrap();

        let (_dir, uploads) = store(limits(1 << 20, 1 << 20));
        assert_eq!(uploads.plugins(), AllowedPlugins::known());
        let refused = put(&uploads, "s", archive.clone()).await.unwrap_err();
        let ReceiveError::PluginNotAllowed(why) = &refused else { panic!("{refused:?}") };
        assert!(why.contains(&sha) && why.contains("is not one this server runs"), "{why}");
        assert_eq!(kept(&uploads), 0, "the bundle is not kept");
        assert_eq!(uploads.held(), Held { bytes: 0, max_bytes: 3 << 20, uploads: 0, receiving: 0 });

        let (_dir, uploads) = store(limits(1 << 20, 1 << 20));
        let uploads = uploads.allowing(AllowedPlugins::known_and([&sha]).unwrap());
        assert!(put(&uploads, "s", archive).await.is_ok());
        assert_eq!(kept(&uploads), 1);
    }

    // A body that fails is the client's side; a bundle that cannot be
    // written is the server's.
    #[tokio::test]
    async fn a_failed_read_and_a_failed_write_are_told_apart() {
        struct Broken;
        impl AsyncRead for Broken {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                _: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Err(std::io::Error::other("connection reset")))
            }
        }
        let (_dir, uploads) = store(limits(1 << 20, 1 << 20));
        let t = uploads.mint("s").await;
        let body = uploads.receive(&t.ticket, None, Broken).await.unwrap_err();
        assert!(matches!(&body, ReceiveError::Body(why) if why.contains("connection reset")));
        assert_eq!(kept(&uploads), 0);

        // The store's directory is a file: no bundle's directory can be made.
        let dir = tempfile::tempdir().unwrap();
        let blocked = dir.path().join("uploads");
        std::fs::write(&blocked, "in the way").unwrap();
        let uploads = Uploads::new(blocked, limits(1 << 20, 1 << 20));
        let storage = put(&uploads, "s", bundle(1)).await.unwrap_err();
        assert!(matches!(storage, ReceiveError::Storage(_)), "{storage:?}");
        assert_eq!(uploads.inner.state().bytes, 0);
    }

    // A session's new upload takes the place of the one it held.
    #[tokio::test]
    async fn a_new_upload_replaces_the_one_the_session_was_holding() {
        let (_dir, uploads) = store(limits(1 << 20, 1 << 20));
        let first = put(&uploads, "s", bundle(10)).await.unwrap();
        let second = put(&uploads, "s", bundle(20)).await.unwrap();
        assert_eq!(kept(&uploads), 1, "one bundle for the session");
        assert_eq!(uploads.inner.state().bytes, extracted(20));
        let replaced = uploads.take(&first.upload_id, "s").await.unwrap_err();
        assert_eq!(replaced, TakeError::NoSuchUpload);
        assert!(uploads.take(&second.upload_id, "s").await.is_ok());
    }

    // The budget is the whole store's, in extracted bytes. A bundle that is
    // arriving is charged the most it may extract to, since its size is not
    // known yet; one that is waiting, what it did extract to; and one with
    // its deploy the limit again, for the room the deploy grows into.
    #[tokio::test]
    async fn the_budget_is_charged_by_what_a_bundle_may_come_to() {
        let dir = tempfile::tempdir().unwrap();
        // Every bundle here is the smallest there is, `U`; one may come to
        // ten times that, and the store holds two at the limit and one more.
        let (limit, budget) = (10 * U, 21 * U);
        assert_eq!(extracted(1), U);
        let uploads =
            Uploads::with_budget(dir.path().join("uploads"), limits(1 << 20, limit), budget);

        // Waiting: what they extracted to.
        let a = put(&uploads, "a", bundle(1)).await.unwrap();
        let b = put(&uploads, "b", bundle(1)).await.unwrap();
        assert_eq!(uploads.held().bytes, 2 * U);
        assert_eq!(uploads.held().uploads, 2);

        // With its deploy: the limit, until the deploy lets go.
        let running = uploads.take(&a.upload_id, "a").await.unwrap();
        assert_eq!(uploads.held().bytes, 11 * U);
        // An arrival reserves the limit before a byte is read: 11 held and
        // 10 more is the budget exactly, so one fits, and settles...
        let c = put(&uploads, "c", bundle(1)).await.unwrap();
        assert_eq!(uploads.held().bytes, 12 * U);
        // ...and the next has 12 held, which with its 10 is past it.
        assert_eq!(put(&uploads, "d", bundle(1)).await.unwrap_err(), ReceiveError::Full);

        // A second deploy needs the limit too: 12 held, 9 more is the
        // budget exactly.
        let second = uploads.take(&b.upload_id, "b").await.unwrap();
        assert_eq!(uploads.held().bytes, 21 * U);
        // A third has no room to grow into. Its upload stays, to be asked
        // for again once there is.
        assert_eq!(uploads.take(&c.upload_id, "c").await.unwrap_err(), TakeError::NoRoom);
        assert_eq!(uploads.held().uploads, 1);
        drop(running);
        assert_eq!(uploads.held().bytes, 11 * U);
        let third = uploads.take(&c.upload_id, "c").await.unwrap();
        drop((second, third));
        assert_eq!(uploads.held(), Held { bytes: 0, max_bytes: budget, uploads: 0, receiving: 0 });

        // A budget is at least one bundle's worth.
        let tiny = Uploads::with_budget(dir.path().join("tiny"), limits(1 << 20, limit), 1);
        assert_eq!(tiny.held().max_bytes, limit);
    }

    // A session's new upload takes the place of the one it held, so that
    // one's bytes count as room; and when there is still no room, the
    // refusal costs the session nothing: what it held is still deployable.
    #[tokio::test]
    async fn a_refused_replacement_leaves_the_session_its_upload() {
        let dir = tempfile::tempdir().unwrap();
        // One may come to ten of the smallest, `U`, and the store holds
        // eleven: an arrival beside one small bundle, and no more.
        let uploads =
            Uploads::with_budget(dir.path().join("uploads"), limits(1 << 20, 10 * U), 11 * U);
        let first = put(&uploads, "a", bundle(1)).await.unwrap();
        let other = put(&uploads, "b", bundle(2 * 4096)).await.unwrap();
        let both = U + extracted(2 * 4096);
        assert!(extracted(2 * 4096) > U);
        // `a`'s own `U` gives way, but `b`'s is more than the one `U` to
        // spare beside the ten an arrival reserves.
        assert_eq!(put(&uploads, "a", bundle(1)).await.unwrap_err(), ReceiveError::Full);
        assert_eq!(uploads.held().bytes, both);
        assert!(
            uploads.inner.state().uploads.contains_key(&first.upload_id),
            "refused, the session still holds its upload"
        );
        // With `b`'s gone there is room, `a`'s own giving way; then it does.
        drop(uploads.take(&other.upload_id, "b").await.unwrap());
        let second = put(&uploads, "a", bundle(4097)).await.unwrap();
        assert_eq!(uploads.held().bytes, extracted(4097));
        assert_eq!(uploads.take(&first.upload_id, "a").await.unwrap_err(), TakeError::NoSuchUpload);
        assert!(uploads.take(&second.upload_id, "a").await.is_ok());
    }

    /// A body that yields `head` and then nothing more, for ever: an upload
    /// whose sender has stalled.
    struct Stalled {
        head: std::io::Cursor<Vec<u8>>,
    }

    impl AsyncRead for Stalled {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let before = buf.filled().len();
            let _ = std::pin::Pin::new(&mut self.head).poll_read(cx, buf);
            match buf.filled().len() > before {
                true => std::task::Poll::Ready(Ok(())),
                false => std::task::Poll::Pending,
            }
        }
    }

    /// `uploads`, with the patience of a test.
    fn impatient(uploads: Uploads, idle: Duration, time: Duration) -> Uploads {
        let inner = &uploads.inner;
        Uploads {
            inner: Arc::new(Inner {
                dir: inner.dir.clone(),
                limits: inner.limits,
                plugins: inner.plugins.clone(),
                max_total_bytes: inner.max_total_bytes,
                patience: (idle, time),
                state: Mutex::default(),
                lease: std::sync::OnceLock::new(),
                stopping: CancellationToken::new(),
            }),
        }
    }

    // The upload route is outside the bearer gate: a ticket the store never
    // minted is refused without the sweep, which is work over every ticket
    // and upload under the lock. What has lapsed waits for a call that has
    // a ticket, or for the sweeper.
    #[tokio::test]
    async fn an_unknown_ticket_is_refused_before_the_store_is_swept() {
        let (_dir, uploads) = store(limits(1 << 20, 1 << 20));
        let received = put(&uploads, "s", bundle(1)).await.unwrap();
        let lapsed = lapse(&uploads, &received.upload_id);
        let refused = uploads.receive(&"0".repeat(64), None, std::io::Cursor::new(bundle(1))).await;
        assert_eq!(refused.unwrap_err(), ReceiveError::UnknownTicket);
        assert_eq!(uploads.held().uploads, 1, "not swept");
        assert!(lapsed.exists());
    }

    // A stopping server takes no new upload and gives up on the one
    // arriving, at once rather than when its body ends: the partial bundle
    // and its reservation go with it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stopped_store_refuses_uploads_and_gives_up_on_what_is_arriving() {
        let (_dir, uploads) = store(limits(1 << 20, 1 << 20));
        let mut archive = bundle(50_000);
        archive.truncate(archive.len() / 2);
        let t = uploads.mint("s").await;
        let arriving = {
            let uploads = uploads.clone();
            let body = Stalled { head: std::io::Cursor::new(archive) };
            tokio::spawn(async move { uploads.receive(&t.ticket, None, body).await })
        };
        while uploads.held().receiving == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let started = Instant::now();
        uploads.stop();
        let given_up = arriving.await.unwrap().unwrap_err();
        assert_eq!(given_up, ReceiveError::Stopping);
        assert!(started.elapsed() < Duration::from_secs(5), "not left to its idle timeout");
        assert_eq!(kept(&uploads), 0, "the partial bundle is removed");
        assert_eq!(uploads.held().bytes, 0);

        let t = uploads.mint("s").await;
        let refused = uploads.receive(&t.ticket, None, std::io::Cursor::new(bundle(1))).await;
        assert_eq!(refused.unwrap_err(), ReceiveError::Stopping);
    }

    // What the server holds the directory by lives as long as anything
    // works in it: past the store's last handle, while a bundle is still
    // being extracted for a request that has gone.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_lease_outlives_the_store_while_a_bundle_is_arriving() {
        let (_dir, uploads) = store(limits(1 << 20, 1 << 20));
        let uploads = impatient(uploads, Duration::from_millis(300), Duration::from_secs(60));
        let lease: Arc<dyn std::any::Any + Send + Sync> = Arc::new(());
        let held = Arc::downgrade(&lease);
        let uploads = uploads.held_with(lease);
        let mut archive = bundle(50_000);
        archive.truncate(archive.len() / 2);
        let t = uploads.mint("s").await;
        let arriving = {
            let uploads = uploads.clone();
            let body = Stalled { head: std::io::Cursor::new(archive) };
            tokio::spawn(async move { uploads.receive(&t.ticket, None, body).await })
        };
        while uploads.held().receiving == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // The request goes, and the store's last handle with it.
        arriving.abort();
        drop(uploads);
        assert!(held.upgrade().is_some(), "the extraction still holds the lease");
        // Its body stalled, it ends at its idle timeout, and lets go.
        let deadline = Instant::now() + Duration::from_secs(10);
        while held.upgrade().is_some() {
            assert!(Instant::now() < deadline, "the extraction ended and let the lease go");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    // A body that stops arriving is given up on, and so is one that takes
    // too long in all: the session's turn, the partial bundle and the
    // reservation go, and the session can upload again.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_upload_that_stalls_is_given_up_on() {
        let (_dir, uploads) = store(limits(1 << 20, 1 << 20));
        let half = || {
            let mut archive = bundle(50_000);
            archive.truncate(archive.len() / 2);
            Stalled { head: std::io::Cursor::new(archive) }
        };

        let idle = impatient(uploads.clone(), Duration::from_millis(50), Duration::from_secs(60));
        let t = idle.mint("s").await;
        let stalled = idle.receive(&t.ticket, None, half()).await.unwrap_err();
        assert!(matches!(&stalled, ReceiveError::Body(why) if why.contains("no data arrived")));
        assert_eq!(kept(&idle), 0, "the partial bundle is removed");
        assert_eq!(idle.held(), Held { bytes: 0, max_bytes: 3 << 20, uploads: 0, receiving: 0 });
        assert!(put(&idle, "s", bundle(1)).await.is_ok(), "the session can upload again");

        let slow = impatient(uploads, Duration::from_secs(60), Duration::from_millis(50));
        let t = slow.mint("s").await;
        let late = slow.receive(&t.ticket, None, half()).await.unwrap_err();
        assert!(matches!(&late, ReceiveError::Body(_)), "{late:?}");
        assert_eq!(slow.held().bytes, 0);
    }

    // A request that is abandoned — its future dropped while the body is
    // still arriving — stops nothing by going: the extraction is the
    // thread's, and ends when the body does, cleaning up after itself. The
    // file an earlier version could leave behind has nowhere to come from.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_abandoned_upload_leaves_nothing_behind() {
        let (_dir, uploads) = store(limits(1 << 20, 1 << 20));
        let uploads = impatient(uploads, Duration::from_millis(200), Duration::from_secs(60));
        let mut archive = bundle(50_000);
        archive.truncate(archive.len() / 2);
        let t = uploads.mint("s").await;
        let body = Stalled { head: std::io::Cursor::new(archive) };
        {
            let receiving = uploads.receive(&t.ticket, None, body);
            tokio::pin!(receiving);
            let abandoned = tokio::time::timeout(Duration::from_millis(50), &mut receiving).await;
            assert!(abandoned.is_err(), "still arriving");
            assert_eq!(uploads.held().receiving, 1);
            assert_eq!(uploads.held().bytes, 1 << 20, "the most it may come to is held for it");
            // While it arrives, the session has no second upload.
            assert_eq!(put(&uploads, "s", bundle(1)).await.unwrap_err(), ReceiveError::Busy);
        }
        // The body ends (here, by stalling); the thread cleans up.
        for _ in 0..100 {
            if uploads.held().receiving == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(uploads.held(), Held { bytes: 0, max_bytes: 3 << 20, uploads: 0, receiving: 0 });
        assert_eq!(kept(&uploads), 0);
    }

    // Uploads from a process that has gone: no ticket or session of this one
    // can deploy them, so a new store starts from an empty directory — of
    // what a store names its own, and nothing else.
    #[tokio::test]
    async fn a_new_store_removes_the_bundles_an_earlier_one_left() {
        let dir = tempfile::tempdir().unwrap();
        let at = dir.path().join("uploads");
        let earlier = Uploads::new(at.clone(), limits(1 << 20, 1 << 20));
        put(&earlier, "s", bundle(10)).await.unwrap();
        // What an earlier version kept, and something that is not the store's.
        std::fs::write(at.join(format!("{}.tar.gz", "a".repeat(64))), "an archive").unwrap();
        std::fs::write(at.join("notes.txt"), "not an upload").unwrap();
        assert_eq!(kept(&earlier), 3);

        let later = Uploads::new(at.clone(), limits(1 << 20, 1 << 20));
        assert_eq!(kept(&later), 1);
        assert!(at.join("notes.txt").exists());
    }

    /// Make `upload_id` one that lapsed a second ago, and say where it is.
    fn lapse(uploads: &Uploads, upload_id: &str) -> PathBuf {
        let mut state = uploads.inner.state();
        let upload = state.uploads.get_mut(upload_id).unwrap();
        upload.expires = Instant::now() - Duration::from_secs(1);
        upload.dir.clone()
    }

    // A sweep stops holding what has lapsed at once, and removes it off the
    // lock, on a thread that may block: the bundle and its bytes go together,
    // when it has been removed.
    #[tokio::test]
    async fn a_sweep_removes_an_expired_upload_and_its_bytes() {
        let (_dir, uploads) = store(limits(1 << 20, 1 << 20));
        let received = put(&uploads, "s", bundle(10)).await.unwrap();
        let bundle_dir = lapse(&uploads, &received.upload_id);
        assert!(bundle_dir.is_dir());
        uploads.sweep();
        assert_eq!(uploads.held().uploads, 0);
        let gone = uploads.take(&received.upload_id, "s").await.unwrap_err();
        assert_eq!(gone, TakeError::NoSuchUpload);
        for _ in 0..100 {
            if uploads.held().bytes == 0 {
                break;
            }
            // Charged for as long as it is there.
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!bundle_dir.exists());
        assert_eq!(uploads.held(), Held { bytes: 0, max_bytes: 3 << 20, uploads: 0, receiving: 0 });
    }

    // With no runtime to lend a thread, the sweep removes what has lapsed
    // itself, before it returns.
    #[test]
    fn a_sweep_off_a_runtime_removes_what_lapsed_before_it_returns() {
        let (_dir, uploads) = store(limits(1 << 20, 1 << 20));
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let received = runtime.block_on(put(&uploads, "s", bundle(10))).unwrap();
        let bundle_dir = lapse(&uploads, &received.upload_id);
        uploads.sweep();
        assert!(!bundle_dir.exists());
        assert_eq!(uploads.held().bytes, 0);
    }

    // A bundle that has lapsed is room for an arrival and for a deploy, as
    // it was when it was removed under the lock: it is gone before either
    // is let on, and its bytes with it.
    #[tokio::test]
    async fn what_has_lapsed_is_room_for_an_arrival_and_for_a_deploy() {
        let dir = tempfile::tempdir().unwrap();
        // One may come to ten of the smallest, `U`, and the store holds
        // eleven.
        let uploads =
            Uploads::with_budget(dir.path().join("uploads"), limits(1 << 20, 10 * U), 11 * U);
        let waiting = put(&uploads, "a", bundle(1)).await.unwrap();
        let large = put(&uploads, "b", bundle(2 * 4096)).await.unwrap();
        assert!(extracted(2 * 4096) > U);

        // A deploy of `a`'s grows to ten: with `b`'s held there is no room.
        let no_room = uploads.take(&waiting.upload_id, "a").await.unwrap_err();
        assert_eq!(no_room, TakeError::NoRoom);
        // Lapsed, `b`'s is room, and gone by the time the deploy has its
        // bundle.
        let lapsed = lapse(&uploads, &large.upload_id);
        let running = uploads.take(&waiting.upload_id, "a").await.unwrap();
        assert!(!lapsed.exists());
        assert_eq!(uploads.held().bytes, 10 * U);
        drop(running);

        // The same for an arrival, which reserves ten: two waiting bundles
        // leave it no room, and one of them lapsed does.
        let first = put(&uploads, "c", bundle(1)).await.unwrap();
        put(&uploads, "d", bundle(1)).await.unwrap();
        assert_eq!(put(&uploads, "e", bundle(1)).await.unwrap_err(), ReceiveError::Full);
        // (The ticket first: minting sweeps too, and what a sweep finds
        // that is not making way for its own call stays charged until a
        // thread has removed it.)
        let t = uploads.mint("e").await;
        let lapsed = lapse(&uploads, &first.upload_id);
        uploads.receive(&t.ticket, None, std::io::Cursor::new(bundle(1))).await.unwrap();
        assert!(!lapsed.exists());
        assert_eq!(uploads.held().bytes, 2 * U);
    }

    // A store's directory that was there already, open to other users, is
    // made the server's user's alone, as one the store makes is — when the
    // store is made, and again at an upload should it have been opened
    // since. Under a directory others can write to, a bundle could be
    // swapped for another tree before its deploy.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_directory_that_was_there_already_is_made_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let at = dir.path().join("uploads");
        let open = || {
            std::fs::set_permissions(&at, std::fs::Permissions::from_mode(0o777)).unwrap();
        };
        let mode = || std::fs::metadata(&at).unwrap().permissions().mode() & 0o777;
        std::fs::create_dir(&at).unwrap();
        open();
        assert_eq!(mode(), 0o777);

        let uploads = Uploads::new(at.clone(), limits(1 << 20, 1 << 20));
        assert_eq!(mode(), 0o700);
        open();
        put(&uploads, "s", bundle(1)).await.unwrap();
        assert_eq!(mode(), 0o700);
    }
}
