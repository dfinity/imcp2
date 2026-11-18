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
//!   * the body is streamed to disk under the cap, a declared length over the
//!     cap refused unread, so a ticket flood costs a lookup each.
//!
//! An upload is held for [`UPLOAD_TTL`] for its deploy to begin; the deploy
//! that takes it removes it, and one never taken is swept at expiry. Each
//! archive is a file of its own under the store's directory, readable by the
//! server's user alone.
//!
//! What the store may hold is bounded, whatever a session does with its
//! tickets:
//!
//!   * a session has one upload at a time: a `PUT` while another of the
//!     session's is still arriving is refused, and one that begins replaces
//!     the archive the session was holding;
//!   * every archive — arriving, held, or with its deploy — counts against
//!     one budget for the whole store, reserved before a byte of the body is
//!     read (the declared length, or the cap when none is declared) and
//!     settled to the size that arrived; past the budget a `PUT` is refused;
//!   * an archive whose `PUT` is abandoned mid-body goes with the request,
//!     and its reservation with it;
//!   * the directory is the store's own: what an earlier process left in it
//!     is removed when the store is made, since nothing could deploy it.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

/// The default cap on an uploaded archive, in bytes: a real bundle is a
/// manifest, a few modules and a frontend's assets, well inside this.
pub const DEFAULT_MAX_UPLOAD_BYTES: usize = 64 * 1024 * 1024;
/// The default budget for every archive a store has at once, as a multiple
/// of its per-archive cap.
pub const DEFAULT_STORED_UPLOADS: usize = 8;
/// How long a ticket is good for: minutes, enough to run one `curl`.
pub const TICKET_TTL: Duration = Duration::from_secs(5 * 60);
/// How long an upload waits for its deploy to begin.
pub const UPLOAD_TTL: Duration = Duration::from_secs(15 * 60);
/// The request header a `PUT` presents its ticket in — a header rather than
/// the path, so the ticket stays out of a proxy's access log.
pub const TICKET_HEADER: &str = "x-deploy-upload-ticket";
/// What an archive's file is named after its id.
const ARCHIVE_SUFFIX: &str = ".tar.gz";

/// The store: a directory of received archives and the tickets and uploads
/// outstanding. Cheap to clone; one per directory, shared by every endpoint
/// of the process that receives into it.
#[derive(Clone)]
pub struct Uploads {
    inner: Arc<Inner>,
}

struct Inner {
    dir: PathBuf,
    max_bytes: usize,
    max_total_bytes: u64,
    state: Mutex<State>,
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
    /// What counts against the budget: the reservation of each archive
    /// arriving, and the size of each held or with its deploy.
    bytes: u64,
}

struct Ticket {
    session: String,
    expires: Instant,
}

struct Upload {
    session: String,
    path: PathBuf,
    bytes: u64,
    expires: Instant,
}

/// A ticket just minted, and how long it is good for.
#[derive(Debug)]
pub struct Minted {
    pub ticket: String,
    pub expires_in: Duration,
}

/// An archive just received: the id its deploy names, its size, and how long
/// the store holds it.
#[derive(Debug)]
pub struct Received {
    pub upload_id: String,
    pub bytes: usize,
    pub expires_in: Duration,
}

/// Why a `PUT` was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum ReceiveError {
    /// No such ticket, or one already used or expired.
    UnknownTicket,
    /// The body is over the cap (the value); nothing is kept.
    TooLarge(usize),
    /// Another upload of the session's is still arriving.
    Busy,
    /// The store is holding as much as it may, across every session.
    Full,
    /// The body could not be read: the client's side of the transfer.
    Body(String),
    /// The archive could not be stored (the directory not made, the file not
    /// written): the server's fault, not the request's.
    Storage(String),
}

impl std::fmt::Display for ReceiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiveError::UnknownTicket => f.write_str(
                "unknown, used or expired upload ticket; call icp_deploy_upload for a new one",
            ),
            ReceiveError::TooLarge(max) => write!(f, "the archive is over the {max}-byte limit"),
            ReceiveError::Busy => f.write_str(
                "another upload for this session is still arriving; wait for it to finish, \
                 then call icp_deploy_upload for a new ticket",
            ),
            ReceiveError::Full => f.write_str(
                "this server is holding as many uploaded bundles as it can right now; call \
                 icp_deploy_upload for a new ticket and try again in a few minutes",
            ),
            ReceiveError::Body(e) => write!(f, "could not read the archive: {e}"),
            ReceiveError::Storage(e) => write!(f, "could not store the archive: {e}"),
        }
    }
}

/// An upload handed to its deploy: the archive's path, and the file's removal
/// — with its share of the store's budget — when this is dropped, whichever
/// way the deploy ends.
pub struct TakenUpload {
    path: PathBuf,
    bytes: u64,
    store: Arc<Inner>,
}

impl TakenUpload {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl std::fmt::Debug for TakenUpload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TakenUpload").field("path", &self.path).finish_non_exhaustive()
    }
}

impl Drop for TakenUpload {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let mut state = self.store.state();
        state.bytes = state.bytes.saturating_sub(self.bytes);
    }
}

/// An archive arriving: the session's one `PUT`, its file and its
/// reservation. Dropped before [`Self::finish`] — the body failed, or the
/// request was abandoned and its future dropped mid-read — it takes the
/// partial file and the reservation with it.
struct Receiving {
    store: Arc<Inner>,
    session: String,
    path: PathBuf,
    reserved: u64,
    finished: bool,
}

impl Receiving {
    /// The archive arrived whole, `bytes` of it: hold it for its deploy.
    fn finish(mut self, upload_id: &str, bytes: u64) {
        let mut state = self.store.state();
        state.receiving.remove(&self.session);
        state.bytes = state.bytes.saturating_sub(self.reserved) + bytes;
        state.uploads.insert(
            upload_id.to_string(),
            Upload {
                session: self.session.clone(),
                path: self.path.clone(),
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
        let _ = std::fs::remove_file(&self.path);
        let mut state = self.store.state();
        state.receiving.remove(&self.session);
        state.bytes = state.bytes.saturating_sub(self.reserved);
    }
}

impl Uploads {
    /// A store writing its archives under `dir`, each at most `max_bytes`
    /// and [`DEFAULT_STORED_UPLOADS`] times that in all; see
    /// [`Self::with_budget`].
    pub fn new(dir: PathBuf, max_bytes: usize) -> Self {
        Self::with_budget(dir, max_bytes, max_bytes.saturating_mul(DEFAULT_STORED_UPLOADS))
    }

    /// A store writing its archives under `dir` (made now, readable by the
    /// server's user alone), each at most `max_bytes` and `max_total_bytes`
    /// in all (at least one archive's worth). The directory is
    /// canonicalized: a relative `dir` is resolved against the working
    /// directory here, so the path of a received archive is absolute, as the
    /// deploy that reads it requires. Should the directory not be makable
    /// now, it is tried again at each upload, which reports the failure.
    ///
    /// The directory is this store's alone, one store per process: archives
    /// already in it were received by a process that has gone, with the
    /// tickets and sessions they belonged to, so they are removed here.
    pub fn with_budget(dir: PathBuf, max_bytes: usize, max_total_bytes: usize) -> Self {
        let dir = make_private_dir(&dir)
            .and_then(|()| dir.canonicalize())
            .or_else(|_| std::path::absolute(&dir))
            .unwrap_or(dir);
        let left = remove_archives(&dir);
        if left > 0 {
            tracing::info!(dir = %dir.display(), left, "removed uploads an earlier run left");
        }
        let max_total_bytes = max_total_bytes.max(max_bytes) as u64;
        Self { inner: Arc::new(Inner { dir, max_bytes, max_total_bytes, state: Mutex::default() }) }
    }

    pub fn max_bytes(&self) -> usize {
        self.inner.max_bytes
    }

    /// Drop expired tickets, and expired uploads with their files. Every
    /// operation does this first; a server calls it on a timer as well, so
    /// an idle store does not hold what has lapsed.
    pub fn sweep(&self) {
        sweep(&mut self.inner.state());
    }

    /// Mint a ticket for `session`, dropping any it already holds.
    pub async fn mint(&self, session: &str) -> Minted {
        let mut state = self.inner.state();
        sweep(&mut state);
        state.tickets.retain(|_, t| t.session != session);
        let ticket = random_token();
        state.tickets.insert(
            ticket.clone(),
            Ticket { session: session.to_string(), expires: Instant::now() + TICKET_TTL },
        );
        tracing::info!(session, "upload ticket minted");
        Minted { ticket, expires_in: TICKET_TTL }
    }

    /// Receive an archive on `ticket`: the ticket is spent first, a declared
    /// length over the cap is refused unread, room is reserved for it (see
    /// the module docs), and the body is streamed to a file up to what was
    /// reserved and no further.
    pub async fn receive(
        &self,
        ticket: &str,
        declared_len: Option<u64>,
        mut body: impl AsyncRead + Unpin,
    ) -> Result<Received, ReceiveError> {
        let max = self.inner.max_bytes;
        let upload_id = random_token();
        let receiving = {
            let mut state = self.inner.state();
            sweep(&mut state);
            let Some(Ticket { session, .. }) = state.tickets.remove(ticket) else {
                tracing::info!("upload refused: no such ticket (spent, expired or unknown)");
                return Err(ReceiveError::UnknownTicket);
            };
            if declared_len.is_some_and(|len| len > max as u64) {
                tracing::warn!(session, ?declared_len, max, "upload refused: declared too large");
                return Err(ReceiveError::TooLarge(max));
            }
            if state.receiving.contains(&session) {
                tracing::warn!(session, "upload refused: another is arriving for the session");
                return Err(ReceiveError::Busy);
            }
            // The archive the session was holding gives way to this one.
            let replaced: Vec<String> = state
                .uploads
                .iter()
                .filter(|(_, u)| u.session == session)
                .map(|(id, _)| id.clone())
                .collect();
            for id in replaced {
                remove_upload(&mut state, &id);
            }
            let reserved = declared_len.unwrap_or(max as u64);
            if state.bytes + reserved > self.inner.max_total_bytes {
                tracing::warn!(session, held = state.bytes, "upload refused: the store is full");
                return Err(ReceiveError::Full);
            }
            state.bytes += reserved;
            state.receiving.insert(session.clone());
            Receiving {
                store: self.inner.clone(),
                session,
                path: self.inner.dir.join(format!("{upload_id}{ARCHIVE_SUFFIX}")),
                reserved,
                finished: false,
            }
        };
        let session = receiving.session.clone();
        make_private_dir(&self.inner.dir).map_err(|e| {
            tracing::error!(session, %e, "upload failed: the upload directory cannot be made");
            ReceiveError::Storage(e.to_string())
        })?;
        // `reserved` fits a usize: it is at most the cap.
        let limit = receiving.reserved as usize;
        let bytes = match write_up_to(&receiving.path, &mut body, limit).await {
            Ok(bytes) => bytes,
            // Past a declared length that was itself within the cap.
            Err(ReceiveError::TooLarge(_)) if limit < max => {
                tracing::warn!(session, limit, "upload failed: longer than its declared length");
                return Err(ReceiveError::Body(format!(
                    "the body is longer than the {limit} bytes it declared"
                )));
            }
            Err(e) => {
                tracing::warn!(session, %e, "upload failed");
                return Err(e);
            }
        };
        receiving.finish(&upload_id, bytes as u64);
        tracing::info!(session, upload_id, bytes, "bundle uploaded");
        Ok(Received { upload_id, bytes, expires_in: UPLOAD_TTL })
    }

    /// Hand `upload_id` to its deploy, if `session` is the one that uploaded
    /// it: the archive's path, removed when the returned handle drops.
    pub async fn take(&self, upload_id: &str, session: &str) -> Option<TakenUpload> {
        let mut state = self.inner.state();
        sweep(&mut state);
        let owned = state.uploads.get(upload_id).is_some_and(|u| u.session == session);
        if !owned {
            tracing::info!(session, upload_id, "no such upload for the session");
            return None;
        }
        tracing::info!(session, upload_id, "upload taken by a deploy");
        // Its bytes stay counted until the handle drops, with the file.
        state.uploads.remove(upload_id).map(|u| TakenUpload {
            path: u.path,
            bytes: u.bytes,
            store: self.inner.clone(),
        })
    }
}

/// Write `body` to a new file at `path`, readable by the owner alone, refusing
/// — and reading no further — once more than `max` bytes have arrived.
async fn write_up_to(
    path: &Path,
    body: &mut (impl AsyncRead + Unpin),
    max: usize,
) -> Result<usize, ReceiveError> {
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).await.map_err(|e| ReceiveError::Storage(e.to_string()))?;
    let mut total = 0usize;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = body.read(&mut buf).await.map_err(|e| ReceiveError::Body(e.to_string()))?;
        if n == 0 {
            break;
        }
        total += n;
        if total > max {
            return Err(ReceiveError::TooLarge(max));
        }
        file.write_all(&buf[..n]).await.map_err(|e| ReceiveError::Storage(e.to_string()))?;
    }
    file.flush().await.map_err(|e| ReceiveError::Storage(e.to_string()))?;
    Ok(total)
}

/// Drop expired tickets, and expired uploads with their files.
fn sweep(state: &mut State) {
    let now = Instant::now();
    state.tickets.retain(|_, t| t.expires > now);
    let expired: Vec<String> =
        state.uploads.iter().filter(|(_, u)| u.expires <= now).map(|(id, _)| id.clone()).collect();
    for id in expired {
        remove_upload(state, &id);
    }
}

/// Forget a held upload: its file, and its share of the budget.
fn remove_upload(state: &mut State, upload_id: &str) {
    if let Some(upload) = state.uploads.remove(upload_id) {
        let _ = std::fs::remove_file(&upload.path);
        state.bytes = state.bytes.saturating_sub(upload.bytes);
    }
}

/// Remove every archive file directly under `dir` — what a store names its
/// files, and nothing else — and say how many there were.
fn remove_archives(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| {
            let name = entry.file_name();
            let is_archive = name.to_str().is_some_and(|n| {
                n.strip_suffix(ARCHIVE_SUFFIX)
                    .is_some_and(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
            });
            is_archive
                && entry.file_type().is_ok_and(|t| t.is_file())
                && std::fs::remove_file(entry.path()).is_ok()
        })
        .count()
}

/// `dir`, created if missing, and on Unix readable by its owner alone.
fn make_private_dir(dir: &Path) -> std::io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)
}

/// 256 random bits, hex-encoded: a ticket or an upload id.
fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("the OS random source to be available");
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(max: usize) -> (tempfile::TempDir, Uploads) {
        let dir = tempfile::tempdir().unwrap();
        let uploads = Uploads::new(dir.path().join("uploads"), max);
        (dir, uploads)
    }

    // A store given a relative directory (a server started with a relative
    // state directory) hands out absolute paths: the deploy that reads an
    // upload takes no other kind.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_received_archive_has_an_absolute_path() {
        let dir = tempfile::tempdir().unwrap();
        // The directory spelled relative to the working directory: up to the
        // root, then down to it.
        let cwd = std::env::current_dir().unwrap();
        let mut relative = PathBuf::new();
        relative.extend(cwd.components().skip(1).map(|_| ".."));
        relative.push(dir.path().strip_prefix("/").unwrap());
        assert!(relative.is_relative(), "{}", relative.display());
        let uploads = Uploads::new(relative.join("uploads"), 1024);
        let minted = uploads.mint("sess").await;
        let received = uploads
            .receive(&minted.ticket, None, std::io::Cursor::new(b"x".to_vec()))
            .await
            .unwrap();
        let taken = uploads.take(&received.upload_id, "sess").await.unwrap();
        assert!(taken.path().is_absolute(), "{}", taken.path().display());
        assert!(taken.path().starts_with(dir.path().canonicalize().unwrap()));
        assert_eq!(std::fs::read(taken.path()).unwrap(), b"x");
    }

    #[tokio::test]
    async fn a_ticket_receives_one_archive_for_its_session_alone() {
        let (_dir, uploads) = store(1024);
        let minted = uploads.mint("sess-a").await;
        assert_eq!(minted.ticket.len(), 64);

        let received = uploads
            .receive(&minted.ticket, Some(5), std::io::Cursor::new(b"hello".to_vec()))
            .await
            .unwrap();
        assert_eq!(received.bytes, 5);
        // Spent: a second PUT on the same ticket is refused.
        let again = uploads.receive(&minted.ticket, None, std::io::Cursor::new(Vec::new())).await;
        assert_eq!(again.unwrap_err(), ReceiveError::UnknownTicket);

        // Another session cannot take it; the owner can, once.
        assert!(uploads.take(&received.upload_id, "sess-b").await.is_none());
        let taken = uploads.take(&received.upload_id, "sess-a").await.expect("owner takes it");
        assert_eq!(std::fs::read(taken.path()).unwrap(), b"hello");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(taken.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "mode {mode:o}");
        }
        assert!(uploads.take(&received.upload_id, "sess-a").await.is_none());
        let path = taken.path().to_path_buf();
        drop(taken);
        assert!(!path.exists(), "the archive goes with the handle");
    }

    #[tokio::test]
    async fn an_archive_over_the_cap_is_refused_and_nothing_kept() {
        let (dir, uploads) = store(16);
        // Declared over the cap: refused unread.
        let t = uploads.mint("s").await;
        let err = uploads.receive(&t.ticket, Some(17), std::io::Cursor::new(vec![0; 17])).await;
        assert_eq!(err.unwrap_err(), ReceiveError::TooLarge(16));
        // Undeclared and over the cap: refused once the cap is passed, the
        // partial file removed.
        let t = uploads.mint("s").await;
        let err = uploads.receive(&t.ticket, None, std::io::Cursor::new(vec![0; 17])).await;
        assert_eq!(err.unwrap_err(), ReceiveError::TooLarge(16));
        let kept = std::fs::read_dir(dir.path().join("uploads")).unwrap().count();
        assert_eq!(kept, 0, "nothing is kept of a refused upload");
        // Exactly at the cap passes.
        let t = uploads.mint("s").await;
        let ok = uploads.receive(&t.ticket, None, std::io::Cursor::new(vec![0; 16])).await.unwrap();
        assert_eq!(ok.bytes, 16);
    }

    #[tokio::test]
    async fn minting_again_drops_the_previous_ticket_and_unknown_tickets_cost_nothing() {
        let (dir, uploads) = store(1024);
        let first = uploads.mint("s").await;
        let second = uploads.mint("s").await;
        let err = uploads.receive(&first.ticket, None, std::io::Cursor::new(vec![1])).await;
        assert_eq!(err.unwrap_err(), ReceiveError::UnknownTicket);
        let err = uploads.receive("not-a-ticket", None, std::io::Cursor::new(vec![1])).await;
        assert_eq!(err.unwrap_err(), ReceiveError::UnknownTicket);
        let kept = std::fs::read_dir(dir.path().join("uploads")).unwrap().count();
        assert_eq!(kept, 0, "nothing is written for a refusal");
        assert!(uploads.receive(&second.ticket, None, std::io::Cursor::new(vec![1])).await.is_ok());
    }

    /// A body that fails to arrive is the request's failure; a file that
    /// cannot be written is the server's. The two are told apart, so a full
    /// disk is not reported to the client as a bad request.
    #[cfg(unix)]
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
        let (dir, uploads) = store(1024);
        let t = uploads.mint("s").await;
        let err = uploads.receive(&t.ticket, None, Broken).await.unwrap_err();
        assert!(matches!(err, ReceiveError::Body(_)), "{err:?}");
        let kept = std::fs::read_dir(dir.path().join("uploads")).unwrap().count();
        assert_eq!(kept, 0, "nothing is kept of an upload that did not arrive");

        // The directory gone and its parent a file: nothing can be stored.
        let t = uploads.mint("s").await;
        std::fs::remove_dir_all(dir.path().join("uploads")).unwrap();
        std::fs::write(dir.path().join("uploads"), b"in the way").unwrap();
        let err = uploads.receive(&t.ticket, None, std::io::Cursor::new(vec![1])).await;
        assert!(matches!(err, Err(ReceiveError::Storage(_))), "{err:?}");
    }

    // One session, however many tickets it mints, has one archive in the
    // store: a new upload replaces the one it was holding.
    #[tokio::test]
    async fn a_new_upload_replaces_the_one_the_session_was_holding() {
        let (dir, uploads) = store(1024);
        let mut first = None;
        for _ in 0..5 {
            let t = uploads.mint("s").await;
            let r = uploads.receive(&t.ticket, None, std::io::Cursor::new(vec![7; 9])).await;
            first.get_or_insert(r.unwrap().upload_id);
        }
        let kept = std::fs::read_dir(dir.path().join("uploads")).unwrap().count();
        assert_eq!(kept, 1, "one archive per session");
        assert!(uploads.take(&first.unwrap(), "s").await.is_none(), "the first was replaced");
        assert_eq!(uploads.inner.state().bytes, 9);
    }

    // The budget is the whole store's: reserved before the body is read, by
    // the declared length or else the cap, settled to what arrived, and
    // given back when an archive leaves — expired, replaced, or deployed.
    #[tokio::test]
    async fn the_store_refuses_past_its_budget_and_takes_again_once_there_is_room() {
        let dir = tempfile::tempdir().unwrap();
        let uploads = Uploads::with_budget(dir.path().join("uploads"), 10, 25);
        let put = |session: &'static str, declared: Option<u64>, len: usize| {
            let uploads = uploads.clone();
            async move {
                let t = uploads.mint(session).await;
                uploads.receive(&t.ticket, declared, std::io::Cursor::new(vec![0; len])).await
            }
        };
        // Undeclared: the cap is reserved, and settled to the 4 that came.
        let a = put("a", None, 4).await.unwrap();
        assert_eq!(uploads.inner.state().bytes, 4);
        let _b = put("b", Some(10), 10).await.unwrap();
        // 14 held: an undeclared body would reserve 10 more, and fits.
        let _c = put("c", None, 10).await.unwrap();
        assert_eq!(uploads.inner.state().bytes, 24);
        // Full, whoever asks and whatever they declare beyond the room left.
        assert_eq!(put("d", Some(2), 2).await.unwrap_err(), ReceiveError::Full);
        assert_eq!(put("d", None, 1).await.unwrap_err(), ReceiveError::Full);
        assert!(put("d", Some(1), 1).await.is_ok());
        // A deploy's archive counts until the deploy lets go of it.
        let taken = uploads.take(&a.upload_id, "a").await.unwrap();
        assert_eq!(put("e", Some(4), 4).await.unwrap_err(), ReceiveError::Full);
        drop(taken);
        assert!(put("e", Some(4), 4).await.is_ok());
    }

    // A body longer than the length it declared is cut off at that length:
    // the reservation is what the store agreed to hold.
    #[tokio::test]
    async fn a_body_longer_than_it_declared_is_refused() {
        let (dir, uploads) = store(1024);
        let t = uploads.mint("s").await;
        let err = uploads.receive(&t.ticket, Some(3), std::io::Cursor::new(vec![0; 9])).await;
        assert!(matches!(err, Err(ReceiveError::Body(_))), "{err:?}");
        let kept = std::fs::read_dir(dir.path().join("uploads")).unwrap().count();
        assert_eq!(kept, 0);
        assert_eq!(uploads.inner.state().bytes, 0);
    }

    // A `PUT` abandoned mid-body — its future dropped — leaves nothing: not
    // the partial file, not the reservation, not the session's turn. And
    // while it is arriving, the session's second `PUT` is refused.
    #[tokio::test]
    async fn an_abandoned_upload_leaves_nothing_behind() {
        /// Yields one byte, then never completes.
        struct Stalls(bool);
        impl AsyncRead for Stalls {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                if std::mem::replace(&mut self.0, true) {
                    return std::task::Poll::Pending;
                }
                buf.put_slice(b"x");
                std::task::Poll::Ready(Ok(()))
            }
        }
        let (dir, uploads) = store(1024);
        let files = || std::fs::read_dir(dir.path().join("uploads")).unwrap().count();
        let first = uploads.mint("s").await;
        let arriving = {
            let uploads = uploads.clone();
            tokio::spawn(async move { uploads.receive(&first.ticket, None, Stalls(false)).await })
        };
        // Wait for the first to be under way.
        while files() == 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(uploads.inner.state().bytes, 1024, "the cap is reserved");
        let second = uploads.mint("s").await;
        let err = uploads.receive(&second.ticket, None, std::io::Cursor::new(vec![1])).await;
        assert_eq!(err.unwrap_err(), ReceiveError::Busy);
        // Another session is not held up by it.
        let other = uploads.mint("t").await;
        assert!(uploads
            .receive(&other.ticket, Some(1), std::io::Cursor::new(vec![1]))
            .await
            .is_ok());

        arriving.abort();
        assert!(arriving.await.unwrap_err().is_cancelled());
        assert_eq!(files(), 1, "the partial file went with the request");
        assert_eq!(uploads.inner.state().bytes, 1, "and so did its reservation");
        let third = uploads.mint("s").await;
        assert!(uploads.receive(&third.ticket, None, std::io::Cursor::new(vec![1])).await.is_ok());
    }

    // A store is made over a directory an earlier process may have left
    // archives in: nothing knows them any more, so they go — and only they.
    #[tokio::test]
    async fn a_new_store_removes_the_archives_an_earlier_one_left() {
        let (dir, uploads) = store(1024);
        let t = uploads.mint("s").await;
        uploads.receive(&t.ticket, None, std::io::Cursor::new(vec![1])).await.unwrap();
        let into = dir.path().join("uploads");
        std::fs::write(into.join("notes.txt"), b"not an archive").unwrap();
        drop(uploads);
        assert_eq!(std::fs::read_dir(&into).unwrap().count(), 2);

        let _again = Uploads::new(into.clone(), 1024);
        let left: Vec<_> =
            std::fs::read_dir(&into).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(left, ["notes.txt"], "{left:?}");
    }

    // The timer's sweep drops what has lapsed without an upload to prompt it.
    #[tokio::test]
    async fn a_sweep_removes_an_expired_upload_and_its_bytes() {
        let (dir, uploads) = store(1024);
        let t = uploads.mint("s").await;
        let r = uploads.receive(&t.ticket, None, std::io::Cursor::new(vec![1; 5])).await.unwrap();
        uploads.sweep();
        assert_eq!(uploads.inner.state().bytes, 5, "not yet expired");
        uploads.inner.state().uploads.get_mut(&r.upload_id).unwrap().expires = Instant::now();
        uploads.sweep();
        assert_eq!(uploads.inner.state().bytes, 0);
        assert_eq!(std::fs::read_dir(dir.path().join("uploads")).unwrap().count(), 0);
    }
}
