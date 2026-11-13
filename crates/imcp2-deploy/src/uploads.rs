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

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};

/// The default cap on an uploaded archive, in bytes: a real bundle is a
/// manifest, a few modules and a frontend's assets, well inside this.
pub const DEFAULT_MAX_UPLOAD_BYTES: usize = 64 * 1024 * 1024;
/// How long a ticket is good for: minutes, enough to run one `curl`.
pub const TICKET_TTL: Duration = Duration::from_secs(5 * 60);
/// How long an upload waits for its deploy to begin.
pub const UPLOAD_TTL: Duration = Duration::from_secs(15 * 60);
/// The request header a `PUT` presents its ticket in — a header rather than
/// the path, so the ticket stays out of a proxy's access log.
pub const TICKET_HEADER: &str = "x-deploy-upload-ticket";

/// The store: a directory of received archives and the tickets and uploads
/// outstanding. Cheap to clone; one per server.
#[derive(Clone)]
pub struct Uploads {
    inner: Arc<Inner>,
}

struct Inner {
    dir: PathBuf,
    max_bytes: usize,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    tickets: HashMap<String, Ticket>,
    uploads: HashMap<String, Upload>,
}

struct Ticket {
    session: String,
    expires: Instant,
}

struct Upload {
    session: String,
    path: PathBuf,
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
    /// The body could not be read, or the file not written.
    Io(String),
}

impl std::fmt::Display for ReceiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiveError::UnknownTicket => f.write_str(
                "unknown, used or expired upload ticket; call icp_deploy_upload for a new one",
            ),
            ReceiveError::TooLarge(max) => write!(f, "the archive is over the {max}-byte limit"),
            ReceiveError::Io(e) => write!(f, "could not receive the archive: {e}"),
        }
    }
}

/// An upload handed to its deploy: the archive's path, and the file's removal
/// when this is dropped, whichever way the deploy ends.
#[derive(Debug)]
pub struct TakenUpload {
    path: PathBuf,
}

impl TakenUpload {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TakenUpload {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Uploads {
    /// A store writing its archives under `dir` (made now, readable by the
    /// server's user alone), each at most `max_bytes`. The directory is
    /// canonicalized: a relative `dir` is resolved against the working
    /// directory here, so the path of a received archive is absolute, as the
    /// deploy that reads it requires. Should the directory not be makable
    /// now, it is tried again at each upload, which reports the failure.
    pub fn new(dir: PathBuf, max_bytes: usize) -> Self {
        let dir = make_private_dir(&dir)
            .and_then(|()| dir.canonicalize())
            .or_else(|_| std::path::absolute(&dir))
            .unwrap_or(dir);
        Self { inner: Arc::new(Inner { dir, max_bytes, state: Mutex::default() }) }
    }

    pub fn max_bytes(&self) -> usize {
        self.inner.max_bytes
    }

    /// Mint a ticket for `session`, dropping any it already holds.
    pub async fn mint(&self, session: &str) -> Minted {
        let mut state = self.inner.state.lock().await;
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
    /// length over the cap is refused unread, and the body is streamed to a
    /// file up to the cap and no further.
    pub async fn receive(
        &self,
        ticket: &str,
        declared_len: Option<u64>,
        mut body: impl AsyncRead + Unpin,
    ) -> Result<Received, ReceiveError> {
        let max = self.inner.max_bytes;
        let session = {
            let mut state = self.inner.state.lock().await;
            sweep(&mut state);
            match state.tickets.remove(ticket) {
                Some(ticket) => ticket.session,
                None => {
                    tracing::info!("upload refused: no such ticket (spent, expired or unknown)");
                    return Err(ReceiveError::UnknownTicket);
                }
            }
        };
        if declared_len.is_some_and(|len| len > max as u64) {
            tracing::warn!(session, ?declared_len, max, "upload refused: declared too large");
            return Err(ReceiveError::TooLarge(max));
        }
        make_private_dir(&self.inner.dir).map_err(|e| ReceiveError::Io(e.to_string()))?;
        let upload_id = random_token();
        let path = self.inner.dir.join(format!("{upload_id}.tar.gz"));
        let received = write_up_to(&path, &mut body, max).await;
        let bytes = match received {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(session, %e, "upload failed");
                let _ = tokio::fs::remove_file(&path).await;
                return Err(e);
            }
        };
        let mut state = self.inner.state.lock().await;
        state.uploads.insert(
            upload_id.clone(),
            Upload { session: session.clone(), path, expires: Instant::now() + UPLOAD_TTL },
        );
        tracing::info!(session, upload_id, bytes, "bundle uploaded");
        Ok(Received { upload_id, bytes, expires_in: UPLOAD_TTL })
    }

    /// Hand `upload_id` to its deploy, if `session` is the one that uploaded
    /// it: the archive's path, removed when the returned handle drops.
    pub async fn take(&self, upload_id: &str, session: &str) -> Option<TakenUpload> {
        let mut state = self.inner.state.lock().await;
        sweep(&mut state);
        let owned = state.uploads.get(upload_id).is_some_and(|u| u.session == session);
        if !owned {
            tracing::info!(session, upload_id, "no such upload for the session");
            return None;
        }
        tracing::info!(session, upload_id, "upload taken by a deploy");
        state.uploads.remove(upload_id).map(|u| TakenUpload { path: u.path })
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
    let mut file = options.open(path).await.map_err(|e| ReceiveError::Io(e.to_string()))?;
    let mut total = 0usize;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = body.read(&mut buf).await.map_err(|e| ReceiveError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        total += n;
        if total > max {
            return Err(ReceiveError::TooLarge(max));
        }
        file.write_all(&buf[..n]).await.map_err(|e| ReceiveError::Io(e.to_string()))?;
    }
    file.flush().await.map_err(|e| ReceiveError::Io(e.to_string()))?;
    Ok(total)
}

/// Drop expired tickets, and expired uploads with their files.
fn sweep(state: &mut State) {
    let now = Instant::now();
    state.tickets.retain(|_, t| t.expires > now);
    let expired: Vec<String> =
        state.uploads.iter().filter(|(_, u)| u.expires <= now).map(|(id, _)| id.clone()).collect();
    for id in expired {
        if let Some(upload) = state.uploads.remove(&id) {
            let _ = std::fs::remove_file(&upload.path);
        }
    }
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
}
