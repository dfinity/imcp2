//! The [`Host`] a bundle is deployed from: the project library's seams, each
//! implemented for an extracted bundle in a scratch directory.
//!
//! A bundle is the self-contained archive `icp project bundle` writes: the
//! project manifest rewritten so every canister is a pre-built wasm the
//! archive carries, the networks and environments inlined, and each sync
//! plugin's wasm and input files alongside. That shape is what makes the seams
//! small: nothing is built from source, no wasm is fetched over HTTP, no
//! recipe is resolved, and the only network a bundle targets from here is the
//! Internet Computer itself.
//!
//! The archive is untrusted input: it arrives in a tool call, and the agent
//! that passes it may have fetched it from anywhere. So the shape is not
//! assumed but enforced, in three places:
//!
//! * **Extraction** writes only regular files and directories, within a total
//!   size budget, under the scratch directory — and keeps the list of what it
//!   wrote ([`extract_bundle`]).
//! * **The filesystem the library reads through is that list**, not the disk
//!   ([`BundleFs`]). A path the manifest names is normalized against the
//!   bundle root (`..` cannot climb above it, an absolute path is re-anchored
//!   at it) and looked up in the index; only a path the archive carried is
//!   read, from where extraction put it. Nothing on the machine is reachable
//!   by any spelling. The disk is the byte store because the sync-plugin
//!   runtime needs real paths to mount.
//! * **The bundle is checked before any phase runs** ([`check_bundle`]): every
//!   canister built by one pre-built wasm in the archive that hashes to its
//!   recorded checksum, every sync plugin in the archive, no script steps
//!   (which the library would run as host subprocesses; [`NoScripts`] refuses
//!   them again at the seams, as a backstop), and no network but `ic`.
//!
//! Everything the project library reads or writes — the manifest, the wasms,
//! the `.icp` id and artifact stores, the build scratch — lives under the
//! extracted directory, which is removed when the deploy ends.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::Read,
    ops::Bound,
    sync::{Arc, Mutex, PoisonError},
};

use async_trait::async_trait;
use camino::{Utf8Component, Utf8Path, Utf8PathBuf};
use icp_events::StepReporter;
use icp_project::{
    canister::{
        build::{Build, BuildError, Builder, Params as BuildParams},
        recipe::{Fetched, Resolve, ResolveError},
        sync::{
            script::{ScriptInvocation, ScriptRunError, ScriptRunner},
            Syncer,
        },
        wasm::{Fetch, FetchError},
    },
    files::{FileSystem, FsError, Scratch},
    host::{Host, Ignore},
    manifest::{
        prebuilt::SourceField, BuildStep, ProjectRootLocate, ProjectRootLocateImpl, SyncStep,
        PROJECT_MANIFEST,
    },
    network::{
        Access, AccessError, CollectFriendlyDomains, Configuration, NetworkAccess, NetworkUrls,
        RootKeySource, RootKeySpec,
    },
    prelude::{IC, IC_MAINNET_NETWORK_API_URL, IC_ROOT_KEY},
    random::HostRandom,
    store_artifact::ArtifactStore,
    store_id::AccessImpl,
    Canister, Lazy, Network, Project, ProjectLoadImpl,
};
use sha2::{Digest, Sha256};

/// Archives above this are refused before anything is written: a bundle rides
/// in a tool call (or a file the call names), and a runaway input must not
/// fill the disk or the heap.
pub const MAX_BUNDLE_BYTES: usize = 256 * 1024 * 1024;

/// What an archive may extract to, in total. Gzip expands by up to about a
/// thousand to one, so the archive limit alone bounds nothing on disk; this
/// one does, on the sum of the entries' sizes and on the decompressed stream
/// itself.
pub const MAX_EXTRACTED_BYTES: u64 = 1024 * 1024 * 1024;

/// The directory under the project root where icp-project keeps its own
/// state (`.icp/data/mappings/<env>.ids.json`, build artifacts). The deploy
/// seeds it from the caller's mapping; the archive may not supply it.
const STATE_DIR: &str = ".icp";

/// The most entries an archive may hold. The byte budget alone would admit
/// millions of empty files, each a path in the index the loader walks; a
/// real bundle is a manifest, a few modules and plugins, and a frontend's
/// assets, well inside this.
pub const MAX_BUNDLE_ENTRIES: usize = 250_000;

/// The most a gzip-compressed module may expand to: 100 MiB, the IC's own
/// ceiling on a module. The library gunzips a module in memory to read its
/// Candid interface, with no bound of its own, so the bound is applied here
/// before a deploy runs.
pub const MAX_WASM_BYTES: u64 = 100 * 1024 * 1024;

/// A plain error for the seams below: each carries one sentence, and the
/// library wraps it whole at its own boundary (`AccessError::new` and the
/// like), so the sentence is what the user reads.
#[derive(Debug)]
pub struct Unsupported(pub String);

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Unsupported {}

// ── The network ───────────────────────────────────────────────────────────

/// Network resolution for a bundle: the Internet Computer, and nothing else.
///
/// A bundle's manifest inlines its networks, and a manifest may declare any:
/// a managed one the icp CLI would launch, a connected one with a root key to
/// fetch or a key spelled out — or one that claims the mainnet root key over
/// an endpoint of its choosing, which would send the user's signed calls
/// wherever it points. This server deploys to mainnet only, so the one
/// network honoured is the reserved `ic`: the project loader supplies it with
/// the mainnet endpoint and the pinned root key, and refuses a manifest that
/// redeclares the name. [`check_bundle`] refuses the rest before any phase
/// runs; this is the seam's own refusal, for the library's own calls.
pub struct IcMainnet;

impl IcMainnet {
    /// The connected configuration of `network`, if it is the reserved `ic`
    /// network as the loader supplies it: that name, the mainnet endpoint and
    /// the mainnet root key.
    pub fn mainnet(network: &Network) -> Result<&icp_project::network::Connected, Unsupported> {
        let refuse = || {
            Unsupported(format!(
                "network '{}' is not the Internet Computer; this server deploys to the `ic` \
                 network only. Deploy to the `ic` environment, or deploy elsewhere with `icp \
                 deploy`",
                network.name
            ))
        };
        if network.name != IC {
            return Err(refuse());
        }
        match &network.configuration {
            Configuration::Connected { connected }
                if matches!(connected.root_key, RootKeySpec::Mainnet)
                    && connected.api_url.as_str().trim_end_matches('/')
                        == IC_MAINNET_NETWORK_API_URL =>
            {
                Ok(connected)
            }
            _ => Err(refuse()),
        }
    }
}

#[async_trait]
impl Access for IcMainnet {
    async fn access(&self, network: &Network) -> Result<NetworkAccess, AccessError> {
        let connected = Self::mainnet(network).map_err(AccessError::new)?;
        Ok(NetworkAccess {
            root_key: IC_ROOT_KEY.to_vec(),
            root_key_source: RootKeySource::Mainnet,
            api_url: connected.api_url.clone(),
            http_gateway_url: connected.http_gateway_url.clone(),
            use_friendly_domains: false,
        })
    }

    async fn urls(&self, network: &Network) -> Result<NetworkUrls, AccessError> {
        let connected = Self::mainnet(network).map_err(AccessError::new)?;
        Ok(NetworkUrls {
            api_url: connected.api_url.clone(),
            http_gateway_url: connected.http_gateway_url.clone(),
        })
    }

    /// Friendly domains are a managed-network convenience; there is no
    /// managed network here to publish them to.
    async fn publish_friendly_domains(
        &self,
        _network: &Network,
        _collect: &CollectFriendlyDomains<'_>,
    ) {
    }
}

// ── The filesystem ────────────────────────────────────────────────────────

/// The extracted bundle, as the filesystem the project library reads through.
///
/// What the archive carried is an index of relative paths, filled in by
/// [`extract_bundle`] as it writes each entry. Every path the library asks
/// about is [normalized](BundleFs::normalize) against the bundle root and
/// answered from that index: present, it is read from under the root; absent,
/// it is "not in the bundle", whatever the disk holds at that spelling. So a
/// manifest's `path:` — absolute, climbing, or plain — can name only what the
/// archive brought with it.
///
/// The one place a write may land is a scratch directory this filesystem made
/// (a pre-built build step copies its module there and the operation reads it
/// back); written files join the index and leave it with the directory.
#[derive(Clone, Debug)]
pub struct BundleFs(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    /// Canonical, so the absolute paths the library derives from it strip
    /// back to the index's relative spellings whatever the scratch directory's
    /// own path goes through.
    root: Utf8PathBuf,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    /// Every file in the bundle, relative to the root.
    files: BTreeSet<Utf8PathBuf>,
    /// Scratch directories currently held, relative to the root: the prefixes
    /// a write is allowed under.
    scratch: BTreeSet<Utf8PathBuf>,
}

impl Inner {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl State {
    /// The entries of `set` strictly under `rel`. A path set orders by
    /// component, so a directory's descendants sit right after it: one
    /// range lookup, then take while the prefix holds, never a scan.
    fn under<'a>(
        set: &'a BTreeSet<Utf8PathBuf>,
        rel: &'a Utf8Path,
    ) -> impl Iterator<Item = &'a Utf8PathBuf> + 'a {
        set.range::<Utf8Path, _>((Bound::Excluded(rel), Bound::Unbounded))
            .take_while(move |p| p.starts_with(rel))
    }

    fn is_dir(&self, rel: &Utf8Path) -> bool {
        rel.as_str().is_empty()
            || self.scratch.contains(rel)
            || Self::under(&self.files, rel).next().is_some()
            || Self::under(&self.scratch, rel).next().is_some()
    }

    fn in_scratch(&self, rel: &Utf8Path) -> bool {
        rel.ancestors().skip(1).any(|a| self.scratch.contains(a))
    }
}

/// Why the bundle could not serve a request. Wrapped in [`FsError`] at the
/// trait boundary, which displays it as itself.
#[derive(Debug)]
pub enum BundleFsError {
    NotInBundle(Utf8PathBuf),
    ReadOnly(Utf8PathBuf),
    Io(Utf8PathBuf, std::io::Error),
}

impl fmt::Display for BundleFsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInBundle(p) => write!(
                f,
                "'{p}' is not in the bundle; a bundle carries every file its manifest names \
                 (`icp project bundle` writes one that does)"
            ),
            Self::ReadOnly(p) => write!(f, "cannot write '{p}': a bundle is read-only"),
            Self::Io(p, e) => write!(f, "'{p}': {e}"),
        }
    }
}

impl std::error::Error for BundleFsError {}

impl From<BundleFsError> for FsError {
    fn from(e: BundleFsError) -> Self {
        FsError::new(e)
    }
}

impl BundleFs {
    /// An empty filesystem rooted at `dir`, which must exist.
    pub fn new(dir: &Utf8Path) -> Result<Self, String> {
        let root = std::fs::canonicalize(dir)
            .map_err(|e| format!("cannot resolve '{dir}': {e}"))
            .and_then(|p| {
            Utf8PathBuf::from_path_buf(p).map_err(|p| format!("'{}' is not UTF-8", p.display()))
        })?;
        Ok(Self(Arc::new(Inner { root, state: Mutex::default() })))
    }

    /// The directory the bundle is extracted into.
    pub fn root(&self) -> &Utf8Path {
        &self.0.root
    }

    /// Record a file extraction wrote, by its path in the archive.
    fn index(&self, archive_path: &Utf8Path) {
        self.0.state().files.insert(self.normalize(archive_path));
    }

    /// Resolve `path` to the relative spelling the index is keyed by: under
    /// the root, with `.` dropped and `..` applied but never climbing above the
    /// root, and an absolute path from elsewhere re-anchored at the root (so
    /// it names what the bundle would hold there, which is nothing).
    pub fn normalize(&self, path: &Utf8Path) -> Utf8PathBuf {
        let path = path.strip_prefix(&self.0.root).unwrap_or(path);
        let mut out = Utf8PathBuf::new();
        for component in path.components() {
            match component {
                Utf8Component::Normal(part) => out.push(part),
                Utf8Component::ParentDir => {
                    out.pop();
                }
                Utf8Component::CurDir | Utf8Component::RootDir | Utf8Component::Prefix(_) => {}
            }
        }
        out
    }

    /// Whether `dir` is spelled under the bundle root without climbing: the
    /// root itself or a descendant, by path alone. A spelling that
    /// normalizes into the root but is not written under it (`/etc`,
    /// `<root>/../x`) is not held, because a reader that takes the spelling
    /// as a host path would leave the bundle.
    pub fn holds_dir(&self, dir: &Utf8Path) -> bool {
        match dir.strip_prefix(&self.0.root) {
            Ok(rest) => rest
                .components()
                .all(|c| matches!(c, Utf8Component::Normal(_) | Utf8Component::CurDir)),
            Err(_) => false,
        }
    }

    /// Whether the bundle holds a file at `path`.
    pub fn contains(&self, path: &Utf8Path) -> bool {
        self.0.state().files.contains(&self.normalize(path))
    }

    /// Where a file in the bundle is on disk, for a runtime that needs a real
    /// path, or "not in the bundle".
    pub fn locate(&self, path: &Utf8Path) -> Result<Utf8PathBuf, BundleFsError> {
        let rel = self.normalize(path);
        if self.0.state().files.contains(&rel) {
            Ok(self.0.root.join(rel))
        } else {
            Err(BundleFsError::NotInBundle(rel))
        }
    }

    fn read_bytes(&self, path: &Utf8Path) -> Result<Vec<u8>, BundleFsError> {
        let on_disk = self.locate(path)?;
        std::fs::read(&on_disk).map_err(|e| BundleFsError::Io(self.normalize(path), e))
    }

    fn write_bytes(&self, path: &Utf8Path, contents: &[u8]) -> Result<(), BundleFsError> {
        let rel = self.normalize(path);
        let mut state = self.0.state();
        if !state.in_scratch(&rel) {
            return Err(BundleFsError::ReadOnly(rel));
        }
        let on_disk = self.0.root.join(&rel);
        if let Some(parent) = on_disk.parent() {
            std::fs::create_dir_all(parent).map_err(|e| BundleFsError::Io(rel.clone(), e))?;
        }
        std::fs::write(&on_disk, contents).map_err(|e| BundleFsError::Io(rel.clone(), e))?;
        state.files.insert(rel);
        Ok(())
    }
}

/// A scratch directory under the root: on disk for as long as this is held,
/// and in the index for exactly as long.
struct ScratchDir {
    _dir: tempfile::TempDir,
    rel: Utf8PathBuf,
    path: Utf8PathBuf,
    fs: Arc<Inner>,
}

impl Scratch for ScratchDir {
    fn path(&self) -> &Utf8Path {
        &self.path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let mut state = self.fs.state();
        state.scratch.remove(&self.rel);
        state.files.retain(|f| !f.starts_with(&self.rel));
    }
}

#[async_trait]
impl FileSystem for BundleFs {
    async fn read(&self, path: &Utf8Path) -> Result<Vec<u8>, FsError> {
        Ok(self.read_bytes(path)?)
    }

    async fn read_to_string(&self, path: &Utf8Path) -> Result<String, FsError> {
        let bytes = self.read_bytes(path)?;
        String::from_utf8(bytes).map_err(|e| {
            FsError::new(BundleFsError::Io(self.normalize(path), std::io::Error::other(e)))
        })
    }

    async fn write(&self, path: &Utf8Path, contents: &[u8]) -> Result<(), FsError> {
        Ok(self.write_bytes(path, contents)?)
    }

    /// A directory is implied by the files beneath it, so in a scratch area
    /// there is nothing to create; anywhere else there is nothing that may be.
    async fn create_dir_all(&self, path: &Utf8Path) -> Result<(), FsError> {
        let rel = self.normalize(path);
        let state = self.0.state();
        if state.scratch.contains(&rel) || state.in_scratch(&rel) {
            return Ok(());
        }
        Err(BundleFsError::ReadOnly(rel).into())
    }

    async fn copy(&self, from: &Utf8Path, to: &Utf8Path) -> Result<(), FsError> {
        let contents = self.read_bytes(from)?;
        Ok(self.write_bytes(to, &contents)?)
    }

    async fn exists(&self, path: &Utf8Path) -> bool {
        let rel = self.normalize(path);
        let state = self.0.state();
        state.files.contains(&rel) || state.is_dir(&rel)
    }

    async fn is_file(&self, path: &Utf8Path) -> bool {
        self.contains(path)
    }

    async fn is_dir(&self, path: &Utf8Path) -> bool {
        self.0.state().is_dir(&self.normalize(path))
    }

    async fn read_dir(&self, path: &Utf8Path) -> Result<Vec<Utf8PathBuf>, FsError> {
        let prefix = self.normalize(path);
        let state = self.0.state();
        let mut children: Vec<Utf8PathBuf> = State::under(&state.files, &prefix)
            .chain(State::under(&state.scratch, &prefix))
            .filter_map(|entry| entry.strip_prefix(&prefix).ok())
            .filter_map(|relative| relative.components().next())
            .map(|first| self.0.root.join(&prefix).join(first.as_str()))
            .collect();
        children.sort();
        children.dedup();
        Ok(children)
    }

    /// Nothing in the bundle is a symlink and every path is normalized on the
    /// way in, so identity is the normalized path, under the root.
    async fn canonicalize(&self, path: &Utf8Path) -> Option<Utf8PathBuf> {
        let rel = self.normalize(path);
        self.exists(&rel).await.then(|| self.0.root.join(rel))
    }

    async fn scratch_dir(&self) -> Result<Box<dyn Scratch>, FsError> {
        let dir = tempfile::Builder::new()
            .prefix(".scratch-")
            .tempdir_in(&self.0.root)
            .map_err(|e| FsError::new(BundleFsError::Io(".scratch".into(), e)))?;
        let path = Utf8PathBuf::from_path_buf(dir.path().to_path_buf())
            .map_err(|p| FsError::new(Unsupported(format!("'{}' is not UTF-8", p.display()))))?;
        let rel = self.normalize(&path);
        self.0.state().scratch.insert(rel.clone());
        Ok(Box::new(ScratchDir { _dir: dir, rel, path, fs: self.0.clone() }))
    }
}

// ── Wasms, recipes, scripts ───────────────────────────────────────────────

/// Wasm resolution for a bundle: the archive carries every module it names,
/// so a source is a path inside the bundle (verified against its recorded
/// checksum) and a remote one is a bundle this tool does not understand.
pub struct BundledWasm(pub BundleFs);

#[async_trait]
impl Fetch for BundledWasm {
    async fn wasm(
        &self,
        source: &SourceField,
        base_dir: &Utf8Path,
        sha256: Option<&str>,
        reporter: &StepReporter,
    ) -> Result<Utf8PathBuf, FetchError> {
        match source {
            SourceField::Local(local) => {
                let path = base_dir.join(&local.path);
                let on_disk = self.0.locate(&path).map_err(FetchError::new)?;
                if let Some(expected) = sha256 {
                    reporter.info(format!("Reading wasm: {}", local.path));
                    let bytes = self.0.read_bytes(&path).map_err(FetchError::new)?;
                    reporter.info("Verifying checksum");
                    verify_checksum(&self.0.normalize(&path), expected, &bytes)
                        .map_err(FetchError::new)?;
                }
                Ok(on_disk)
            }
            SourceField::Remote(_) => Err(FetchError::new(Unsupported(
                "a bundle carries every wasm it names, so a remote wasm source is not \
                 expected here; rebuild the bundle with `icp project bundle`"
                    .into(),
            ))),
        }
    }
}

fn verify_checksum(path: &Utf8Path, expected: &str, bytes: &[u8]) -> Result<(), Unsupported> {
    let actual = hex::encode(Sha256::digest(bytes));
    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(Unsupported(format!(
            "checksum mismatch for '{path}': the manifest records {expected}, the file hashes \
             to {actual}"
        )))
    }
}

/// Hold a gzip-compressed module to `limit` bytes expanded, by streaming it
/// through a bounded decoder into nothing. A module that is not gzip passes
/// as it is: its size is its own.
fn gunzipped_within(path: &Utf8Path, bytes: &[u8], limit: u64) -> Result<(), Unsupported> {
    if !bytes.starts_with(&[0x1f, 0x8b]) {
        return Ok(());
    }
    let mut decoder = Limited { inner: flate2::read::GzDecoder::new(bytes), left: limit };
    match std::io::copy(&mut decoder, &mut std::io::sink()) {
        Ok(_) => Ok(()),
        Err(_) => Err(Unsupported(format!(
            "the gzip-compressed wasm '{path}' expands past {limit} bytes, the most a module \
             can be, or is not valid gzip"
        ))),
    }
}

/// Recipe resolution for a bundle: a bundled manifest spells every canister
/// out as explicit pre-built steps, so a recipe reference means the archive
/// is not a bundle.
pub struct NoRecipes;

#[async_trait]
impl Resolve for NoRecipes {
    async fn resolve(
        &self,
        recipe: &icp_project::manifest::recipe::Recipe,
    ) -> Result<Fetched, ResolveError> {
        Err(ResolveError::new(Unsupported(format!(
            "the manifest references recipe '{recipe:?}', which a bundle never does; rebuild \
             it with `icp project bundle`"
        ))))
    }
}

/// Build and sync for a bundle: pre-built steps and plugin steps run as they
/// do under the CLI, script steps are refused.
///
/// [`check_bundle`] catches a script step before any phase runs; this is the
/// backstop at the seam the library would run one through, so a step the
/// check missed still cannot reach a shell.
pub struct NoScripts {
    prebuilt: Builder,
}

impl NoScripts {
    fn script_refused(what: &str) -> Unsupported {
        Unsupported(format!(
            "the manifest declares a script {what} step, which a bundle never has and this \
             server does not run; rebuild the bundle with `icp project bundle`"
        ))
    }
}

#[async_trait]
impl Build for NoScripts {
    async fn build(
        &self,
        step: &BuildStep,
        params: &BuildParams,
        reporter: &StepReporter,
    ) -> Result<(), BuildError> {
        match step {
            BuildStep::Prebuilt(_) => self.prebuilt.build(step, params, reporter).await,
            BuildStep::Script(_) => Err(BuildError::new(Self::script_refused("build"))),
        }
    }
}

#[async_trait]
impl ScriptRunner for NoScripts {
    async fn run_script(
        &self,
        _invocation: ScriptInvocation,
        _reporter: &StepReporter,
    ) -> Result<Vec<String>, ScriptRunError> {
        Err(ScriptRunError { source: Box::new(Self::script_refused("sync")) })
    }
}

// ── The check, the host, the extraction ───────────────────────────────────

/// Hold an environment's canisters to the shape a bundle has — before any
/// phase runs, so a bundle that would fail at its build or sync phase, or
/// be refused there, does not first spend cycles creating canisters.
///
/// Each canister lives in a directory under the bundle root, and is built by
/// exactly one pre-built step naming a wasm in the archive that hashes to the
/// checksum the manifest records; each sync step is a plugin in the archive
/// (hashing to its checksum, if one is recorded); no step is a script. The
/// environment's network is the Internet Computer.
///
/// Canister names must also differ by more than letter case: the library's
/// artifact store keys a canister's build output by its name on disk, and
/// a case-insensitive volume (macOS and Windows by default) would hand the
/// last-built module to both.
///
/// The directory check matters because not every reader goes through
/// [`BundleFs`]: the sync-plugin runtime takes the canister directory as a
/// host path and confines a plugin's declared files to the project directory
/// only when the canister's lies inside it — a canister directory outside the
/// project is its own sandbox root. A manifest may spell a canister's path
/// absolutely, and the bundle can carry the `canister.yaml` the loader looks
/// for at that spelling, so the directory must be held to the root here.
pub fn check_bundle<'a>(
    fs: &BundleFs,
    network: &Network,
    canisters: impl IntoIterator<Item = (&'a Utf8Path, &'a Canister)>,
) -> Result<(), String> {
    IcMainnet::mainnet(network).map_err(|e| e.0)?;
    let canisters: Vec<_> = canisters.into_iter().collect();
    let mut by_folded: BTreeMap<String, &str> = BTreeMap::new();
    for (_, canister) in &canisters {
        if let Some(other) = by_folded.insert(canister.name.to_lowercase(), &canister.name) {
            if other != canister.name {
                return Err(format!(
                    "canisters '{other}' and '{}' differ only in letter case; the build artifact \
                     store keys files by canister name, which a case-insensitive disk would merge",
                    canister.name
                ));
            }
        }
    }
    for (dir, canister) in canisters {
        let name = &canister.name;
        let at = |e: Unsupported| format!("canister '{name}': {e}");
        if !fs.holds_dir(dir) {
            return Err(at(Unsupported(format!(
                "its directory '{dir}' is not under the bundle root; a bundle's canisters live \
                 under its root, which is where `icp project bundle` puts them"
            ))));
        }
        let present = |path: &Utf8Path| -> Result<Vec<u8>, String> {
            fs.read_bytes(&dir.join(path)).map_err(|e| format!("canister '{name}': {e}"))
        };

        if canister.build.steps.iter().any(|s| matches!(s, BuildStep::Script(_))) {
            return Err(at(NoScripts::script_refused("build")));
        }
        if canister.sync.steps.iter().any(|s| matches!(s, SyncStep::Script(_))) {
            return Err(at(NoScripts::script_refused("sync")));
        }
        let [BuildStep::Prebuilt(adapter)] = canister.build.steps.as_slice() else {
            return Err(at(Unsupported(format!(
                "built by {} steps where a bundle has exactly one pre-built step; rebuild the \
                 bundle with `icp project bundle`",
                canister.build.steps.len()
            ))));
        };
        let SourceField::Local(local) = &adapter.source else {
            return Err(at(Unsupported(
                "built from a remote wasm source, which a bundle never is; rebuild the bundle \
                 with `icp project bundle`"
                    .into(),
            )));
        };
        let wasm = present(&local.path)?;
        let Some(expected) = adapter.sha256.as_deref() else {
            return Err(at(Unsupported(format!(
                "the wasm '{}' carries no sha256, which a bundle always records; rebuild the \
                 bundle with `icp project bundle`",
                local.path
            ))));
        };
        verify_checksum(&local.path, expected, &wasm).map_err(at)?;
        gunzipped_within(&local.path, &wasm, MAX_WASM_BYTES).map_err(at)?;

        for step in &canister.sync.steps {
            let SyncStep::Plugin(plugin) = step else { continue };
            let SourceField::Local(local) = &plugin.source else {
                return Err(at(Unsupported(
                    "synced by a remote plugin, which a bundle never is; rebuild the bundle \
                     with `icp project bundle`"
                        .into(),
                )));
            };
            let bytes = present(&local.path)?;
            if let Some(expected) = plugin.sha256.as_deref() {
                verify_checksum(&local.path, expected, &bytes).map_err(at)?;
            }
        }
    }
    Ok(())
}

/// The host for the bundle extracted into `fs`: its manifest is the project,
/// its `.icp` directory the id and artifact stores, and nothing outside it is
/// reachable.
pub fn host_for(fs: BundleFs) -> Host {
    // The directory IS the project root: no climbing to a workspace above it.
    let root = fs.root().to_path_buf();
    let locate: Arc<dyn ProjectRootLocate> =
        Arc::new(ProjectRootLocateImpl::new(root.clone(), Some(root)));
    let files: Arc<dyn FileSystem> = Arc::new(fs.clone());
    let wasm: Arc<dyn Fetch> = Arc::new(BundledWasm(fs));
    let project = Lazy::<_, Project>::new(ProjectLoadImpl {
        project_root_locate: locate.clone(),
        recipe: Arc::new(NoRecipes),
        files: files.clone(),
    });
    let no_scripts = Arc::new(NoScripts { prebuilt: Builder::new(wasm.clone(), files.clone()) });
    Host {
        project: Arc::new(project),
        files,
        ids: Arc::new(AccessImpl::new(locate.clone())),
        artifacts: Arc::new(ArtifactStore::new(locate)),
        builder: no_scripts.clone(),
        syncer: Arc::new(Syncer::new(
            no_scripts,
            wasm.clone(),
            Arc::new(icp_sync_plugin::Wasmtime),
        )),
        wasm,
        network: Arc::new(IcMainnet),
        random: Arc::new(HostRandom),
        observer: Arc::new(Ignore),
    }
}

/// Extract a bundle archive into `into`, which must exist and be empty, and
/// return it as a filesystem indexed by what was written.
///
/// Only regular files and directories are written — `icp project bundle`
/// writes nothing else, and a symlink or a device node is how an archive
/// reaches past its directory — and their sizes may not add up to more than
/// [`MAX_EXTRACTED_BYTES`]. `tar` refuses entry paths that would land outside
/// `into`. What it extracts is then required to look like a bundle, i.e. to
/// carry a project manifest at its root.
pub fn extract_bundle(bytes: &[u8], into: &Utf8Path) -> Result<BundleFs, String> {
    extract_bundle_within(bytes, into, MAX_BUNDLE_ENTRIES)
}

/// [`extract_bundle`] with the entry cap as a parameter, so a test can reach
/// it without writing a quarter of a million files.
fn extract_bundle_within(
    bytes: &[u8],
    into: &Utf8Path,
    max_entries: usize,
) -> Result<BundleFs, String> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(format!(
            "the bundle is {} bytes, above the {} byte limit",
            bytes.len(),
            MAX_BUNDLE_BYTES
        ));
    }
    let fs = BundleFs::new(into)?;
    let unreadable =
        |e: std::io::Error| format!("the bundle is not a readable .tar.gz archive: {e}");
    let decoder = Limited { inner: flate2::read::GzDecoder::new(bytes), left: MAX_EXTRACTED_BYTES };
    let mut archive = tar::Archive::new(decoder);
    let mut total: u64 = 0;
    let mut entries: usize = 0;
    for entry in archive.entries().map_err(unreadable)? {
        let mut entry = entry.map_err(unreadable)?;
        entries += 1;
        if entries > max_entries {
            return Err(format!(
                "the bundle holds more than {max_entries} entries, more than a bundle ever has"
            ));
        }
        let kind = entry.header().entry_type();
        let path = entry.path().map_err(unreadable)?.into_owned();
        let path = Utf8PathBuf::from_path_buf(path)
            .map_err(|p| format!("the archive entry '{}' is not UTF-8", p.display()))?;
        if !(kind.is_file() || kind.is_dir()) {
            return Err(format!(
                "the archive entry '{path}' is not a regular file or directory ({kind:?}), which \
                 a bundle never carries; rebuild it with `icp project bundle`"
            ));
        }
        // `.icp` is the library's own state under the project root: the id
        // mappings a deploy reads to decide what exists, and the artifact
        // store. A bundle never carries it (`icp project bundle` writes
        // manifests, modules, plugins, argument files and images), and one
        // that did could point a deploy at canisters the caller never named.
        // Compared without regard to case: on a case-insensitive disk `.ICP`
        // is the same directory.
        if fs
            .normalize(&path)
            .components()
            .next()
            .is_some_and(|c| c.as_str().eq_ignore_ascii_case(STATE_DIR))
        {
            return Err(format!(
                "the archive entry '{path}' is under `{STATE_DIR}/`, the project state a bundle \
                 never carries; rebuild it with `icp project bundle`"
            ));
        }
        total = total.saturating_add(entry.size());
        if total > MAX_EXTRACTED_BYTES {
            return Err(too_large());
        }
        if entry.unpack_in(fs.root().as_std_path()).map_err(unreadable)? && kind.is_file() {
            fs.index(&path);
        }
    }
    if !fs.contains(Utf8Path::new(PROJECT_MANIFEST)) {
        return Err(format!(
            "the archive carries no `{PROJECT_MANIFEST}` at its root, so it is not an icp \
             project bundle (`icp project bundle` writes one)"
        ));
    }
    Ok(fs)
}

fn too_large() -> String {
    format!("the bundle extracts to more than the {MAX_EXTRACTED_BYTES} byte limit")
}

/// A reader that fails once more than `left` bytes have passed through it:
/// the decompressed stream's own bound, independent of what the entry
/// headers claim.
struct Limited<R> {
    inner: R,
    left: u64,
}

impl<R: Read> Read for Limited<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n as u64 > self.left {
            return Err(std::io::Error::other(too_large()));
        }
        self.left -= n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use icp_project::network::{Connected, Managed};
    use std::io::Write;

    fn managed(name: &str) -> Network {
        Network {
            name: name.into(),
            configuration: Configuration::Managed { managed: Managed::default() },
        }
    }

    fn connected(name: &str, root_key: RootKeySpec) -> Network {
        Network {
            name: name.into(),
            configuration: Configuration::Connected {
                connected: Connected {
                    api_url: "https://icp-api.io".parse().unwrap(),
                    http_gateway_url: Some("https://icp.net".parse().unwrap()),
                    root_key,
                },
            },
        }
    }

    /// A gzipped tar of the given entries, each a regular file.
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
        archive.into_inner().unwrap().finish().unwrap()
    }

    fn scratch() -> (tempfile::TempDir, Utf8PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        (dir, path)
    }

    // Only the Internet Computer: a bundle built for `local` names a managed
    // network, a testnet a connected one with a fetched key; both are refused
    // with the way out, not deep inside the deploy.
    #[tokio::test]
    async fn only_the_ic_network_is_served() {
        // A manifest may declare a network of any name, and it may claim the
        // mainnet root key over an endpoint of its own: refused, like a
        // network to be launched or one whose key would be fetched. So is
        // the reserved name over another endpoint, should a loader ever let
        // that through.
        let mut elsewhere = connected("mainnet2", RootKeySpec::Mainnet);
        let Configuration::Connected { connected: config } = &mut elsewhere.configuration else {
            unreachable!()
        };
        config.api_url = "http://127.0.0.1:4943".parse().unwrap();
        let mut ic_elsewhere = elsewhere.clone();
        ic_elsewhere.name = "ic".into();
        for network in [
            managed("local"),
            connected("testnet", RootKeySpec::Fetch),
            connected("mainnet2", RootKeySpec::Mainnet),
            elsewhere,
            ic_elsewhere,
        ] {
            let err = match IcMainnet.urls(&network).await {
                Err(e) => e.to_string(),
                Ok(_) => panic!("{} must be refused", network.name),
            };
            assert!(err.contains("not the Internet Computer"), "{err}");
            assert!(err.contains("`ic`"), "{err}");
            assert!(IcMainnet.access(&network).await.is_err());
        }
    }

    // The mainnet root key is pinned, never fetched: a bundle for `ic`
    // resolves without touching the network.
    #[tokio::test]
    async fn the_ic_network_resolves_to_the_pinned_root_key() {
        let access = IcMainnet.access(&connected("ic", RootKeySpec::Mainnet)).await.unwrap();
        assert_eq!(access.root_key, IC_ROOT_KEY.to_vec());
        assert_eq!(access.root_key_source, RootKeySource::Mainnet);
        assert_eq!(access.api_url.as_str(), "https://icp-api.io/");
    }

    #[test]
    fn an_archive_without_a_manifest_is_not_a_bundle() {
        let (_dir, into) = scratch();
        let err = extract_bundle(&archive(&[("README", b"hello")]), &into).unwrap_err();
        assert!(err.contains(PROJECT_MANIFEST), "{err}");
    }

    #[test]
    fn garbage_is_not_an_archive() {
        let (_dir, into) = scratch();
        let err = extract_bundle(b"not a tarball", &into).unwrap_err();
        assert!(err.contains("not a readable"), "{err}");
    }

    #[test]
    fn oversized_bundles_are_refused_before_extraction() {
        let (_dir, into) = scratch();
        let big = vec![0u8; MAX_BUNDLE_BYTES + 1];
        let err = extract_bundle(&big, &into).unwrap_err();
        assert!(err.contains("limit"), "{err}");
    }

    // A small archive can claim a huge file: the entry's size is what tar
    // writes (as a hole, if the data is not there), so the budget is checked
    // against the sizes before anything is written.
    #[test]
    fn an_archive_that_extracts_past_the_budget_is_refused() {
        let (_dir, into) = scratch();
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        let mut header = tar::Header::new_gnu();
        header.set_path("huge").unwrap();
        header.set_size(MAX_EXTRACTED_BYTES + 1);
        header.set_mode(0o644);
        header.set_cksum();
        // Only the header is appended: the claimed data never follows.
        archive.get_mut().write_all(header.as_bytes()).unwrap();
        let bytes = archive.into_inner().unwrap().finish().unwrap();
        let err = extract_bundle(&bytes, &into).unwrap_err();
        assert!(err.contains("extracts to more than"), "{err}");
        assert!(!into.join("huge").exists());
    }

    // A symlink is how an archive reaches past its directory; a bundle
    // carries none, so one is refused rather than written — which is what
    // lets the index below trust that every path under the root is a file
    // extraction wrote.
    #[test]
    fn an_archive_with_a_symlink_is_refused() {
        let (_dir, into) = scratch();
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_cksum();
        archive.append_link(&mut header, "icp.yaml", "/etc/passwd").unwrap();
        let bytes = archive.into_inner().unwrap().finish().unwrap();
        let err = extract_bundle(&bytes, &into).unwrap_err();
        assert!(err.contains("not a regular file or directory"), "{err}");
        assert!(!into.join("icp.yaml").exists());
    }

    #[test]
    fn an_archive_carrying_project_state_is_refused() {
        let (_dir, into) = scratch();
        let bytes = archive(&[
            ("icp.yaml", b"canisters: []"),
            (".icp/data/mappings/ic.ids.json", b"{\"backend\": \"aaaaa-aa\"}"),
        ]);
        let err = extract_bundle(&bytes, &into).unwrap_err();
        assert!(err.contains("`.icp/`"), "{err}");
        assert!(!into.join(".icp").exists());

        // Spelled `.ICP/`: the same directory on a case-insensitive disk.
        let (_dir, into) = scratch();
        let bytes = archive(&[
            ("icp.yaml", b"canisters: []"),
            (".ICP/data/mappings/ic.ids.json", b"{\"backend\": \"aaaaa-aa\"}"),
        ]);
        let err = extract_bundle(&bytes, &into).unwrap_err();
        assert!(err.contains("`.icp/`"), "{err}");
        assert!(!into.join(".ICP").exists());

        // The same entry spelled `./.icp/...`: the archive path's first
        // component is `.`, extraction writes it into `.icp/` all the same.
        let (_dir, into) = scratch();
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        let data: &[u8] = b"{\"backend\": \"aaaaa-aa\"}";
        let mut header = tar::Header::new_gnu();
        header.set_path("./.icp/data/mappings/ic.ids.json").unwrap();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append(&header, data).unwrap();
        let bytes = archive.into_inner().unwrap().finish().unwrap();
        let err = extract_bundle(&bytes, &into).unwrap_err();
        assert!(err.contains("`.icp/`"), "{err}");
        assert!(!into.join(".icp").exists());
    }

    #[test]
    fn an_archive_with_too_many_entries_is_refused() {
        let (_dir, into) = scratch();
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        for i in 0..=8 {
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(&mut header, format!("f/{i}"), &b""[..]).unwrap();
        }
        let bytes = archive.into_inner().unwrap().finish().unwrap();
        let err = extract_bundle_within(&bytes, &into, 8).unwrap_err();
        assert!(err.contains("more than 8 entries"), "{err}");
        let err = extract_bundle_within(&bytes, &into, 9).unwrap_err();
        assert!(err.contains(PROJECT_MANIFEST), "{err}");
    }

    // A gzip-compressed module is bounded by what it expands to, read
    // through a bounded decoder; a plain module passes as it is.
    #[test]
    fn a_gzipped_module_is_held_to_its_limit() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&[0u8; 4096]).unwrap();
        let gz = encoder.finish().unwrap();
        let path = Utf8Path::new("backend.wasm.gz");
        gunzipped_within(path, &gz, 8192).unwrap();
        let err = gunzipped_within(path, &gz, 1024).unwrap_err();
        assert!(err.0.contains("expands past 1024"), "{err}");
        gunzipped_within(path, b"\0asm plain", 1).unwrap();
    }

    // Directory lookups come from the index by range, not by scanning it:
    // what is under a directory, and whether anything is.
    #[test]
    fn directory_lookups_follow_the_index() {
        let (_dir, into) = scratch();
        let fs = extract_bundle(
            &archive(&[
                ("icp.yaml", b"canisters: []"),
                ("a/b/c.txt", b"1"),
                ("a/b/d.txt", b"2"),
                ("a/e.txt", b"3"),
                ("ab/f.txt", b"4"),
            ]),
            &into,
        )
        .unwrap();
        let state = fs.0.state();
        assert!(state.is_dir(Utf8Path::new("a")));
        assert!(state.is_dir(Utf8Path::new("a/b")));
        assert!(!state.is_dir(Utf8Path::new("a/b/c.txt")));
        assert!(!state.is_dir(Utf8Path::new("a/x")));
        let under: Vec<_> = State::under(&state.files, Utf8Path::new("a")).collect();
        assert_eq!(under.len(), 3, "{under:?}");
        assert!(under.iter().all(|p| p.starts_with("a")), "{under:?}");
        drop(state);
        let children = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(fs.read_dir(&fs.root().join("a")))
            .unwrap();
        assert_eq!(children, vec![fs.root().join("a/b"), fs.root().join("a/e.txt")]);
    }

    // A canister directory is held to the bundle root by its spelling, since
    // the sync-plugin runtime takes it as a host path: inside by name is
    // held, and `/etc` or a climb out of the root is not, however it would
    // normalize.
    #[test]
    fn a_canister_directory_is_under_the_root_by_spelling() {
        let (_dir, into) = scratch();
        let fs = extract_bundle(&archive(&[("icp.yaml", b"canisters: []")]), &into).unwrap();
        let root = fs.root().to_path_buf();
        assert!(fs.holds_dir(&root));
        assert!(fs.holds_dir(&root.join("backend")));
        assert!(fs.holds_dir(&root.join("./backend")));
        assert!(!fs.holds_dir(Utf8Path::new("/etc")));
        assert!(!fs.holds_dir(&root.join("../elsewhere")));
        assert!(!fs.holds_dir(&root.join("backend/../../elsewhere")));
    }

    // The index is the filesystem: what extraction wrote is readable by any
    // spelling that normalizes to it, and nothing else is, however the disk
    // looks at the spelling — absolute, climbing, or a file that happens to
    // exist under the root without having come from the archive.
    #[tokio::test]
    async fn the_bundle_serves_its_index_and_nothing_else() {
        let (_dir, into) = scratch();
        let fs = extract_bundle(
            &archive(&[("icp.yaml", b"canisters: []"), ("./canisters/a.wasm", b"wasm")]),
            &into,
        )
        .unwrap();
        let root = fs.root().to_path_buf();

        for spelling in ["canisters/a.wasm", "./canisters/a.wasm", "canisters/../canisters/a.wasm"]
        {
            assert_eq!(fs.read(Utf8Path::new(spelling)).await.unwrap(), b"wasm", "{spelling}");
        }
        // The absolute paths the library derives from the root strip back.
        assert_eq!(fs.read(&root.join("canisters/a.wasm")).await.unwrap(), b"wasm");
        assert_eq!(
            fs.canonicalize(Utf8Path::new("canisters/a.wasm")).await,
            Some(root.join("canisters/a.wasm"))
        );
        assert!(fs.is_dir(Utf8Path::new("canisters")).await);
        assert!(fs.is_dir(&root).await);
        assert!(!fs.is_dir(Utf8Path::new("canisters/a.wasm")).await);
        assert_eq!(
            fs.read_dir(&root).await.unwrap(),
            vec![root.join("canisters"), root.join("icp.yaml")]
        );

        std::fs::write(root.join("planted"), b"not from the archive").unwrap();
        for escape in ["/etc/hostname", "../../../../etc/hostname", "canisters/../../x", "planted"]
        {
            let err = fs.read(Utf8Path::new(escape)).await.unwrap_err().to_string();
            assert!(err.contains("not in the bundle"), "{escape}: {err}");
            assert!(!fs.exists(Utf8Path::new(escape)).await, "{escape}");
        }
        let err = fs.locate(Utf8Path::new("/etc/hostname")).unwrap_err().to_string();
        assert!(err.contains("'etc/hostname' is not in the bundle"), "{err}");
    }

    // A build writes its output to a scratch directory and the operation
    // reads it back through the same filesystem; nowhere else may be written,
    // and the scratch goes — from the disk and the index — with its holder.
    #[tokio::test]
    async fn a_build_output_lands_in_scratch_and_nowhere_else() {
        let (_dir, into) = scratch();
        let fs = extract_bundle(&archive(&[("icp.yaml", b"canisters: []")]), &into).unwrap();
        let scratch = fs.scratch_dir().await.unwrap();
        assert!(scratch.path().starts_with(fs.root()));
        let out = scratch.path().join("out/module.wasm");
        fs.write(&out, b"built").await.unwrap();
        assert_eq!(fs.read(&out).await.unwrap(), b"built");
        assert!(fs.is_file(&out).await);
        assert!(fs.is_dir(scratch.path()).await);
        assert!(fs.create_dir_all(&scratch.path().join("more")).await.is_ok());

        let err = fs.write(Utf8Path::new("canisters/x.wasm"), b"no").await.unwrap_err().to_string();
        assert!(err.contains("read-only"), "{err}");
        let err = fs.write(Utf8Path::new("/tmp/x"), b"no").await.unwrap_err().to_string();
        assert!(err.contains("read-only"), "{err}");
        assert!(!fs.root().join("tmp/x").exists());
        assert!(fs.create_dir_all(Utf8Path::new("elsewhere")).await.is_err());

        let on_disk = out.clone();
        drop(scratch);
        assert!(!fs.exists(&out).await, "scratch leaves the index with its holder");
        assert!(!on_disk.exists(), "and the disk");
    }
}
