//! The [`Host`] a bundle is deployed from: the project library's seams, each
//! implemented for an extracted bundle in a scratch directory.
//!
//! A bundle is the self-contained archive `icp project bundle` writes: the
//! project manifest rewritten so every canister is a pre-built wasm the
//! archive carries, the networks and environments inlined, and each sync
//! plugin's wasm and input files alongside. That shape is what makes the seams
//! small: nothing is built from source, no wasm is fetched over HTTP, no
//! recipe is resolved, and the only network a bundle can sensibly target from
//! here is a connected one.
//!
//! The archive is untrusted input: it arrives in a tool call, and the agent
//! that passes it may have fetched it from anywhere. So the shape is not
//! assumed but enforced, at the three places a crafted archive could reach
//! past the deploy:
//!
//! * **Extraction** writes only regular files and directories, within a total
//!   size budget, under the scratch directory ([`extract_bundle`]).
//! * **Every path the manifest names** — a wasm, an argument file, an
//!   environment-variable file — is resolved against the extracted root and
//!   refused if it leads outside it ([`Root`], [`ConfinedFs`],
//!   [`BundledWasm`]). The project library reads the manifest's files through
//!   its [`FileSystem`] seam, so one adapter covers them all.
//! * **No script runs.** A manifest's build and sync steps may be scripts,
//!   which the library runs as host subprocesses; a bundle never carries one
//!   (`icp project bundle` replaces each build with the wasm it produced), and
//!   here they are refused instead of run ([`NoScripts`]). Sync plugins run in
//!   the wasmtime sandbox as they do under the CLI.
//!
//! Everything the project library reads or writes — the manifest, the wasms,
//! the `.icp` id and artifact stores, the build scratch — lives under the
//! extracted directory, which is removed when the deploy ends.

use std::{fmt, io::Read, sync::Arc};

use async_trait::async_trait;
use camino::{Utf8Path, Utf8PathBuf};
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
    files::{FileSystem, FsError, HostFileSystem, Scratch},
    host::{Host, Ignore},
    manifest::{
        prebuilt::SourceField, BuildStep, ProjectRootLocate, ProjectRootLocateImpl, SyncStep,
        PROJECT_MANIFEST,
    },
    network::{
        Access, AccessError, CollectFriendlyDomains, Configuration, NetworkAccess, NetworkUrls,
        RootKeySource, RootKeySpec,
    },
    prelude::IC_ROOT_KEY,
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
/// Network resolution for a bundle: connected networks only.
///
/// A managed network is one the icp CLI launches and controls on the machine
/// it runs on; there is none here to launch, so an environment on one is
/// refused with that explanation rather than failing deep inside the deploy
/// with a missing descriptor file.
pub struct ConnectedNetworks;

impl ConnectedNetworks {
    fn connected(network: &Network) -> Result<&icp_project::network::Connected, AccessError> {
        match &network.configuration {
            Configuration::Connected { connected } => Ok(connected),
            Configuration::Managed { .. } => Err(AccessError::new(Unsupported(format!(
                "network '{}' is a managed (locally launched) network, which this server cannot \
                 run; deploy the bundle to an environment on a connected network such as `ic`, \
                 or deploy locally with `icp deploy`",
                network.name
            )))),
        }
    }
}

#[async_trait]
impl Access for ConnectedNetworks {
    async fn access(&self, network: &Network) -> Result<NetworkAccess, AccessError> {
        let connected = Self::connected(network)?;
        let (root_key, root_key_source) = match &connected.root_key {
            RootKeySpec::Mainnet => (IC_ROOT_KEY.to_vec(), RootKeySource::Mainnet),
            RootKeySpec::Explicit(bytes) => (bytes.clone(), RootKeySource::Configured),
            // Trust-on-first-use, exactly as the icp CLI treats `root-key:
            // fetch`: the bundle's author chose it for their own network. It is
            // logged, because a key fetched over the network is only as
            // trustworthy as the response that carried it.
            RootKeySpec::Fetch => {
                tracing::warn!(
                    "fetching the root key of network '{}' from {} (trust-on-first-use)",
                    network.name,
                    connected.api_url
                );
                let bootstrap = ic_agent::Agent::builder()
                    .with_url(connected.api_url.as_str())
                    .build()
                    .map_err(AccessError::new)?;
                bootstrap.fetch_root_key().await.map_err(AccessError::new)?;
                (bootstrap.read_root_key(), RootKeySource::Fetched)
            }
        };
        Ok(NetworkAccess {
            root_key,
            root_key_source,
            api_url: connected.api_url.clone(),
            http_gateway_url: connected.http_gateway_url.clone(),
            use_friendly_domains: false,
        })
    }

    async fn urls(&self, network: &Network) -> Result<NetworkUrls, AccessError> {
        let connected = Self::connected(network)?;
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

/// The extracted bundle's directory, canonical, and the rule every path the
/// project library hands back is held to: it must resolve to somewhere
/// beneath it.
///
/// "Resolve" is the operative word. The manifest's paths are joined onto a
/// canister directory, and a join does not confine: an absolute path replaces
/// the base, `..` climbs out of it, and a symlink leads wherever it points. So
/// a path is checked after the filesystem has had its say — its longest
/// existing prefix canonicalized, the rest (which may create new files, as a
/// build output does) appended with no `..` in it.
#[derive(Clone, Debug)]
pub struct Root(Arc<Utf8PathBuf>);

impl Root {
    pub fn new(dir: &Utf8Path) -> Result<Self, String> {
        let canonical = canonicalize(dir).map_err(|e| format!("cannot resolve '{dir}': {e}"))?;
        Ok(Self(Arc::new(canonical)))
    }

    pub fn path(&self) -> &Utf8Path {
        &self.0
    }

    /// Where `path` (relative to the root, if relative) leads, provided that
    /// is under the root. The path need not exist in full.
    pub fn resolve(&self, path: &Utf8Path) -> Result<Utf8PathBuf, Unsupported> {
        let joined = if path.is_absolute() { path.to_path_buf() } else { self.0.join(path) };
        // Split off the trailing components that do not exist yet. A symlink
        // counts as existing — canonicalizing it is the point.
        let mut existing = joined.as_path();
        let mut pending: Vec<&str> = Vec::new();
        while std::fs::symlink_metadata(existing).is_err() {
            match (existing.file_name(), existing.parent()) {
                (Some(name), Some(parent)) => {
                    pending.push(name);
                    existing = parent;
                }
                _ => return Err(self.outside(path)),
            }
        }
        if pending.contains(&"..") {
            return Err(self.outside(path));
        }
        let mut resolved = canonicalize(existing)
            .map_err(|e| Unsupported(format!("cannot resolve '{path}': {e}")))?;
        if !resolved.starts_with(&*self.0) {
            return Err(self.outside(path));
        }
        for component in pending.into_iter().rev() {
            resolved.push(component);
        }
        Ok(resolved)
    }

    /// An existing regular file under the root: what a manifest may read.
    /// Anything else a path could lead to — a directory, a device, a pipe —
    /// is refused, so a read is bounded by a file's size.
    pub fn file(&self, path: &Utf8Path) -> Result<Utf8PathBuf, Unsupported> {
        let resolved = self.resolve(path)?;
        match std::fs::metadata(&resolved) {
            Ok(meta) if meta.is_file() => Ok(resolved),
            Ok(_) => Err(Unsupported(format!("'{path}' is not a regular file"))),
            Err(e) => Err(Unsupported(format!("cannot read '{path}': {e}"))),
        }
    }

    fn outside(&self, path: &Utf8Path) -> Unsupported {
        Unsupported(format!(
            "'{path}' leads outside the bundle, which a bundle's manifest never does; rebuild it \
             with `icp project bundle`"
        ))
    }
}

fn canonicalize(path: &Utf8Path) -> std::io::Result<Utf8PathBuf> {
    let canonical = std::fs::canonicalize(path)?;
    Utf8PathBuf::from_path_buf(canonical)
        .map_err(|p| std::io::Error::other(format!("'{}' is not UTF-8", p.display())))
}

/// The host filesystem, confined to a [`Root`]: every path is resolved through
/// it before it is touched, and the scratch directory a build step writes to
/// is made inside it, so that what the step writes can be read back.
pub struct ConfinedFs {
    root: Root,
    host: HostFileSystem,
}

impl ConfinedFs {
    pub fn new(root: Root) -> Self {
        Self { root, host: HostFileSystem }
    }

    fn file(&self, path: &Utf8Path) -> Result<Utf8PathBuf, FsError> {
        self.root.file(path).map_err(FsError::new)
    }

    fn resolve(&self, path: &Utf8Path) -> Result<Utf8PathBuf, FsError> {
        self.root.resolve(path).map_err(FsError::new)
    }
}

#[async_trait]
impl FileSystem for ConfinedFs {
    async fn read(&self, path: &Utf8Path) -> Result<Vec<u8>, FsError> {
        self.host.read(&self.file(path)?).await
    }

    async fn read_to_string(&self, path: &Utf8Path) -> Result<String, FsError> {
        self.host.read_to_string(&self.file(path)?).await
    }

    async fn write(&self, path: &Utf8Path, contents: &[u8]) -> Result<(), FsError> {
        self.host.write(&self.resolve(path)?, contents).await
    }

    async fn create_dir_all(&self, path: &Utf8Path) -> Result<(), FsError> {
        self.host.create_dir_all(&self.resolve(path)?).await
    }

    async fn copy(&self, from: &Utf8Path, to: &Utf8Path) -> Result<(), FsError> {
        self.host.copy(&self.file(from)?, &self.resolve(to)?).await
    }

    async fn exists(&self, path: &Utf8Path) -> bool {
        match self.resolve(path) {
            Ok(p) => self.host.exists(&p).await,
            Err(_) => false,
        }
    }

    async fn is_file(&self, path: &Utf8Path) -> bool {
        match self.resolve(path) {
            Ok(p) => self.host.is_file(&p).await,
            Err(_) => false,
        }
    }

    async fn is_dir(&self, path: &Utf8Path) -> bool {
        match self.resolve(path) {
            Ok(p) => self.host.is_dir(&p).await,
            Err(_) => false,
        }
    }

    async fn read_dir(&self, path: &Utf8Path) -> Result<Vec<Utf8PathBuf>, FsError> {
        self.host.read_dir(&self.resolve(path)?).await
    }

    async fn canonicalize(&self, path: &Utf8Path) -> Option<Utf8PathBuf> {
        self.host.canonicalize(&self.resolve(path).ok()?).await
    }

    async fn scratch_dir(&self) -> Result<Box<dyn Scratch>, FsError> {
        let dir = tempfile::Builder::new()
            .prefix(".scratch-")
            .tempdir_in(self.root.path())
            .map_err(FsError::new)?;
        let path = Utf8PathBuf::from_path_buf(dir.path().to_path_buf())
            .map_err(|p| FsError::new(Unsupported(format!("'{}' is not UTF-8", p.display()))))?;
        Ok(Box::new(ConfinedScratch { _dir: dir, path }))
    }
}

/// A scratch directory under the root, removed when dropped.
struct ConfinedScratch {
    _dir: tempfile::TempDir,
    path: Utf8PathBuf,
}

impl Scratch for ConfinedScratch {
    fn path(&self) -> &Utf8Path {
        &self.path
    }
}

/// Wasm resolution for a bundle: the archive carries every module it names,
/// so a source is a path inside the bundle (verified against its recorded
/// checksum) and a remote one is a bundle this tool does not understand.
pub struct BundledWasm {
    root: Root,
}

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
                let path = self.root.file(&base_dir.join(&local.path)).map_err(FetchError::new)?;
                if let Some(expected) = sha256 {
                    reporter.info(format!("Reading wasm: {}", local.path));
                    let bytes = tokio::fs::read(path.as_std_path()).await.map_err(|e| {
                        FetchError::new(Unsupported(format!("failed to read '{path}': {e}")))
                    })?;
                    reporter.info("Verifying checksum");
                    let actual = hex::encode(Sha256::digest(&bytes));
                    if actual != expected {
                        return Err(FetchError::new(Unsupported(format!(
                            "checksum mismatch for '{path}': the manifest records {expected}, \
                             the file hashes to {actual}"
                        ))));
                    }
                }
                Ok(path)
            }
            SourceField::Remote(_) => Err(FetchError::new(Unsupported(
                "a bundle carries every wasm it names, so a remote wasm source is not \
                 expected here; rebuild the bundle with `icp project bundle`"
                    .into(),
            ))),
        }
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
/// [`refuse_scripts`] catches a script step before any phase runs; this is
/// the backstop at the seam the library would run one through, so a step the
/// walk missed still cannot reach a shell.
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

/// Refuse, by name, every canister whose build or sync steps include a
/// script — before any phase runs, so a bundle that would be refused at its
/// sync phase does not first spend cycles creating canisters.
pub fn refuse_scripts<'a>(canisters: impl IntoIterator<Item = &'a Canister>) -> Result<(), String> {
    for canister in canisters {
        let build = canister.build.steps.iter().any(|s| matches!(s, BuildStep::Script(_)));
        let sync = canister.sync.steps.iter().any(|s| matches!(s, SyncStep::Script(_)));
        let what = match (build, sync) {
            (true, _) => "build",
            (false, true) => "sync",
            (false, false) => continue,
        };
        return Err(format!("canister '{}': {}", canister.name, NoScripts::script_refused(what)));
    }
    Ok(())
}

/// The host for the bundle extracted at `dir`: its manifest is the project,
/// its `.icp` directory the id and artifact stores, and nothing outside it is
/// reachable.
pub fn host_for(dir: &Utf8Path) -> Result<Host, String> {
    let root = Root::new(dir)?;
    // The directory IS the project root: no climbing to a workspace above it.
    let locate: Arc<dyn ProjectRootLocate> = Arc::new(ProjectRootLocateImpl::new(
        root.path().to_path_buf(),
        Some(root.path().to_path_buf()),
    ));
    let files: Arc<dyn FileSystem> = Arc::new(ConfinedFs::new(root.clone()));
    let wasm: Arc<dyn Fetch> = Arc::new(BundledWasm { root });
    let project = Lazy::<_, Project>::new(ProjectLoadImpl {
        project_root_locate: locate.clone(),
        recipe: Arc::new(NoRecipes),
        files: files.clone(),
    });
    let no_scripts = Arc::new(NoScripts { prebuilt: Builder::new(wasm.clone(), files.clone()) });
    Ok(Host {
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
        network: Arc::new(ConnectedNetworks),
        random: Arc::new(HostRandom),
        observer: Arc::new(Ignore),
    })
}

/// Extract a bundle archive into `into`, which must exist and be empty.
///
/// Only regular files and directories are written — `icp project bundle`
/// writes nothing else, and a symlink or a device node is how an archive
/// reaches past its directory — and their sizes may not add up to more than
/// [`MAX_EXTRACTED_BYTES`]. `tar` refuses entry paths that would land outside
/// `into`. What it extracts is then required to look like a bundle, i.e. to
/// carry a project manifest at its root.
pub fn extract_bundle(bytes: &[u8], into: &Utf8Path) -> Result<(), String> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(format!(
            "the bundle is {} bytes, above the {} byte limit",
            bytes.len(),
            MAX_BUNDLE_BYTES
        ));
    }
    let unreadable =
        |e: std::io::Error| format!("the bundle is not a readable .tar.gz archive: {e}");
    let decoder = Limited { inner: flate2::read::GzDecoder::new(bytes), left: MAX_EXTRACTED_BYTES };
    let mut archive = tar::Archive::new(decoder);
    let mut total: u64 = 0;
    for entry in archive.entries().map_err(unreadable)? {
        let mut entry = entry.map_err(unreadable)?;
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            let path = entry.path().map(|p| p.display().to_string()).unwrap_or_default();
            return Err(format!(
                "the archive entry '{path}' is not a regular file or directory ({kind:?}), which \
                 a bundle never carries; rebuild it with `icp project bundle`"
            ));
        }
        total = total.saturating_add(entry.size());
        if total > MAX_EXTRACTED_BYTES {
            return Err(too_large());
        }
        entry.unpack_in(into.as_std_path()).map_err(unreadable)?;
    }
    if !into.join(PROJECT_MANIFEST).is_file() {
        return Err(format!(
            "the archive carries no `{PROJECT_MANIFEST}` at its root, so it is not an icp \
             project bundle (`icp project bundle` writes one)"
        ));
    }
    Ok(())
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
    use icp_project::network::Managed;
    use std::io::Write;

    fn managed(name: &str) -> Network {
        Network {
            name: name.into(),
            configuration: Configuration::Managed { managed: Managed::default() },
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

    // A bundle built for `local` names a managed network; the refusal must
    // say what to do instead, not fail on a missing descriptor file.
    #[tokio::test]
    async fn managed_networks_are_refused_with_the_way_out() {
        let err = match ConnectedNetworks.urls(&managed("local")).await {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a managed network must be refused"),
        };
        assert!(err.contains("managed"), "{err}");
        assert!(err.contains("`ic`"), "{err}");
        let err = match ConnectedNetworks.access(&managed("local")).await {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a managed network must be refused"),
        };
        assert!(err.contains("managed"), "{err}");
    }

    // The mainnet root key is pinned, never fetched: a bundle for `ic`
    // resolves without touching the network.
    #[tokio::test]
    async fn the_ic_network_resolves_to_the_pinned_root_key() {
        let network = Network {
            name: "ic".into(),
            configuration: Configuration::Connected {
                connected: icp_project::network::Connected {
                    api_url: "https://icp-api.io".parse().unwrap(),
                    http_gateway_url: Some("https://icp.net".parse().unwrap()),
                    root_key: RootKeySpec::Mainnet,
                },
            },
        };
        let access = ConnectedNetworks.access(&network).await.unwrap();
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
    // carries none, so one is refused rather than followed later.
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

    // The root is the fence: a relative path stays, an absolute path and a
    // climbing one are refused, as is a symlink that points out — however it
    // got there — and a path that leads to something other than a file.
    #[test]
    fn the_root_confines_every_path_it_resolves() {
        let (_dir, dir) = scratch();
        std::fs::create_dir(dir.join("canisters")).unwrap();
        std::fs::write(dir.join("canisters/a.wasm"), b"wasm").unwrap();
        let root = Root::new(&dir).unwrap();

        let inside = root.file(Utf8Path::new("canisters/a.wasm")).unwrap();
        assert!(inside.starts_with(root.path()));
        assert_eq!(std::fs::read(inside).unwrap(), b"wasm");
        let inside = root.file(&dir.join("canisters").join("a.wasm")).unwrap();
        assert!(inside.starts_with(root.path()));

        // Not there yet, but under the root: where a build writes its output.
        let new = root.resolve(Utf8Path::new("canisters/out/b.wasm")).unwrap();
        assert_eq!(new, root.path().join("canisters/out/b.wasm"));

        for escape in ["/etc/passwd", "../x", "canisters/../../x", "canisters/a.wasm/../../../x"] {
            let err = root.resolve(Utf8Path::new(escape)).unwrap_err().to_string();
            assert!(err.contains("outside the bundle"), "{escape}: {err}");
        }
        let err = root.file(Utf8Path::new("canisters")).unwrap_err().to_string();
        assert!(err.contains("not a regular file"), "{err}");

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/", dir.join("escape")).unwrap();
            let err = root.file(Utf8Path::new("escape/etc/hostname")).unwrap_err().to_string();
            assert!(err.contains("outside the bundle"), "{err}");
            std::os::unix::fs::symlink("/dev/zero", dir.join("canisters/zero.wasm")).unwrap();
            let err = root.file(Utf8Path::new("canisters/zero.wasm")).unwrap_err().to_string();
            assert!(err.contains("outside the bundle"), "{err}");
        }
    }

    // The confined filesystem's scratch directory is under the root, so a
    // build output written there can be read back through the same fence.
    #[tokio::test]
    async fn the_scratch_directory_is_inside_the_root() {
        let (_dir, dir) = scratch();
        let fs = ConfinedFs::new(Root::new(&dir).unwrap());
        let scratch = fs.scratch_dir().await.unwrap();
        let out = scratch.path().join("out.wasm");
        fs.write(&out, b"built").await.unwrap();
        assert_eq!(fs.read(&out).await.unwrap(), b"built");
        let err = fs.read(Utf8Path::new("/etc/hostname")).await.unwrap_err().to_string();
        assert!(err.contains("outside the bundle"), "{err}");
    }
}
