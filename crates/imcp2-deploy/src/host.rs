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
//! assumed but enforced, and the rule it is held to is the library's own:
//! `icp_project::untrusted`, the rule for a project someone else handed over
//! (dfinity/icp-cli#873), the one `--untrusted` on `icp build`, `deploy` and
//! `sync` applies. The host composes it as the CLI does, from the library's
//! three parts:
//!
//! * **The project is read through [`Confined`]**, the host filesystem held
//!   to the extraction directory: the root is opened once as a directory
//!   handle and every read is made beneath it, so the operating system
//!   refuses a path that leaves the root, by `..`, by an absolute path or by
//!   a symlink; and on top of that a path through a symlink is refused
//!   wherever it leads. A manifest can name only what the archive brought
//!   with it. The disk is the byte store because the sync-plugin runtime
//!   needs real paths to mount.
//! * **No recipe is fetched** ([`NoRecipes`]): a recipe is build
//!   instructions read from a file or fetched from a URL while the project
//!   loads, so a project naming one fails to load, naming the recipe. A
//!   bundle spells every step out and names none.
//! * **The loaded project is vetted** ([`Vetted`]) before it is handed out:
//!   each build step is a pre-built module, each sync step a plugin, and
//!   what each names is a regular file the confined filesystem will give;
//!   what a plugin step hands its plugin, each `dirs:` and `files:` entry,
//!   is a directory or a regular file there too. A project with any other
//!   step — a script, a download — or a path that is not such a file fails
//!   the load, naming it. The loader is the one gate on the project's
//!   shape; the builder and syncer are the library's own, and see no other
//!   step.
//!
//! What a consumer of a bundle adds, this crate adds:
//!
//! * **Extraction** writes only regular files and directories, within a total
//!   size budget and an object budget, under the scratch directory
//!   ([`extract_bundle`]), and refuses the `.icp` state a deploy seeds for
//!   itself: the library takes what is under `.icp` as its own earlier
//!   writes, and vets none of it.
//! * **The bundle is checked before any phase runs** ([`check_bundle`]): every
//!   canister built by one pre-built wasm in the archive that hashes to its
//!   recorded checksum, every sync plugin in the archive with the bytes it
//!   declares held to a sum, and no network but `ic`. The check's own work
//!   is bounded by the archive, not by what the manifest repeats.
//! * **What the load retains is metered**, so a manifest naming large
//!   argument files over and over costs no more than [`MAX_PROJECT_BYTES`].
//!
//! The rule is one, split three ways upstream (dfinity/icp-cli#863): the
//! user's own project may run, fetch and link whatever it likes; `icp
//! project bundle` writes an archive of regular files and directories with
//! every step spelled out (dfinity/icp-cli#868); and a consumer of a bundle
//! it does not trust loads it as untrusted (dfinity/icp-cli#873, on #868).
//! This crate is that consumer, and pins icp-cli's main at the merge of #873.
//!
//! Everything the project library reads or writes — the manifest, the wasms,
//! the `.icp` id and artifact stores, the build scratch — lives under the
//! extracted directory, which is removed when the deploy ends.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::Read,
    sync::{Arc, Mutex, PoisonError},
};

use async_trait::async_trait;
use camino::{Utf8Path, Utf8PathBuf};
use icp_events::StepReporter;
use icp_project::{
    canister::{
        build::Builder,
        sync::{
            script::{ScriptInvocation, ScriptRunError, ScriptRunner},
            Syncer,
        },
        wasm::{Fetch, FetchError},
    },
    files::{Confined, FileSystem, FsError, Scratch},
    host::{Host, Ignore},
    manifest::{
        plugin::NamedPaths, prebuilt::SourceField, BuildStep, ProjectRootLocate,
        ProjectRootLocateImpl, SyncStep, PROJECT_MANIFEST,
    },
    network::{
        Access, AccessError, CollectFriendlyDomains, Configuration, NetworkAccess, NetworkUrls,
        RootKeySource, RootKeySpec,
    },
    operations::wasm::extract_candid_service,
    prelude::{IC, IC_MAINNET_NETWORK_API_URL, IC_ROOT_KEY},
    random::HostRandom,
    store_artifact::ArtifactStore,
    store_id::AccessImpl,
    untrusted::{NoRecipes, Vetted},
    Canister, CanisterArgs, Lazy, Network, Project, ProjectLoadImpl,
};
use imcp2_core::guard_candid_text;
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

/// The most files and directories an archive may extract to, counting the
/// directories its entries' paths imply and extraction creates on the way.
/// The byte budget alone would admit millions of empty files, each a path
/// the loader may walk, or a few files at the bottom of millions of
/// directories, each an inode; a real bundle is a manifest, a few modules and
/// plugins, and a frontend's assets, well inside this.
pub const MAX_BUNDLE_ENTRIES: usize = 250_000;

/// The longest path an archive entry may have, in bytes: Linux's own `PATH_MAX`,
/// past which no path can be created anyway. Counting the directories a path
/// implies costs a lookup per component, so the path is held to a length first.
pub const MAX_ENTRY_PATH_BYTES: usize = 4096;

/// What loading the project may read in all: the manifests, and the argument
/// and variable files the loader reads into each canister. Each read is
/// retained, and the loader reads a file once per canister that names it,
/// so the extraction budget bounds none of this: fifty canisters naming one
/// file of 100 MiB would hold 5 GiB. A canister's arguments fit in one
/// ingress message, so a real project reads a few MiB at most.
pub const MAX_PROJECT_BYTES: u64 = 256 * 1024 * 1024;

/// The most a gzip-compressed module may expand to: 100 MiB, the IC's own
/// ceiling on a module. The library gunzips a module in memory to read its
/// Candid interface, with no bound of its own, so the bound is applied here
/// before a deploy runs.
pub const MAX_WASM_BYTES: u64 = 100 * 1024 * 1024;

/// What the gzip-compressed modules of one bundle may expand to in all, each
/// distinct module counted once: the extraction budget again, so that
/// compressing a module buys nothing against it. [`check_bundle`] expands
/// each module once to hold it to [`MAX_WASM_BYTES`]; without a sum, an
/// archive of ten thousand kilobyte-sized gzip files each expanding to that
/// limit would have the check decompress a terabyte before refusing anything.
pub const MAX_WASM_BYTES_IN_ALL: u64 = MAX_EXTRACTED_BYTES;

/// What one sync step's `files:` entries may hold in all, an entry counted
/// each time it is declared: the sync-plugin runtime reads every declared
/// file into a string of its own before the plugin runs, so a file declared
/// a hundred times is held a hundred times over. A plugin's file inputs are
/// its configuration, a few KiB; the directories it declares are mounted,
/// not read, and cost nothing here.
pub const MAX_PLUGIN_INPUT_BYTES: u64 = 64 * 1024 * 1024;

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

/// The extracted bundle, as the filesystem the project library reads
/// through: the library's own [`Confined`], rooted at the scratch directory.
///
/// Every path the library asks about is opened beneath that root's directory
/// handle, and refused if it passes through a symlink, so a manifest's
/// `path:` — absolute, climbing, or plain — can name only what the archive
/// brought with it; what is not there is "not in the bundle", whatever the
/// machine holds at that spelling or behind a link. A
/// scratch directory the library asks for (a pre-built build step copies its
/// module there and the operation reads it back) is made under the root too.
pub type BundleFs = Confined;

/// Where a file in the bundle is on disk, for a runtime that needs a real
/// path, or why there is none: the path leaves the root, or nothing is there.
pub fn locate(fs: &BundleFs, path: &Utf8Path) -> Result<Utf8PathBuf, Unsupported> {
    let on_disk = fs.resolve(path).map_err(|e| Unsupported(e.to_string()))?;
    if on_disk.is_file() {
        Ok(on_disk)
    } else {
        Err(Unsupported(format!(
            "'{}' is not in the bundle; a bundle carries every file its manifest names (`icp \
             project bundle` writes one that does)",
            on_disk.strip_prefix(fs.root()).unwrap_or(&on_disk)
        )))
    }
}

/// The bytes of a file in the bundle, read where [`locate`] says.
fn read_bytes(fs: &BundleFs, path: &Utf8Path) -> Result<Vec<u8>, Unsupported> {
    let on_disk = locate(fs, path)?;
    std::fs::read(&on_disk).map_err(|e| Unsupported(format!("'{on_disk}': {e}")))
}

/// [`BundleFs`] with a budget on what is read through it: the filesystem
/// the project loader is given, so what it retains is bounded.
///
/// The loader reads a manifest, an argument file or a variable file into the
/// canister that names it, once per canister, and keeps it for the life of
/// the project. Every read is charged by the file's size before it is made;
/// the rest of the trait passes through.
struct Metered {
    inner: BundleFs,
    left: Mutex<u64>,
}

impl Metered {
    fn new(inner: BundleFs, budget: u64) -> Self {
        Self { inner, left: Mutex::new(budget) }
    }

    /// Charge `path`'s size to the budget, or refuse the read.
    fn charge(&self, path: &Utf8Path) -> Result<(), FsError> {
        let on_disk = locate(&self.inner, path).map_err(FsError::new)?;
        let size = std::fs::metadata(&on_disk)
            .map_err(|e| FsError::new(Unsupported(format!("'{on_disk}': {e}"))))?
            .len();
        let mut left = self.left.lock().unwrap_or_else(PoisonError::into_inner);
        if size > *left {
            return Err(FsError::new(Unsupported(format!(
                "loading the project reads more than {} bytes of manifests, argument files and \
                 variable files in all, more than a project ever holds; a canister's arguments \
                 fit in one message",
                MAX_PROJECT_BYTES
            ))));
        }
        *left -= size;
        Ok(())
    }
}

#[async_trait]
impl FileSystem for Metered {
    async fn read(&self, path: &Utf8Path) -> Result<Vec<u8>, FsError> {
        self.charge(path)?;
        self.inner.read(path).await
    }

    async fn read_to_string(&self, path: &Utf8Path) -> Result<String, FsError> {
        self.charge(path)?;
        self.inner.read_to_string(path).await
    }

    async fn write(&self, path: &Utf8Path, contents: &[u8]) -> Result<(), FsError> {
        self.inner.write(path, contents).await
    }

    async fn create_dir_all(&self, path: &Utf8Path) -> Result<(), FsError> {
        self.inner.create_dir_all(path).await
    }

    async fn copy(&self, from: &Utf8Path, to: &Utf8Path) -> Result<(), FsError> {
        self.inner.copy(from, to).await
    }

    async fn exists(&self, path: &Utf8Path) -> bool {
        self.inner.exists(path).await
    }

    async fn is_file(&self, path: &Utf8Path) -> bool {
        self.inner.is_file(path).await
    }

    async fn is_dir(&self, path: &Utf8Path) -> bool {
        self.inner.is_dir(path).await
    }

    async fn read_dir(&self, path: &Utf8Path) -> Result<Vec<Utf8PathBuf>, FsError> {
        self.inner.read_dir(path).await
    }

    async fn canonicalize(&self, path: &Utf8Path) -> Option<Utf8PathBuf> {
        self.inner.canonicalize(path).await
    }

    async fn scratch_dir(&self) -> Result<Box<dyn Scratch>, FsError> {
        self.inner.scratch_dir().await
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
                let on_disk = locate(&self.0, &path).map_err(FetchError::new)?;
                if let Some(expected) = sha256 {
                    reporter.info(format!("Reading wasm: {}", local.path));
                    let bytes = read_bytes(&self.0, &path).map_err(FetchError::new)?;
                    reporter.info("Verifying checksum");
                    verify_checksum(&local.path, expected, &bytes).map_err(FetchError::new)?;
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
    checksum_matches(path, expected, &hex::encode(Sha256::digest(bytes)))
}

fn checksum_matches(path: &Utf8Path, expected: &str, actual: &str) -> Result<(), Unsupported> {
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
/// through a bounded decoder into nothing, and say what it expanded to. A
/// module that is not gzip passes as it is: its size is its own, and it
/// expands to nothing.
fn gunzipped_within(path: &Utf8Path, bytes: &[u8], limit: u64) -> Result<u64, Unsupported> {
    if !bytes.starts_with(&[0x1f, 0x8b]) {
        return Ok(0);
    }
    let mut decoder = Limited { inner: flate2::read::GzDecoder::new(bytes), left: limit };
    match std::io::copy(&mut decoder, &mut std::io::sink()) {
        Ok(expanded) => Ok(expanded),
        Err(_) => Err(Unsupported(format!(
            "the gzip-compressed wasm '{path}' expands past {limit} bytes, the most a module \
             can be, or is not valid gzip"
        ))),
    }
}

/// The script runner the syncer is composed with. A bundle has no script
/// step for it to run — the vetted loader refuses a project with one — so
/// this spawns nothing; it is here because the syncer takes a runner, not
/// as a second gate.
pub struct NoScripts;

#[async_trait]
impl ScriptRunner for NoScripts {
    async fn run_script(
        &self,
        _invocation: ScriptInvocation,
        _reporter: &StepReporter,
    ) -> Result<Vec<String>, ScriptRunError> {
        Err(ScriptRunError {
            source: Box::new(Unsupported(
                "a script sync step reached the runner, which the vetted loader admits none of"
                    .into(),
            )),
        })
    }
}

// ── The check, the host, the extraction ───────────────────────────────────

/// Hold an environment's canisters to the shape a bundle has — before any
/// phase runs, so a bundle that would fail at its build or sync phase, or
/// be refused there, does not first spend cycles creating canisters.
///
/// Each canister is built by exactly one pre-built step naming a wasm in the
/// archive that hashes to the checksum the manifest records; each sync step
/// is a plugin in the archive (hashing to its checksum, if one is recorded).
/// The environment's network is the Internet Computer. That no step is a
/// script and no module or plugin is remote, the loader has already seen
/// to ([`Vetted`]): the check reads what the loaded project names.
///
/// Canister names must also differ by more than letter case: the library's
/// artifact store keys a canister's build output by its name on disk, and
/// a case-insensitive volume (macOS and Windows by default) would hand the
/// last-built module to both.
///
/// What a plugin declares under `dirs:` and `files:` is held to the bundle
/// the way the runtime will hold it at sync, and the files to what the
/// runtime will read of them ([`check_declared`]).
///
/// The work the check does is bounded by the archive, not by the manifest:
/// a file is read, hashed, expanded and its interface guarded once however
/// many canisters name it ([`Verified`]), and the expansions are summed
/// ([`MAX_WASM_BYTES_IN_ALL`]).
///
/// The textual Candid the bundle carries is held to what the library can
/// parse safely: its parser recurses without a depth guard, on the worker
/// thread the deploy runs on, so a canister's `init_args`/`upgrade_args`
/// value and the `candid:service` interface in its module are checked for
/// size and nesting first ([`guard_candid_text`], the bound the call tools
/// apply to caller-supplied Candid). The library parses the arguments at
/// install and the interface at the upgrade compatibility check; a value it
/// cannot parse fails there, but one that would overflow the stack aborts
/// the process, so the bound comes first.
///
/// Where each canister lives is the loader's business: it finds a canister
/// directory through the confined filesystem, so one outside the bundle root
/// — which the sync-plugin runtime would take as its own sandbox root — is
/// not found and the project does not load.
pub fn check_bundle<'a>(
    fs: &BundleFs,
    network: &Network,
    canisters: impl IntoIterator<Item = (&'a Utf8Path, &'a Canister)>,
) -> Result<(), String> {
    check_bundle_within(fs, network, canisters, MAX_WASM_BYTES_IN_ALL, MAX_PLUGIN_INPUT_BYTES)
}

/// [`check_bundle`] with the two sums as parameters, so a test can reach
/// them without a gigabyte of modules.
fn check_bundle_within<'a>(
    fs: &BundleFs,
    network: &Network,
    canisters: impl IntoIterator<Item = (&'a Utf8Path, &'a Canister)>,
    wasm_in_all: u64,
    plugin_input: u64,
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
    let mut verified = Verified { hashes: BTreeMap::new(), wasm_left: wasm_in_all };
    for (dir, canister) in canisters {
        let name = &canister.name;
        let at = |e: Unsupported| format!("canister '{name}': {e}");

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
        let actual = verified.sha256(fs, dir, &local.path).map_err(at)?;
        let Some(expected) = adapter.sha256.as_deref() else {
            return Err(at(Unsupported(format!(
                "the wasm '{}' carries no sha256, which a bundle always records; rebuild the \
                 bundle with `icp project bundle`",
                local.path
            ))));
        };
        checksum_matches(&local.path, expected, &actual).map_err(at)?;
        for (field, args) in
            [("init_args", &canister.init_args), ("upgrade_args", &canister.upgrade_args)]
        {
            // The format type is not nameable from here (the library exposes
            // it through this field alone); its default is `candid`, the one
            // format that is parsed rather than decoded.
            if let Some(CanisterArgs::Text { content, format }) = args {
                if *format == Default::default() {
                    guard_candid_text(&format!("`{field}`"), content)
                        .map_err(|e| at(Unsupported(e)))?;
                }
            }
        }

        for step in &canister.sync.steps {
            let SyncStep::Plugin(plugin) = step else { continue };
            let SourceField::Local(local) = &plugin.source else {
                return Err(at(Unsupported(
                    "synced by a remote plugin, which a bundle never is; rebuild the bundle \
                     with `icp project bundle`"
                        .into(),
                )));
            };
            let actual = verified.sha256(fs, dir, &local.path).map_err(at)?;
            if let Some(expected) = plugin.sha256.as_deref() {
                checksum_matches(&local.path, expected, &actual).map_err(at)?;
            }
            let files = plugin.files.iter().flat_map(NamedPaths::entries).map(|entry| entry.path);
            check_declared(fs, dir, files, plugin_input).map_err(at)?;
        }
    }
    Ok(())
}

/// What [`check_bundle`] has read so far, by where each file lies on disk:
/// a module or plugin that several canisters name — or one canister names
/// under several spellings — is read, hashed, expanded and its interface
/// guarded once, so the work the check does is bounded by what the archive
/// holds, not by what the manifest repeats.
struct Verified {
    /// Each file's sha256, in hex, by its on-disk path.
    hashes: BTreeMap<Utf8PathBuf, String>,
    /// What the gzip-compressed files seen so far may still expand to, in all.
    wasm_left: u64,
}

impl Verified {
    /// The sha256 of the file at `path` under `dir`, read and hashed on first
    /// sight — when a gzip-compressed one is also held to [`MAX_WASM_BYTES`]
    /// expanded, its expansion counted against the sum, and the
    /// `candid:service` interface a module carries held to what the library
    /// can parse.
    fn sha256(
        &mut self,
        fs: &BundleFs,
        dir: &Utf8Path,
        path: &Utf8Path,
    ) -> Result<String, Unsupported> {
        let on_disk = locate(fs, &dir.join(path))?;
        if let Some(hash) = self.hashes.get(&on_disk) {
            return Ok(hash.clone());
        }
        let bytes =
            std::fs::read(&on_disk).map_err(|e| Unsupported(format!("'{on_disk}': {e}")))?;
        let expanded = gunzipped_within(path, &bytes, MAX_WASM_BYTES)?;
        if expanded > self.wasm_left {
            return Err(Unsupported(format!(
                "the bundle's gzip-compressed modules expand to more than \
                 {MAX_WASM_BYTES_IN_ALL} bytes in all, more than a bundle extracts to"
            )));
        }
        self.wasm_left -= expanded;
        // Bounded above, so the extractor's own gunzip is bounded too.
        if let Some(interface) = extract_candid_service(&bytes) {
            guard_candid_text(&format!("the `candid:service` interface of '{path}'"), &interface)
                .map_err(Unsupported)?;
        }
        let hash = hex::encode(Sha256::digest(&bytes));
        self.hashes.insert(on_disk, hash.clone());
        Ok(hash)
    }
}

/// Hold the bytes a sync step's `files:` declare to `budget`, counting a
/// file each time it is declared: the runtime reads every declared file
/// into memory before the plugin runs. That each `dirs:` and `files:` entry
/// is in the bundle — under the root, through no symlink, a directory or a
/// regular file — the vet settled at the load; which of the two settings
/// the plugin's interface accepts, and whether an entry carries a name, is
/// the plugin's to say and stays the runtime's to tell.
fn check_declared<'a>(
    fs: &BundleFs,
    dir: &Utf8Path,
    files: impl IntoIterator<Item = &'a str>,
    budget: u64,
) -> Result<(), Unsupported> {
    let mut left = budget;
    for path in files {
        // Where the vet saw it; a path the vet did not pass never gets here.
        let not_there = || {
            Unsupported(format!(
                "its sync step declares '{path}' under `files:`, which is not in the bundle"
            ))
        };
        let on_disk = fs.resolve(&dir.join(path)).map_err(|_| not_there())?;
        let meta = std::fs::metadata(&on_disk).map_err(|_| not_there())?;
        if meta.is_file() {
            if meta.len() > left {
                return Err(Unsupported(format!(
                    "its sync step's `files:` hold more than {budget} bytes in all, counting a \
                     file each time it is declared, more than a plugin's inputs ever do; the \
                     runtime reads every declared file into memory before the plugin runs"
                )));
            }
            left -= meta.len();
        }
    }
    Ok(())
}

/// The host for the bundle extracted into `fs`: its manifest is the project,
/// its `.icp` directory the id and artifact stores, and nothing outside it is
/// reachable.
///
/// The project is loaded through a [`Metered`] view of the bundle, so what
/// the loader reads and retains — once per canister that names a file — stays
/// within [`MAX_PROJECT_BYTES`]; the phases read the bundle itself.
///
/// What is not bounded here: the sync-plugin runtime (`icp-sync-plugin`'s
/// wasmtime runner) holds a plugin to a compute-time budget and a stack
/// limit, and each of its linear memories to the wasm32 address space, but
/// sets no store limiter, so a plugin may allocate up to that space before
/// its time runs out. The runner builds its own engine and store, so the
/// limiter belongs there, upstream; until it has one, a bundle's plugins run
/// with the memory bound the icp CLI gives them. Nor is the number of
/// canisters or steps a manifest declares: the phases do their work once per
/// canister, and each canister costs the caller the cycles that create it.
pub fn host_for(fs: BundleFs) -> Host {
    host_within(fs, MAX_PROJECT_BYTES)
}

/// [`host_for`] with the project-loading budget as a parameter, so a test can
/// reach it without a quarter of a gigabyte of argument files.
fn host_within(fs: BundleFs, project_bytes: u64) -> Host {
    // The directory IS the project root: no climbing to a workspace above it.
    let root = fs.root().to_path_buf();
    let locate: Arc<dyn ProjectRootLocate> =
        Arc::new(ProjectRootLocateImpl::new(root.clone(), Some(root)));
    let files: Arc<dyn FileSystem> = Arc::new(fs.clone());
    let wasm: Arc<dyn Fetch> = Arc::new(BundledWasm(fs.clone()));
    // The untrusted rule, composed as `icp --untrusted` composes it: the
    // project is read through the bundle's own filesystem, no recipe is
    // fetched, and the project is vetted as it loads, each path a step
    // names asked of that filesystem. The loader is the one gate on the
    // project's shape, so the builder is the library's own.
    let project = Lazy::<_, Project>::new(Vetted::new(
        ProjectLoadImpl {
            project_root_locate: locate.clone(),
            recipe: Arc::new(NoRecipes),
            files: Arc::new(Metered::new(fs, project_bytes)),
        },
        files.clone(),
    ));
    Host {
        project: Arc::new(project),
        files: files.clone(),
        ids: Arc::new(AccessImpl::new(locate.clone())),
        artifacts: Arc::new(ArtifactStore::new(locate)),
        builder: Arc::new(Builder::new(wasm.clone(), files)),
        syncer: Arc::new(Syncer::new(
            Arc::new(NoScripts),
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
/// return it as the filesystem the deploy reads through, confined to it.
///
/// Only regular files and directories are written — `icp project bundle`
/// writes nothing else, and a symlink or a device node is how an archive
/// reaches past its directory — and their sizes may not add up to more than
/// [`MAX_EXTRACTED_BYTES`], nor their number, with the directories their
/// paths imply, to more than [`MAX_BUNDLE_ENTRIES`]. `tar` refuses entry
/// paths that would land outside `into`. What it extracts is then required
/// to look like a bundle, i.e. to carry a project manifest at its root.
pub fn extract_bundle(bytes: &[u8], into: &Utf8Path) -> Result<BundleFs, String> {
    extract_bundle_within(bytes, into, MAX_BUNDLE_ENTRIES)
}

/// [`extract_bundle`] with the files-and-directories cap as a parameter, so a
/// test can reach it without writing a quarter of a million files.
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
    // A link is refused on the way in, so nothing under the root leads out
    // of it; should one appear later, the filesystem refuses any path
    // through it. The root is held as spelled: it and everything above it
    // are this crate's own (macOS keeps its temporary directories under
    // `/var`, a link to `/private/var`), and only what lies below is held
    // to shape.
    let fs = Confined::new(into).map_err(|e| {
        let mut why = e.to_string();
        if let Some(cause) = std::error::Error::source(&e) {
            why.push_str(": ");
            why.push_str(&cause.to_string());
        }
        format!("the extraction directory cannot be confined to: {why}")
    })?;
    let unreadable =
        |e: std::io::Error| format!("the bundle is not a readable .tar.gz archive: {e}");
    let decoder = Limited { inner: flate2::read::GzDecoder::new(bytes), left: MAX_EXTRACTED_BYTES };
    let mut archive = tar::Archive::new(decoder);
    let mut total: u64 = 0;
    // Files and directories written so far, counting each directory an
    // entry's path implies: `unpack_in` creates the missing parents of every
    // entry, so a few files at the bottom of long, distinct directory chains
    // would otherwise cost inodes the entry count never sees.
    let mut objects: usize = 0;
    let too_many = || {
        format!(
            "the bundle holds more than {max_entries} files and directories, more than a bundle \
             ever has"
        )
    };
    // The directories that exist so far, written as entries or implied by
    // the paths of earlier ones, relative to the root.
    let mut dirs: BTreeSet<Utf8PathBuf> = BTreeSet::new();
    for entry in archive.entries().map_err(unreadable)? {
        let mut entry = entry.map_err(unreadable)?;
        objects += 1;
        if objects > max_entries {
            return Err(too_many());
        }
        let kind = entry.header().entry_type();
        let path = entry.path().map_err(unreadable)?.into_owned();
        let path = Utf8PathBuf::from_path_buf(path)
            .map_err(|p| format!("the archive entry '{}' is not UTF-8", p.display()))?;
        if path.as_str().len() > MAX_ENTRY_PATH_BYTES {
            return Err(format!(
                "an archive entry's path is {} bytes long, more than the {MAX_ENTRY_PATH_BYTES} \
                 a path can be",
                path.as_str().len()
            ));
        }
        if !(kind.is_file() || kind.is_dir()) {
            return Err(format!(
                "the archive entry '{path}' is not a regular file or directory ({kind:?}), which \
                 a bundle never carries; rebuild it with `icp project bundle`"
            ));
        }
        // Where the entry lands, relative to the root: `tar` refuses a path
        // that would leave `into`, so resolving it against the root is only
        // a matter of spelling (`./x` is `x`).
        let rel = match fs.resolve(&path) {
            Ok(resolved) => resolved.strip_prefix(fs.root()).unwrap_or(&resolved).to_path_buf(),
            Err(_) => {
                return Err(format!(
                    "the archive entry '{path}' would land outside the extraction directory"
                ))
            }
        };
        // `.icp` is the library's own state under the project root: the id
        // mappings a deploy reads to decide what exists, and the artifact
        // store. A bundle never carries it (`icp project bundle` writes
        // manifests, modules, plugins, argument files and images), and one
        // that did could point a deploy at canisters the caller never named.
        // Compared without regard to case: on a case-insensitive disk `.ICP`
        // is the same directory.
        if rel.components().next().is_some_and(|c| c.as_str().eq_ignore_ascii_case(STATE_DIR)) {
            return Err(format!(
                "the archive entry '{path}' is under `{STATE_DIR}/`, the project state a bundle \
                 never carries; rebuild it with `icp project bundle`"
            ));
        }
        // The parents this entry implies that nothing before it did. A known
        // directory's own parents are known too, so the walk up stops at the
        // first one.
        let implied: Vec<Utf8PathBuf> = rel
            .ancestors()
            .skip(1)
            .filter(|dir| !dir.as_str().is_empty())
            .take_while(|dir| !dirs.contains(*dir))
            .map(Utf8Path::to_path_buf)
            .collect();
        objects = objects.saturating_add(implied.len());
        if objects > max_entries {
            return Err(too_many());
        }
        total = total.saturating_add(entry.size());
        if total > MAX_EXTRACTED_BYTES {
            return Err(too_large());
        }
        if entry.unpack_in(fs.root().as_std_path()).map_err(unreadable)? {
            dirs.extend(implied);
            if kind.is_dir() {
                dirs.insert(rel);
            }
        }
    }
    if !fs.root().join(PROJECT_MANIFEST).is_file() {
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
    use icp_project::{
        host::EnvironmentSelection,
        network::{Connected, Managed},
        Environment,
    };
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
    // carries none, so one is refused rather than written. Should one appear
    // later, the filesystem refuses any path through it (the test after
    // this), so neither gate stands alone.
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

    // Should a link appear under the root after extraction, the filesystem
    // refuses every path through it, wherever it leads: the vet sees a
    // module named through one as not a regular file of the project, and a
    // read through one is refused naming the link. The untrusted rule's own
    // test, run through this host.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_module_named_through_a_link_fails_the_load() {
        use std::os::unix::fs::symlink;
        let manifest = |path: &str| {
            format!(
                "canisters:\n  - name: backend\n    build:\n      steps:\n        - type: \
                 pre-built\n          path: {path}\n"
            )
        };
        let elsewhere = tempfile::tempdir().unwrap();
        let secret = elsewhere.path().join("secret.wasm");
        std::fs::write(&secret, b"\0asm").unwrap();

        // Out: refused at the load, naming the path.
        let (_dir, into) = scratch();
        let bytes = archive(&[("icp.yaml", manifest("out.wasm").as_bytes())]);
        let fs = extract_bundle(&bytes, &into).unwrap();
        symlink(&secret, into.join("out.wasm")).unwrap();
        let err = chain(&host_for(fs.clone()).project.load().await.expect_err("a link out"));
        assert!(err.contains("not a regular file in the project"), "{err}");
        assert!(err.contains("out.wasm"), "{err}");
        // And a read through it is refused naming the link, not followed.
        let err = chain(&fs.read(Utf8Path::new("out.wasm")).await.unwrap_err());
        assert!(err.contains("passes through") && err.contains("out.wasm"), "{err}");

        // Within: refused all the same; the rule is no link, not no link out.
        let (_dir, into) = scratch();
        let bytes =
            archive(&[("icp.yaml", manifest("in.wasm").as_bytes()), ("backend.wasm", b"\0asm")]);
        let fs = extract_bundle(&bytes, &into).unwrap();
        symlink("backend.wasm", into.join("in.wasm")).unwrap();
        let err = chain(&host_for(fs.clone()).project.load().await.expect_err("a link within"));
        assert!(err.contains("not a regular file in the project"), "{err}");
        assert!(err.contains("in.wasm"), "{err}");
        assert!(fs.read(Utf8Path::new("in.wasm")).await.is_err());
        assert_eq!(fs.read(Utf8Path::new("backend.wasm")).await.unwrap(), b"\0asm");

        // Dangling: a link is a link, wherever it leads or fails to.
        let (_dir, into) = scratch();
        let bytes = archive(&[("icp.yaml", manifest("gone.wasm").as_bytes())]);
        let fs = extract_bundle(&bytes, &into).unwrap();
        symlink(into.join("nowhere.wasm"), into.join("gone.wasm")).unwrap();
        let err = chain(&host_for(fs).project.load().await.expect_err("a dangling link"));
        assert!(err.contains("not a regular file in the project"), "{err}");
        assert!(err.contains("gone.wasm"), "{err}");
    }

    // What a step names must be a regular file: a directory of the bundle
    // named as a module is refused at the load, naming what was found. (A
    // pipe cannot arrive in an archive: extraction writes files and
    // directories alone.)
    #[tokio::test]
    async fn a_directory_named_as_a_module_fails_the_load() {
        let manifest = "canisters:\n  - name: backend\n    build:\n      steps:\n        \
                        - type: pre-built\n          path: assets\n";
        let (_dir, into) = scratch();
        let bytes = archive_with_dirs(&[("icp.yaml", manifest.as_bytes())], &["assets"]);
        let fs = extract_bundle(&bytes, &into).unwrap();
        let err = chain(&host_for(fs).project.load().await.expect_err("a directory"));
        assert!(err.contains("not a regular file"), "{err}");
        assert!(err.contains("assets"), "{err}");
    }

    // The root is held as spelled: named through a link, the extraction
    // lands in the directory the link leads to, the filesystem answers to
    // the spelling it was given, and the project in it loads — the root and
    // everything above it are the caller's, and only what lies below is
    // held to shape.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_root_named_through_a_link_holds_the_project() {
        let manifest = "canisters:\n  - name: backend\n    build:\n      steps:\n        \
                        - type: pre-built\n          path: backend.wasm\n";
        let (dir, into) = scratch();
        let alias = Utf8PathBuf::from_path_buf(dir.path().with_extension("alias")).unwrap();
        std::os::unix::fs::symlink(&into, &alias).unwrap();
        let bytes = archive(&[("icp.yaml", manifest.as_bytes()), ("backend.wasm", b"\0asm")]);
        let fs = extract_bundle(&bytes, &alias).unwrap();
        assert_eq!(fs.root(), alias);
        assert!(into.join("backend.wasm").is_file());
        let project = host_for(fs.clone()).project.load().await.unwrap();
        assert_eq!(project.canisters.len(), 1);
        assert_eq!(fs.read(Utf8Path::new("backend.wasm")).await.unwrap(), b"\0asm");
        std::fs::remove_file(&alias).unwrap();
    }

    /// An error and its causes, outermost first.
    fn chain(err: &(dyn std::error::Error + 'static)) -> String {
        let mut text = err.to_string();
        let mut source = err.source();
        while let Some(cause) = source {
            text.push_str(": ");
            text.push_str(&cause.to_string());
            source = cause.source();
        }
        text
    }

    // The rule for a project someone else handed over is the library's own,
    // and it holds at the load: a script step or a module fetched from a URL
    // fails the load, before any phase could act on it. So does a recipe:
    // the library would read or fetch it while loading, and an untrusted
    // project may name none.
    #[tokio::test]
    async fn a_project_asking_more_than_an_untrusted_one_may_fails_to_load() {
        for (manifest, refused) in [
            (
                "canisters:\n  - name: backend\n    build:\n      steps:\n        - type: script\n          command: touch /tmp/pwned\n",
                "not a pre-built module, which is all an untrusted project may have",
            ),
            (
                "canisters:\n  - name: backend\n    build:\n      steps:\n        - type: pre-built\n          url: https://example.com/backend.wasm\n          sha256: abc\n",
                "not a pre-built module, which is all an untrusted project may have",
            ),
            (
                "canisters:\n  - name: backend\n    recipe:\n      type: \"@dfinity/rust@v1\"\n",
                "recipe '@dfinity/rust@v1' is refused: an untrusted project may not use a recipe",
            ),
        ] {
            let (_dir, into) = scratch();
            let fs = extract_bundle(&archive(&[("icp.yaml", manifest.as_bytes())]), &into).unwrap();
            let err = host_for(fs).project.load().await.expect_err(refused);
            let err = chain(&err);
            assert!(err.contains(refused), "{refused}: {err}");
            // The refusal names the step, so the reader sees what was asked.
            let named = ["touch /tmp/pwned", "example.com/backend.wasm", "@dfinity/rust@v1"];
            assert!(named.iter().any(|n| err.contains(n)), "{err}");
        }
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

    // The cap counts files and directories alike, the directories by what
    // the paths imply: nine files under one directory are ten objects.
    #[test]
    fn an_archive_with_too_many_entries_is_refused() {
        let (_dir, into) = scratch();
        let paths: Vec<String> = (0..=8).map(|i| format!("f/{i}")).collect();
        let bytes = empty_files(&paths);
        let err = extract_bundle_within(&bytes, &into, 9).unwrap_err();
        assert!(err.contains("more than 9 files and directories"), "{err}");
        let (_dir, into) = scratch();
        let err = extract_bundle_within(&bytes, &into, 10).unwrap_err();
        assert!(err.contains(PROJECT_MANIFEST), "{err}");
    }

    // An entry's path implies the directories above it, which extraction
    // creates whether or not the archive lists them: they count once each,
    // however many entries share them, and an entry written as a directory
    // counts as itself.
    #[test]
    fn the_directories_an_archive_implies_count_against_its_cap() {
        // Two files at the bottom of one chain: 2 files + 3 directories.
        let bytes = empty_files(&["a/b/c/x".into(), "a/b/c/y".into()]);
        let (_dir, into) = scratch();
        let err = extract_bundle_within(&bytes, &into, 4).unwrap_err();
        assert!(err.contains("more than 4 files and directories"), "{err}");
        assert!(!into.join("a/b/c/y").exists(), "the refused entry is not written");
        let (_dir, into) = scratch();
        let err = extract_bundle_within(&bytes, &into, 5).unwrap_err();
        assert!(err.contains(PROJECT_MANIFEST), "{err}");

        // Two files under distinct chains share nothing: 2 files + 6 dirs.
        let bytes = empty_files(&["a/b/c/x".into(), "d/e/f/y".into()]);
        let (_dir, into) = scratch();
        let err = extract_bundle_within(&bytes, &into, 7).unwrap_err();
        assert!(err.contains("more than 7 files and directories"), "{err}");
        let (_dir, into) = scratch();
        let err = extract_bundle_within(&bytes, &into, 8).unwrap_err();
        assert!(err.contains(PROJECT_MANIFEST), "{err}");

        // One file far down a chain is refused on its own, before it is
        // written: the directories it would create are the cost.
        let deep = (0..64).map(|_| "d").collect::<Vec<_>>().join("/") + "/x";
        let bytes = empty_files(&[deep]);
        let (_dir, into) = scratch();
        let err = extract_bundle_within(&bytes, &into, 32).unwrap_err();
        assert!(err.contains("more than 32 files and directories"), "{err}");
        assert!(!into.join("d").exists());

        // A directory entry counts as itself; a file under it then implies
        // nothing new: 1 dir entry + 1 file.
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_mode(0o755);
        header.set_cksum();
        archive.append_data(&mut header, "a/", &b""[..]).unwrap();
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append_data(&mut header, "a/x", &b""[..]).unwrap();
        let bytes = archive.into_inner().unwrap().finish().unwrap();
        let (_dir, into) = scratch();
        let err = extract_bundle_within(&bytes, &into, 2).unwrap_err();
        assert!(err.contains(PROJECT_MANIFEST), "{err}");
        assert!(into.join("a/x").exists());
    }

    // Counting what a path implies costs a lookup per component, so the
    // path is held to a length first — one no filesystem would take anyway.
    #[test]
    fn an_entry_path_past_the_length_limit_is_refused() {
        let long = (0..=MAX_ENTRY_PATH_BYTES / 2).map(|_| "a").collect::<Vec<_>>().join("/");
        assert!(long.len() > MAX_ENTRY_PATH_BYTES);
        let bytes = empty_files(&[long]);
        let (_dir, into) = scratch();
        let err = extract_bundle(&bytes, &into).unwrap_err();
        assert!(err.contains("bytes long"), "{err}");
        assert!(!into.join("a").exists());
    }

    /// A gzipped tar of empty regular files at the given paths.
    fn empty_files(paths: &[String]) -> Vec<u8> {
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        for path in paths {
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(&mut header, path, &b""[..]).unwrap();
        }
        archive.into_inner().unwrap().finish().unwrap()
    }

    /// A gzipped tar of the given regular files, then directory entries at
    /// the given paths.
    fn archive_with_dirs(files: &[(&str, &[u8])], dirs: &[&str]) -> Vec<u8> {
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        for (path, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(&mut header, path, *data).unwrap();
        }
        for path in dirs {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            archive.append_data(&mut header, path, &b""[..]).unwrap();
        }
        archive.into_inner().unwrap().finish().unwrap()
    }

    // A directory entry makes its parents known like a file does: two
    // sibling directory entries under one chain are four directories, the
    // shared parents counted once.
    #[test]
    fn the_parents_a_directory_entry_implies_are_counted_once() {
        let bytes = archive_with_dirs(&[], &["a/b/c/", "a/b/d/"]);
        let (_dir, into) = scratch();
        let err = extract_bundle_within(&bytes, &into, 3).unwrap_err();
        assert!(err.contains("more than 3 files and directories"), "{err}");
        let (_dir, into) = scratch();
        let err = extract_bundle_within(&bytes, &into, 4).unwrap_err();
        assert!(err.contains(PROJECT_MANIFEST), "{err}");
        assert!(into.join("a/b/d").is_dir());
    }

    // A directory the archive lists as an entry of its own, with nothing
    // under it, is a directory of the bundle: it is on disk, so it is found
    // and listed like any other.
    #[tokio::test]
    async fn an_empty_directory_entry_is_a_directory_of_the_bundle() {
        let (_dir, into) = scratch();
        let bytes = archive_with_dirs(&[("icp.yaml", b"canisters: []")], &["assets/"]);
        let fs = extract_bundle(&bytes, &into).unwrap();
        let root = fs.root().to_path_buf();
        assert!(fs.is_dir(Utf8Path::new("assets")).await);
        assert!(fs.exists(Utf8Path::new("assets")).await);
        assert_eq!(
            fs.read_dir(&root).await.unwrap(),
            vec![root.join("assets"), root.join("icp.yaml")]
        );
        assert!(fs.read_dir(Utf8Path::new("assets")).await.unwrap().is_empty());
    }

    // A gzip-compressed module is bounded by what it expands to, read
    // through a bounded decoder; a plain module passes as it is.
    #[test]
    fn a_gzipped_module_is_held_to_its_limit() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&[0u8; 4096]).unwrap();
        let gz = encoder.finish().unwrap();
        let path = Utf8Path::new("backend.wasm.gz");
        assert_eq!(gunzipped_within(path, &gz, 8192).unwrap(), 4096);
        let err = gunzipped_within(path, &gz, 1024).unwrap_err();
        assert!(err.0.contains("expands past 1024"), "{err}");
        assert_eq!(gunzipped_within(path, b"\0asm plain", 1).unwrap(), 0);
    }

    // The confined filesystem serves what the archive carried, by any spelling
    // that resolves to it, and refuses what resolves outside the root — an
    // absolute path elsewhere, a climb above the root — whatever the machine
    // holds at that spelling. (The filesystem's own tests, upstream, cover
    // the spellings; this is the bundle seen through it.)
    #[tokio::test]
    async fn the_bundle_serves_what_it_carries_and_nothing_outside_it() {
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
            assert_eq!(
                locate(&fs, Utf8Path::new(spelling)).unwrap(),
                root.join("canisters/a.wasm")
            );
        }
        // The absolute paths the library derives from the root resolve too.
        assert_eq!(fs.read(&root.join("canisters/a.wasm")).await.unwrap(), b"wasm");
        assert!(fs.is_dir(Utf8Path::new("canisters")).await);
        assert!(fs.is_dir(&root).await);
        assert_eq!(
            fs.read_dir(&root).await.unwrap(),
            vec![root.join("canisters"), root.join("icp.yaml")]
        );

        for escape in ["/etc/hostname", "../../../../etc/hostname", "canisters/../../x"] {
            let err = fs.read(Utf8Path::new(escape)).await.unwrap_err().to_string();
            assert!(err.contains("is outside"), "{escape}: {err}");
            assert!(!fs.exists(Utf8Path::new(escape)).await, "{escape}");
            let err = locate(&fs, Utf8Path::new(escape)).unwrap_err().to_string();
            assert!(err.contains("is outside"), "{escape}: {err}");
        }
        // Inside the root but not there: not in the bundle.
        let err = locate(&fs, Utf8Path::new("canisters/b.wasm")).unwrap_err().to_string();
        assert!(err.contains("'canisters/b.wasm' is not in the bundle"), "{err}");
    }

    // The loader reads an argument file into every canister that names it,
    // so two canisters naming one file read it twice, and the budget counts
    // both: what the project retains is bounded, not what the archive holds.
    #[tokio::test]
    async fn loading_the_project_is_held_to_its_read_budget() {
        let manifest = "canisters:\n  - name: a\n    init_args:\n      path: args.bin\n      \
                        format: bin\n    build:\n      steps:\n        - type: pre-built\n          \
                        path: a.wasm\n  - name: b\n    init_args:\n      path: args.bin\n      \
                        format: bin\n    build:\n      steps:\n        - type: pre-built\n          \
                        path: a.wasm\n";
        let args = [7u8; 1000];
        // The module is in the archive, as the vet asks; what the loader
        // reads of it is nothing.
        let bytes = archive(&[
            ("icp.yaml", manifest.as_bytes()),
            ("args.bin", &args),
            ("a.wasm", b"\0asm"),
        ]);

        // Room for the manifest and one read of the file, not two.
        let (_dir, into) = scratch();
        let fs = extract_bundle(&bytes, &into).unwrap();
        let host = host_within(fs, manifest.len() as u64 + 1500);
        let err = host.project.load().await.expect_err("the second read is over budget");
        let chain = std::iter::successors(Some(&err as &dyn std::error::Error), |e| e.source())
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(": ");
        assert!(chain.contains("canister 'b'"), "{chain}");
        assert!(chain.contains("loading the project reads more than"), "{chain}");

        // Room for both.
        let (_dir, into) = scratch();
        let fs = extract_bundle(&bytes, &into).unwrap();
        let host = host_within(fs, manifest.len() as u64 + 2000);
        let project = host.project.load().await.unwrap();
        assert_eq!(project.canisters.len(), 2);
    }

    // The budget is the loader's alone: the phases read the bundle itself,
    // where a module is read as many times as the deploy needs it.
    #[tokio::test]
    async fn the_read_budget_meters_reads_and_nothing_else() {
        let (_dir, into) = scratch();
        let fs = extract_bundle(
            &archive(&[("icp.yaml", b"canisters: []"), ("big", &[0u8; 100])]),
            &into,
        )
        .unwrap();
        let metered = Metered::new(fs.clone(), 150);
        assert_eq!(metered.read(Utf8Path::new("big")).await.unwrap().len(), 100);
        assert!(metered.is_file(Utf8Path::new("big")).await);
        assert!(metered.exists(Utf8Path::new("big")).await);
        let err = metered.read(Utf8Path::new("big")).await.unwrap_err().to_string();
        assert!(err.contains("loading the project reads more than"), "{err}");
        // A file the bundle does not hold is refused as such, not charged.
        let err = metered.read(Utf8Path::new("missing")).await.unwrap_err().to_string();
        assert!(err.contains("not in the bundle"), "{err}");
        assert_eq!(fs.read(Utf8Path::new("big")).await.unwrap().len(), 100);
    }

    /// The `ic` environment of the bundle `bytes`, as a deploy would load
    /// it: extracted, then read through the host.
    async fn environment(bytes: &[u8]) -> (tempfile::TempDir, BundleFs, Environment) {
        let (dir, into) = scratch();
        let fs = extract_bundle(bytes, &into).unwrap();
        let env = host_for(fs.clone())
            .get_environment(&EnvironmentSelection::Named("ic".into()))
            .await
            .unwrap();
        (dir, fs, env)
    }

    fn check(
        fs: &BundleFs,
        env: &Environment,
        wasm_in_all: u64,
        plugin_input: u64,
    ) -> Result<(), String> {
        check_bundle_within(
            fs,
            &env.network,
            env.canisters.values().map(|(dir, canister)| (dir.as_path(), canister)),
            wasm_in_all,
            plugin_input,
        )
    }

    // A module is read, hashed and expanded once however many canisters name
    // it, by whatever spelling: the sum of the expansions is a sum over the
    // archive's files, so a manifest cannot multiply the work by repeating
    // itself.
    #[tokio::test]
    async fn a_module_is_checked_once_however_many_canisters_name_it() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&[0u8; 4096]).unwrap();
        let gz = encoder.finish().unwrap();
        let sha = hex::encode(Sha256::digest(&gz));
        let canister = |name: &str, path: &str| {
            format!(
                "  - name: {name}\n    build:\n      steps:\n        - type: pre-built\n          \
                 path: {path}\n          sha256: {sha}\n"
            )
        };

        // Three canisters, one module, two spellings: expanded once.
        let manifest = format!(
            "canisters:\n{}{}{}",
            canister("a", "m.wasm.gz"),
            canister("b", "./m.wasm.gz"),
            canister("c", "m.wasm.gz")
        );
        let bytes = archive(&[("icp.yaml", manifest.as_bytes()), ("m.wasm.gz", &gz)]);
        let (_dir, fs, env) = environment(&bytes).await;
        check(&fs, &env, 4096, MAX_PLUGIN_INPUT_BYTES).unwrap();

        // The same bytes at two paths are two modules: expanded twice, and
        // the sum holds.
        let manifest =
            format!("canisters:\n{}{}", canister("a", "m.wasm.gz"), canister("b", "n.wasm.gz"));
        let bytes =
            archive(&[("icp.yaml", manifest.as_bytes()), ("m.wasm.gz", &gz), ("n.wasm.gz", &gz)]);
        let (_dir, fs, env) = environment(&bytes).await;
        let err = check(&fs, &env, 4096, MAX_PLUGIN_INPUT_BYTES).unwrap_err();
        assert!(err.contains("canister 'b'") && err.contains("in all"), "{err}");
        check(&fs, &env, 8192, MAX_PLUGIN_INPUT_BYTES).unwrap();
    }

    // What a sync step hands its plugin is held to the bundle at the load,
    // by the vet — each entry under the root, through no link, present, of
    // the kind declared — and the files the runtime will read are held to a
    // sum here, counting a file each time it is declared.
    #[tokio::test]
    async fn a_sync_step_declares_what_the_bundle_holds() {
        let wasm = wat::parse_str("(module)").unwrap();
        let sha = hex::encode(Sha256::digest(&wasm));
        let bundle = |declared: &str| {
            let canister = format!(
                "name: backend\nbuild:\n  steps:\n    - type: pre-built\n      path: backend.wasm\n      \
                 sha256: {sha}\nsync:\n  steps:\n    - type: plugin\n      path: plugin.wasm\n{declared}"
            );
            archive(&[
                ("icp.yaml", b"canisters:\n  - canisters/backend\n"),
                ("canisters/backend/canister.yaml", canister.as_bytes()),
                ("canisters/backend/backend.wasm", &wasm),
                ("canisters/backend/plugin.wasm", &wasm),
                ("canisters/backend/config.txt", b"0123456789"),
                ("canisters/backend/assets/index.html", b"<html>"),
                ("shared/common.txt", b"abc"),
            ])
        };
        let all = (MAX_WASM_BYTES_IN_ALL, MAX_PLUGIN_INPUT_BYTES);

        let accepted = [
            "      files:\n        config: config.txt\n        seed: assets\n",
            "      files:\n        shared: ../../shared/common.txt\n",
            "      dirs:\n        - assets\n      files:\n        - config.txt\n",
        ];
        for declared in accepted {
            let (_dir, fs, env) = environment(&bundle(declared)).await;
            check(&fs, &env, all.0, all.1).unwrap_or_else(|e| panic!("{declared}: {e}"));
        }

        // A file that is not there, a file where a directory is declared, an
        // absolute path, a path climbing out: each fails the load, before
        // the check could read anything.
        let refused = [
            ("      files:\n        config: missing.txt\n", "missing.txt"),
            ("      dirs:\n        - config.txt\n", "config.txt"),
            ("      files:\n        etc: /etc/passwd\n", "/etc/passwd"),
            ("      files:\n        up: ../../../x\n", "x"),
        ];
        for (declared, named) in refused {
            let (_dir, into) = scratch();
            let fs = extract_bundle(&bundle(declared), &into).unwrap();
            let err = chain(&host_for(fs).project.load().await.expect_err(declared));
            assert!(
                err.contains("gives its sync plugin") && err.contains(named),
                "{declared}: {err}"
            );
        }

        // Ten bytes declared twice are twenty; a directory costs nothing.
        let declared =
            "      files:\n        a: config.txt\n        b: config.txt\n        seed: assets\n";
        let (_dir, fs, env) = environment(&bundle(declared)).await;
        let err = check(&fs, &env, all.0, 19).unwrap_err();
        assert!(err.contains("`files:` hold more than 19 bytes in all"), "{err}");
        check(&fs, &env, all.0, 20).unwrap();
    }
}
