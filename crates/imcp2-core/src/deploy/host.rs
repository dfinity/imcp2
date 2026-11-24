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
//!   ([`extract_bundle_from`]), and refuses the `.icp` state a deploy seeds
//!   for itself: the library takes what is under `.icp` as its own earlier
//!   writes, and vets none of it. The archive is read as a stream — a file,
//!   or a request body as it arrives — and never held whole, and the size
//!   budget is in the bytes a bundle occupies ([`occupies`]), which is what
//!   it costs a server that keeps it in memory. How large is the server's
//!   to say ([`BundleLimits`]).
//! * **A sync plugin is run only if the server knows it**, where the server
//!   deploys for others ([`AllowedPlugins`]): by the hash of its module, on
//!   the upload ([`vet_plugins`]) and again before the deploy
//!   ([`check_bundle`]).
//! * **What the deploy adds to the directory is counted with it**: the copy
//!   of each canister's module the build keeps beside the bundle, held to
//!   the same budget before any is made ([`check_bundle`]).
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
//! This crate is that consumer, on the 0.1 release of the icp CLI's crates.
//!
//! Everything the project library reads or writes — the manifest, the wasms,
//! the `.icp` id and artifact stores, the build scratch — lives under the
//! extracted directory, which is removed when the deploy ends.

use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::Read,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use crate::guard_candid_text;
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

/// The unit a filesystem keeps a file's bytes in: a file of one byte takes a
/// whole one, in memory where the filesystem is a RAM one (a page) as on a
/// disk (a block).
pub const BLOCK_BYTES: u64 = 4096;

/// What a file or a directory costs besides its bytes — its inode and its
/// name — as this crate counts it: about what a RAM filesystem holds in
/// kernel memory for each.
pub const ENTRY_BYTES: u64 = 1024;

/// What a file of `len` bytes occupies where it is extracted to, or (with a
/// `len` of zero) a directory: its bytes in whole blocks, and its entry.
/// This is what a bundle's size is counted in. The sum of the files' own
/// sizes would say that a quarter of a million one-byte files come to a
/// quarter of a megabyte, where they hold a gigabyte of pages.
pub fn occupies(len: u64) -> u64 {
    len.div_ceil(BLOCK_BYTES).saturating_mul(BLOCK_BYTES).saturating_add(ENTRY_BYTES)
}

/// How large a bundle a server takes. The constants above are what a server
/// on the user's own machine takes ([`BundleLimits::LOCAL`]): the disk is the
/// user's and so is the bundle. A server that deploys for others, and keeps
/// what it extracts in memory, sets its own ([`BundleLimits::new`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BundleLimits {
    /// The most an archive may be, compressed, in bytes.
    pub archive_bytes: u64,
    /// The most a deploy's directory may come to, in bytes, counted as what
    /// its files and directories occupy ([`occupies`]): what the archive
    /// extracts to and, with that, the copy of each canister's module that
    /// the deploy keeps beside the bundle (see [`check_bundle`], and there
    /// for the scratch copies a build holds briefly, which are not counted).
    pub extracted_bytes: u64,
    /// The most files and directories an archive may extract to.
    pub entries: usize,
}

impl BundleLimits {
    /// What a server on the user's own machine takes.
    pub const LOCAL: Self = Self {
        archive_bytes: MAX_BUNDLE_BYTES as u64,
        extracted_bytes: MAX_EXTRACTED_BYTES,
        entries: MAX_BUNDLE_ENTRIES,
    };

    /// Limits of `archive_bytes` compressed and `extracted_bytes` extracted.
    /// An archive is never larger than what it extracts to, so the first is
    /// held to the second.
    pub fn new(archive_bytes: u64, extracted_bytes: u64) -> Self {
        Self {
            archive_bytes: archive_bytes.min(extracted_bytes),
            extracted_bytes,
            entries: MAX_BUNDLE_ENTRIES,
        }
    }

    /// What loading the project may read in all ([`MAX_PROJECT_BYTES`]), and
    /// no more than the bundle may hold.
    fn project_bytes(&self) -> u64 {
        MAX_PROJECT_BYTES.min(self.extracted_bytes)
    }

    /// What the decompressed stream may come to. Not what is kept — that is
    /// the entries, counted as they are written — but what is read through:
    /// an archive's framing (a header and padding for each entry, more for a
    /// long name) on top of its contents. Several times the contents' own
    /// limit covers any real archive, and is what bounds the work of reading
    /// one that is mostly padding.
    fn stream_bytes(&self) -> u64 {
        self.extracted_bytes.saturating_mul(3).saturating_add(1024 * 1024)
    }
}

impl Default for BundleLimits {
    fn default() -> Self {
        Self::LOCAL
    }
}

/// What one run of a sync plugin is held to, for a server to set: a project
/// cannot. Each is the icp CLI's own limit (`icp_sync_plugin::Limits`), and
/// one left `None` is the CLI's default — which stops nothing a plugin does
/// today, and is what a server on the user's own machine runs with.
///
/// A plugin runs inside the server's own process, as many at once as deploys
/// do, so a server that deploys for others sizes these to what it has.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PluginLimits {
    /// Linear memory, in bytes, summed across every memory the plugin has.
    /// A growth past it is refused, as a wasm `memory.grow` that fails. The
    /// CLI's default is 4 GiB, what one wasm32 memory can reach anyway.
    pub memory_bytes: Option<u64>,
    /// CPU time, in whole seconds: the time the plugin's wasm runs, with
    /// what it spends waiting on a canister call given back. The CLI's
    /// default is 60. A plugin waiting on the host is never charged, so
    /// this alone does not bound a run; [`Self::wall_clock`] does.
    pub compute_secs: Option<u64>,
    /// How long one run may take from start to finish, canister calls and
    /// anything else the plugin waits on included. The CLI's default is no
    /// limit.
    pub wall_clock: Option<Duration>,
}

impl PluginLimits {
    /// These, as the runtime takes them.
    fn runtime(&self) -> icp_sync_plugin::Limits {
        let mut limits = icp_sync_plugin::Limits::default();
        if let Some(bytes) = self.memory_bytes {
            limits.memory_bytes = bytes;
        }
        if let Some(secs) = self.compute_secs {
            limits.compute_secs = secs;
        }
        if let Some(wall_clock) = self.wall_clock {
            limits.wall_clock = Some(wall_clock);
        }
        limits
    }
}

/// The sync plugins a server that deploys for others runs unless it is told
/// otherwise, each by the sha256 of its module and what it is.
///
/// A sync plugin is a program the bundle brings and the server runs: it is
/// held to a sandbox (WASI, its own deploy directory read-only, no network)
/// and to the limits the server sets ([`PluginLimits`]), but it runs inside
/// the server's own process. So a server whose bundles are not its user's
/// own runs the plugins it knows, and no others.
/// A plugin is known by what it is — the hash of its bytes, which is also
/// what `icp project bundle` records for it — never by the name or path the
/// bundle gives it, which are the bundle's to choose.
pub const KNOWN_PLUGINS: [(&str, &str); 3] = [
    (
        "6deedcc2127a3bda014af9e08aff83ee58c95125050acb296676aa234906a08e",
        "the static-site sync plugin, v1.0.0",
    ),
    (
        "afb5d626761e891a42e5c36e8799bf521823de9f55c5102860bd3a237d3b164f",
        "the static-site sync plugin, v0.4.3",
    ),
    (
        "ca7cb5666c30d2875f8d5e10535f8a53f97a86c79c263f7d5bdac2fdd1bbf83c",
        "the asset canister sync plugin",
    ),
];

/// Which sync plugins a server runs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AllowedPlugins {
    /// Whatever the bundle brings: for a server on the user's own machine,
    /// where the bundle and what it runs are the user's own.
    #[default]
    Any,
    /// Those whose module hashes to one of these (lowercase hex sha256, with
    /// what each is), and no others. With none listed, a bundle with any
    /// sync plugin is refused; one with none deploys as ever.
    Only(Arc<BTreeMap<String, String>>),
}

impl AllowedPlugins {
    /// [`KNOWN_PLUGINS`], and no others.
    pub fn known() -> Self {
        Self::known_and(std::iter::empty::<&str>()).expect("the built-in hashes are well formed")
    }

    /// [`KNOWN_PLUGINS`] and `more`, each the sha256 of a plugin's module in
    /// hex: what a server's operator adds, for a plugin release newer than
    /// this build. Refused whole if one is not a sha256.
    pub fn known_and(more: impl IntoIterator<Item = impl AsRef<str>>) -> Result<Self, String> {
        let mut allowed: BTreeMap<String, String> =
            KNOWN_PLUGINS.iter().map(|(sha, what)| (sha.to_string(), what.to_string())).collect();
        for sha in more {
            let sha = sha.as_ref().trim().to_ascii_lowercase();
            if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!(
                    "'{sha}' is not the sha256 of a plugin: 64 hexadecimal characters"
                ));
            }
            allowed.entry(sha).or_insert_with(|| "allowed by this server's configuration".into());
        }
        Ok(Self::Only(Arc::new(allowed)))
    }

    /// Whether a plugin whose module hashes to `sha256` (hex) is one this
    /// server runs.
    pub fn allows(&self, sha256: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Only(allowed) => allowed.contains_key(&sha256.to_ascii_lowercase()),
        }
    }

    /// Refuse the plugin at `path` whose module hashes to `sha256`, unless
    /// it is one this server runs: with what it is, and what would be.
    fn check(&self, path: &Utf8Path, sha256: &str) -> Result<(), Unsupported> {
        if self.allows(sha256) {
            return Ok(());
        }
        let Self::Only(allowed) = self else { return Ok(()) };
        let runs = match allowed.is_empty() {
            true => "it runs no sync plugin".to_string(),
            false => format!(
                "it runs: {}",
                allowed
                    .iter()
                    .map(|(sha, what)| format!("{what} ({sha})"))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        };
        Err(Unsupported(format!(
            "its sync plugin '{path}' (sha256 {sha256}) is not one this server runs; {runs}. A \
             sync plugin is a program the server runs for the bundle, so a server that deploys \
             for others runs only the releases it knows: use one of them, or deploy this \
             bundle with a server of your own"
        )))
    }
}

/// Why an uploaded bundle is not one a server will deploy, found before any
/// deploy is asked for: see [`vet_plugins`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VetError {
    /// The project does not load: it is not a bundle a deploy could run.
    NotABundle(String),
    /// It carries a sync plugin this server does not run.
    PluginNotAllowed(String),
}

/// Hold a bundle just extracted to the plugins a server runs, before any
/// deploy is asked for: every sync plugin of every canister the project
/// declares, whichever environment a deploy would later name. A bundle that
/// carries a plugin the server does not run is refused whole — it is not
/// deployed in part — and the project is loaded to find them, so one that
/// does not load is refused here as well, with the loader's reason.
///
/// This is the early word, on the upload. [`check_bundle`] holds the deploy
/// itself to the same list, on what it is about to run.
pub async fn vet_plugins(
    fs: &BundleFs,
    limits: &BundleLimits,
    plugins: &AllowedPlugins,
) -> Result<(), VetError> {
    if *plugins == AllowedPlugins::Any {
        return Ok(());
    }
    let project =
        host_for(fs.clone(), limits, PluginLimits::default()).project.load().await.map_err(
            |e| {
                let mut why = e.to_string();
                let mut source = std::error::Error::source(&e);
                while let Some(cause) = source {
                    why.push_str(": ");
                    why.push_str(&cause.to_string());
                    source = cause.source();
                }
                VetError::NotABundle(why)
            },
        )?;
    // Each module is hashed once, however many canisters name it.
    let mut hashes: BTreeMap<Utf8PathBuf, String> = BTreeMap::new();
    for (dir, canister) in project.canisters.values() {
        let at = |e: Unsupported| format!("canister '{}': {e}", canister.name);
        for step in &canister.sync.steps {
            let SyncStep::Plugin(plugin) = step else { continue };
            let SourceField::Local(local) = &plugin.source else {
                return Err(VetError::NotABundle(at(Unsupported(
                    "synced by a remote plugin, which a bundle never is; rebuild the bundle \
                     with `icp project bundle`"
                        .into(),
                ))));
            };
            let on_disk =
                locate(fs, &dir.join(&local.path)).map_err(|e| VetError::NotABundle(at(e)))?;
            let sha256 = match hashes.get(&on_disk) {
                Some(sha256) => sha256.clone(),
                None => {
                    let sha256 = sha256_of(&on_disk).map_err(|e| VetError::NotABundle(at(e)))?;
                    hashes.insert(on_disk, sha256.clone());
                    sha256
                }
            };
            plugins.check(&local.path, &sha256).map_err(|e| VetError::PluginNotAllowed(at(e)))?;
        }
    }
    Ok(())
}

/// The sha256 of the file at `path`, in hex, read through rather than into
/// memory: a module may be as large as a bundle.
fn sha256_of(path: &Utf8Path) -> Result<String, Unsupported> {
    let unreadable = |e: std::io::Error| Unsupported(format!("'{path}': {e}"));
    let mut file = std::fs::File::open(path).map_err(unreadable)?;
    let mut hasher = Sha256::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        match file.read(&mut chunk).map_err(unreadable)? {
            0 => break,
            n => hasher.update(&chunk[..n]),
        }
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Why an archive was not extracted. The kinds are what a server answers and
/// counts differently: which limit was passed, the sender's side of the
/// transfer, an archive that is not a bundle, and the server's own storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractError {
    /// The archive is larger, compressed, than the limit (the value).
    ArchiveTooLarge(u64),
    /// The archive extracts to more than the limit (the value).
    ExtractsTooLarge(u64),
    /// The archive could not be read to its end: the transfer failed.
    Source(String),
    /// What arrived is not a bundle: not a `.tar.gz`, an entry a bundle
    /// never carries, too many entries, no manifest.
    NotABundle(String),
    /// What was extracted could not be written.
    Storage(String),
}

impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArchiveTooLarge(max) => {
                write!(f, "the bundle archive is larger than the {max} byte limit")
            }
            Self::ExtractsTooLarge(max) => {
                write!(f, "the bundle extracts to more than the {max} byte limit")
            }
            Self::Source(why) => write!(f, "the bundle could not be read to its end: {why}"),
            Self::NotABundle(why) => f.write_str(why),
            Self::Storage(why) => write!(f, "the bundle could not be extracted: {why}"),
        }
    }
}

/// A bundle just extracted: the filesystem a deploy reads it through, and
/// how much there was of it.
pub struct Extracted {
    pub fs: BundleFs,
    /// What its files and directories occupy ([`occupies`]).
    pub bytes: u64,
    /// How much was read of the archive, compressed.
    pub archive_bytes: u64,
}

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
    budget: u64,
}

impl Metered {
    fn new(inner: BundleFs, budget: u64) -> Self {
        Self { inner, left: Mutex::new(budget), budget }
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
                self.budget
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
    let mut decoder =
        Limited { inner: flate2::read::GzDecoder::new(bytes), left: limit, tripped: None };
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
///
/// And the directory the deploy will fill is held to
/// [`BundleLimits::extracted_bytes`] before it is filled: the build keeps a
/// copy of each canister's module beside the bundle (the library's artifact
/// store, one file per canister name), so a manifest of fifty canisters
/// naming one module would have the deploy write it fifty times over.
/// `bundle_bytes` is what the bundle itself extracted to; with the copies it
/// may come to the limit and no more.
///
/// One thing is in the directory and not in that count. While a canister is
/// being built, the library holds a second copy of its module there — the
/// build's scratch output (`.scratch-*/out.wasm`), written before the
/// artifact is saved and removed as that canister's build returns — and the
/// canisters are built at once. So for the length of the build phase a
/// deploy's directory can pass the limit by what its modules come to: at
/// most half the limit again, since the bundle and the counted copies hold
/// each module twice within it. That is left uncounted on purpose, as the
/// lesser cost: counted, the largest module a server takes would fall from
/// half the limit to a third. A server whose state directory is a RAM
/// filesystem leaves that much headroom for each deploy it runs at once
/// (see the README's "Deploying a project bundle").
///
/// And every sync plugin a canister of the environment names is one the
/// server runs (`plugins`), by the hash of the module that is about to run.
/// An upload was held to the same list as it arrived ([`vet_plugins`]); this
/// is the check that counts, made on the deploy's own directory, for the
/// canisters it is deploying, immediately before it deploys them.
pub fn check_bundle<'a>(
    fs: &BundleFs,
    network: &Network,
    canisters: impl IntoIterator<Item = (&'a Utf8Path, &'a Canister)>,
    bundle_bytes: u64,
    limits: &BundleLimits,
    plugins: &AllowedPlugins,
) -> Result<(), String> {
    check_bundle_within(
        fs,
        network,
        canisters,
        limits.extracted_bytes.min(MAX_WASM_BYTES_IN_ALL),
        MAX_PLUGIN_INPUT_BYTES,
        (bundle_bytes, limits.extracted_bytes),
        plugins,
    )
}

/// [`check_bundle`] with the two sums as parameters, so a test can reach
/// them without a gigabyte of modules.
fn check_bundle_within<'a>(
    fs: &BundleFs,
    network: &Network,
    canisters: impl IntoIterator<Item = (&'a Utf8Path, &'a Canister)>,
    wasm_in_all: u64,
    plugin_input: u64,
    (bundle_bytes, directory_bytes): (u64, u64),
    plugins: &AllowedPlugins,
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
    let mut verified = Verified { hashes: BTreeMap::new(), wasm_left: wasm_in_all, wasm_in_all };
    // What the deploy's directory will hold: the bundle, and a copy of its
    // module for each canister.
    let mut directory = bundle_bytes;
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
        let module = locate(fs, &dir.join(&local.path))
            .and_then(|on_disk| {
                std::fs::metadata(&on_disk).map_err(|e| Unsupported(format!("'{on_disk}': {e}")))
            })
            .map_err(at)?
            .len();
        directory = directory.saturating_add(occupies(module));
        if directory > directory_bytes {
            return Err(format!(
                "the bundle comes to more than the {directory_bytes} bytes this server holds for \
                 one deploy, counting the copy of each canister's module the deploy keeps \
                 beside it (canister '{name}' is where it passes that); make the bundle \
                 smaller, for one by gzip-compressing its modules"
            ));
        }
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
            // By what the module is, not by what the manifest says of it:
            // the hash just taken of the bytes that will run.
            plugins.check(&local.path, &actual).map_err(at)?;
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
    /// What they may expand to in all, for the refusal to name.
    wasm_in_all: u64,
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
                "the bundle's gzip-compressed modules expand to more than {} bytes in all, \
                 more than a bundle extracts to",
                self.wasm_in_all
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
/// Each sync plugin the deploy runs is held to `plugin_limits` by the
/// runtime (`icp-sync-plugin`'s wasmtime runner): its memory, its CPU time
/// and how long it may take. Left at the icp CLI's defaults, a plugin may
/// allocate up to its address space — which is one reason a server that
/// deploys for others also runs only the plugins it knows
/// ([`AllowedPlugins`]).
///
/// What is not bounded here: the number of canisters or steps a manifest
/// declares. The phases do their work once per canister, and each canister
/// costs the caller the cycles that create it.
pub fn host_for(fs: BundleFs, limits: &BundleLimits, plugin_limits: PluginLimits) -> Host {
    host_within(fs, limits.project_bytes(), plugin_limits)
}

/// [`host_for`] with the project-loading budget as a parameter, so a test can
/// reach it without a quarter of a gigabyte of argument files.
fn host_within(fs: BundleFs, project_bytes: u64, plugin_limits: PluginLimits) -> Host {
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
            Arc::new(icp_sync_plugin::Wasmtime::new(plugin_limits.runtime())),
        )),
        wasm,
        network: Arc::new(IcMainnet),
        random: Arc::new(HostRandom),
        observer: Arc::new(Ignore),
    }
}

/// Extract a bundle archive, read from `archive`, into `into`, which must
/// exist and be empty, and return it as the filesystem the deploy reads
/// through, confined to it.
///
/// The archive is read as a stream and written as it is read: it is never
/// held whole, in memory or on disk, so a caller may hand in a request body
/// as it arrives. Both of its sizes are held as it goes — the compressed
/// bytes read, to [`BundleLimits::archive_bytes`], and what the entries
/// occupy ([`occupies`]), to [`BundleLimits::extracted_bytes`], each entry
/// counted from its header before a byte of it is written — and reading
/// stops at the byte that passes either. What was written by then is the caller's to remove, with
/// the directory.
///
/// Only regular files and directories are written — `icp project bundle`
/// writes nothing else, and a symlink or a device node is how an archive
/// reaches past its directory — and no more of them, with the directories
/// their paths imply, than [`BundleLimits::entries`]. `tar` refuses entry
/// paths that would land outside `into`. What it extracts is then required
/// to look like a bundle, i.e. to carry a project manifest at its root. The
/// archive is read to its end either way, so that a sender is heard out.
pub fn extract_bundle_from(
    archive: impl Read,
    into: &Utf8Path,
    limits: &BundleLimits,
) -> Result<Extracted, ExtractError> {
    let meter = Meter::default();
    let extracted_bytes = limits.extracted_bytes;
    let source = Source { inner: archive, left: limits.archive_bytes, limits, meter: &meter };
    let result = extract_stream(source, into, limits, &meter);
    // A reader that stopped the extraction says why itself: what `tar` or
    // the decoder made of its error is only that something went wrong.
    match (meter.tripped.take(), result) {
        (Some(why), _) => Err(why),
        (None, Err(why)) => Err(why),
        (None, Ok((fs, bytes))) => {
            debug_assert!(bytes <= extracted_bytes);
            Ok(Extracted { fs, bytes, archive_bytes: meter.archive.get() })
        }
    }
}

/// [`extract_bundle_from`] for an archive already in memory, under the local
/// limits and with the refusal as a sentence.
#[cfg(test)]
pub fn extract_bundle(bytes: &[u8], into: &Utf8Path) -> Result<BundleFs, String> {
    extract_bundle_within(bytes, into, MAX_BUNDLE_ENTRIES)
}

/// [`extract_bundle`] with the files-and-directories cap as a parameter, so a
/// test can reach it without writing a quarter of a million files.
#[cfg(test)]
fn extract_bundle_within(
    bytes: &[u8],
    into: &Utf8Path,
    max_entries: usize,
) -> Result<BundleFs, String> {
    let limits = BundleLimits { entries: max_entries, ..BundleLimits::LOCAL };
    extract_bundle_from(bytes, into, &limits).map(|e| e.fs).map_err(|e| e.to_string())
}

/// The filesystem a deploy reads a bundle through, over a directory a bundle
/// was already extracted into by [`extract_bundle_from`] (an upload, taken
/// by its deploy): confined to it, like one just extracted.
pub fn open_bundle(dir: &Utf8Path) -> Result<BundleFs, String> {
    confined(dir).map_err(|e| e.to_string())
}

/// `into`, as the confined filesystem everything below it is read through.
fn confined(into: &Utf8Path) -> Result<BundleFs, ExtractError> {
    // A link is refused on the way in, so nothing under the root leads out
    // of it; should one appear later, the filesystem refuses any path
    // through it. The root is held as spelled: it and everything above it
    // are this crate's own (macOS keeps its temporary directories under
    // `/var`, a link to `/private/var`), and only what lies below is held
    // to shape.
    Confined::new(into).map_err(|e| {
        let mut why = e.to_string();
        if let Some(cause) = std::error::Error::source(&e) {
            why.push_str(": ");
            why.push_str(&cause.to_string());
        }
        ExtractError::Storage(format!("the extraction directory cannot be confined to: {why}"))
    })
}

/// What the readers of one extraction share with it: how much of the archive
/// has been read, and the reason one of them stopped it.
#[derive(Default)]
struct Meter {
    archive: Cell<u64>,
    tripped: Cell<Option<ExtractError>>,
}

impl Meter {
    /// Record why the extraction stops, unless something already has, and
    /// return the error a reader stops it with.
    fn trip(&self, why: ExtractError) -> std::io::Error {
        let said = why.to_string();
        let first = self.tripped.take().unwrap_or(why);
        self.tripped.set(Some(first));
        std::io::Error::other(said)
    }
}

/// The archive as it is read: counted, held to the archive limit, and its
/// own failures — the sender's — told apart from the archive's contents.
struct Source<'a, R> {
    inner: R,
    left: u64,
    limits: &'a BundleLimits,
    meter: &'a Meter,
}

impl<R: Read> Read for Source<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = match self.inner.read(buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => return Err(e),
            Err(e) => return Err(self.meter.trip(ExtractError::Source(e.to_string()))),
        };
        if n as u64 > self.left {
            return Err(self.meter.trip(ExtractError::ArchiveTooLarge(self.limits.archive_bytes)));
        }
        self.left -= n as u64;
        self.meter.archive.set(self.meter.archive.get() + n as u64);
        Ok(n)
    }
}

/// The body of [`extract_bundle_from`]: the filesystem, and the sum of the
/// entries' sizes.
fn extract_stream<R: Read>(
    source: Source<'_, R>,
    into: &Utf8Path,
    limits: &BundleLimits,
    meter: &Meter,
) -> Result<(BundleFs, u64), ExtractError> {
    let max_entries = limits.entries;
    let fs = confined(into)?;
    // An error writing is the server's; any other is the archive's.
    let unreadable = |e: std::io::Error| {
        use std::io::ErrorKind::{
            PermissionDenied, QuotaExceeded, ReadOnlyFilesystem, StorageFull,
        };
        match e.kind() {
            StorageFull | QuotaExceeded | PermissionDenied | ReadOnlyFilesystem => {
                ExtractError::Storage(e.to_string())
            }
            _ => ExtractError::NotABundle(format!(
                "the bundle is not a readable .tar.gz archive: {e}"
            )),
        }
    };
    let too_large = || ExtractError::ExtractsTooLarge(limits.extracted_bytes);
    let decoder = Limited {
        inner: flate2::read::GzDecoder::new(source),
        left: limits.stream_bytes(),
        tripped: Some((meter, limits.extracted_bytes)),
    };
    let mut archive = tar::Archive::new(decoder);
    let mut total: u64 = 0;
    // Files and directories written so far, counting each directory an
    // entry's path implies: `unpack_in` creates the missing parents of every
    // entry, so a few files at the bottom of long, distinct directory chains
    // would otherwise cost inodes the entry count never sees.
    let mut objects: usize = 0;
    let too_many = || {
        ExtractError::NotABundle(format!(
            "the bundle holds more than {max_entries} files and directories, more than a bundle \
             ever has"
        ))
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
        let path = Utf8PathBuf::from_path_buf(path).map_err(|p| {
            ExtractError::NotABundle(format!("the archive entry '{}' is not UTF-8", p.display()))
        })?;
        if path.as_str().len() > MAX_ENTRY_PATH_BYTES {
            return Err(ExtractError::NotABundle(format!(
                "an archive entry's path is {} bytes long, more than the {MAX_ENTRY_PATH_BYTES} \
                 a path can be",
                path.as_str().len()
            )));
        }
        if !(kind.is_file() || kind.is_dir()) {
            return Err(ExtractError::NotABundle(format!(
                "the archive entry '{path}' is not a regular file or directory ({kind:?}), which \
                 a bundle never carries; rebuild it with `icp project bundle`"
            )));
        }
        // Where the entry lands, relative to the root: `tar` refuses a path
        // that would leave `into`, so resolving it against the root is only
        // a matter of spelling (`./x` is `x`).
        let rel = match fs.resolve(&path) {
            Ok(resolved) => resolved.strip_prefix(fs.root()).unwrap_or(&resolved).to_path_buf(),
            Err(_) => {
                return Err(ExtractError::NotABundle(format!(
                    "the archive entry '{path}' would land outside the extraction directory"
                )))
            }
        };
        // `.icp` is the library's own state under the project root: the id
        // mappings a deploy reads to decide what exists, and the artifact
        // store. A bundle never carries it (`icp project bundle` writes
        // manifests, modules, plugins, argument files and images), and one
        // that did could point a deploy at canisters the caller never named.
        // Compared without regard to case: on a case-insensitive disk `.ICP`
        // is the same directory. This is the refusal that names the entry,
        // made before it is written; a spelling it does not know that the
        // disk takes for the same name is caught once the archive is out
        // ([`refuse_state`]).
        if rel.components().next().is_some_and(|c| c.as_str().eq_ignore_ascii_case(STATE_DIR)) {
            return Err(ExtractError::NotABundle(format!(
                "the archive entry '{path}' is under `{STATE_DIR}/`, the project state a bundle \
                 never carries; rebuild it with `icp project bundle`"
            )));
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
        // What the entry will occupy, and each directory made on the way to
        // it, known from the header: refused before any of it is written.
        total = total
            .saturating_add(occupies(entry.size()))
            .saturating_add(ENTRY_BYTES.saturating_mul(implied.len() as u64));
        if total > limits.extracted_bytes {
            return Err(too_large());
        }
        if entry.unpack_in(fs.root().as_std_path()).map_err(unreadable)? {
            // The mode the archive names for the entry is replaced at once,
            // before the next entry is written under it: the tree is the
            // server's to read and to remove, and a directory an archive
            // marked read-only would be neither (see `own`).
            own(fs.root().join(&rel).as_std_path()).map_err(|e| {
                ExtractError::Storage(format!(
                    "the archive entry '{path}' could not be made the server's own: {e}"
                ))
            })?;
            dirs.extend(implied);
            if kind.is_dir() {
                dirs.insert(rel);
            }
        }
    }
    // The rest of the stream is read through, both limits still holding: an
    // archive ends in padding, and may be followed by more, and a sender
    // whose body is left half-read sees its connection cut, not an answer.
    let mut decoder = archive.into_inner();
    std::io::copy(&mut decoder, &mut std::io::sink()).map_err(unreadable)?;
    let mut source = decoder.inner.into_inner();
    std::io::copy(&mut source, &mut std::io::sink()).map_err(unreadable)?;
    refuse_state(fs.root())?;
    if !fs.root().join(PROJECT_MANIFEST).is_file() {
        return Err(ExtractError::NotABundle(format!(
            "the archive carries no `{PROJECT_MANIFEST}` at its root, so it is not an icp \
             project bundle (`icp project bundle` writes one)"
        )));
    }
    Ok((fs, total))
}

/// Refuse an extraction that left the library's state directory under
/// `root`, whatever the archive called it.
///
/// The entries were compared with the name as they were read, but a name is
/// the disk's to interpret: Windows takes `.icp.`, `.icp ` and
/// `.icp::$INDEX_ALLOCATION` for `.icp`, and another filesystem may fold a
/// spelling this code has not heard of. So the question is asked of the disk,
/// which answers for every spelling it honours: the directory was empty
/// before the archive was written into it, and nothing but the archive has
/// written there since.
fn refuse_state(root: &Utf8Path) -> Result<(), ExtractError> {
    match std::fs::symlink_metadata(root.join(STATE_DIR)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ExtractError::Storage(format!(
            "whether the archive wrote `{STATE_DIR}/` could not be told: {e}"
        ))),
        Ok(_) => Err(ExtractError::NotABundle(format!(
            "the archive wrote `{STATE_DIR}/`, the project state a bundle never carries, under \
             another spelling of the name; rebuild it with `icp project bundle`"
        ))),
    }
}

/// Give an extracted file or directory the mode everything a deploy writes
/// has: the owner's alone, readable and — a directory — writable and
/// searchable, so that it can be removed. Which it is is read off the disk,
/// not the entry's header: an old-style header for a regular file whose name
/// ends in `/` is unpacked as a directory. An archive holds regular files
/// and directories only, so `path` is never a link, and is not followed.
#[cfg(unix)]
fn own(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let kind = std::fs::symlink_metadata(path)?.file_type();
    let mode = match (kind.is_dir(), kind.is_file()) {
        (true, _) => 0o700,
        (_, true) => 0o600,
        _ => return Ok(()),
    };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn own(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

/// A reader that fails once more than `left` bytes have passed through it:
/// the decompressed stream's own bound, independent of what the entry
/// headers claim. In an extraction it says so to the extraction's meter,
/// with the limit that was passed.
struct Limited<'a, R> {
    inner: R,
    left: u64,
    tripped: Option<(&'a Meter, u64)>,
}

impl<R: Read> Read for Limited<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n as u64 > self.left {
            return Err(match self.tripped {
                Some((meter, limit)) => meter.trip(ExtractError::ExtractsTooLarge(limit)),
                None => std::io::Error::other("more than the limit"),
            });
        }
        self.left -= n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a server sets reaches the runtime, and what it leaves unset is
    /// the icp CLI's own default.
    #[test]
    fn plugin_limits_are_the_runtimes_unless_set() {
        assert_eq!(PluginLimits::default().runtime(), icp_sync_plugin::Limits::default());
        let set = PluginLimits {
            memory_bytes: Some(256 << 20),
            compute_secs: Some(30),
            wall_clock: Some(Duration::from_secs(600)),
        }
        .runtime();
        assert_eq!(set.memory_bytes, 256 << 20);
        assert_eq!(set.compute_secs, 30);
        assert_eq!(set.wall_clock, Some(Duration::from_secs(600)));
        assert_eq!(set.table_elements, icp_sync_plugin::Limits::default().table_elements);
    }
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
        // Held to the archive limit as it is read, since a stream has no
        // length to check first: an archive one byte over is stopped.
        let bytes = archive(&[("icp.yaml", b"canisters: []\n")]);
        let over = BundleLimits { archive_bytes: bytes.len() as u64 - 1, ..BundleLimits::LOCAL };
        let err = extract_bundle_from(&bytes[..], &into, &over).err().unwrap();
        assert_eq!(err, ExtractError::ArchiveTooLarge(bytes.len() as u64 - 1));
        let (_dir, into) = scratch();
        let fits = BundleLimits { archive_bytes: bytes.len() as u64, ..BundleLimits::LOCAL };
        let extracted = extract_bundle_from(&bytes[..], &into, &fits).ok().unwrap();
        assert_eq!(extracted.archive_bytes, bytes.len() as u64);
        // What it extracted to is what it occupies: a block for the
        // manifest's few bytes, and its entry.
        assert_eq!(extracted.bytes, BLOCK_BYTES + ENTRY_BYTES);
    }

    // What a bundle extracts to is counted as what it occupies, which is
    // what a server that keeps bundles in memory pays: small files cost a
    // block each, and every file and directory its entry. The limit is held
    // from the headers, before the entry that passes it is written. And the
    // sender's own failure is told from an archive that is not one.
    #[test]
    fn a_bundle_is_held_to_what_it_occupies() {
        let files: Vec<(String, &[u8])> =
            (0..10).map(|i| (format!("assets/{i}"), &b"x"[..])).collect();
        let mut entries: Vec<(&str, &[u8])> = vec![("icp.yaml", b"canisters: []\n")];
        entries.extend(files.iter().map(|(path, data)| (path.as_str(), *data)));
        let bytes = archive(&entries);
        // Eleven files of a block each, and their entries with the one
        // directory their paths imply: far more than their 24 bytes.
        let occupied = 11 * (BLOCK_BYTES + ENTRY_BYTES) + ENTRY_BYTES;
        let (_dir, into) = scratch();
        let fits = BundleLimits { extracted_bytes: occupied, ..BundleLimits::LOCAL };
        assert_eq!(extract_bundle_from(&bytes[..], &into, &fits).ok().unwrap().bytes, occupied);
        let (_dir, into) = scratch();
        let over = BundleLimits { extracted_bytes: occupied - 1, ..BundleLimits::LOCAL };
        let err = extract_bundle_from(&bytes[..], &into, &over).err().unwrap();
        assert_eq!(err, ExtractError::ExtractsTooLarge(occupied - 1));
        assert!(!into.join("assets/9").exists(), "the entry that passes it is not written");

        struct Cut<'a>(&'a [u8]);
        impl Read for Cut<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                match self.0.is_empty() {
                    true => Err(std::io::Error::other("connection reset")),
                    false => self.0.read(buf),
                }
            }
        }
        let (_dir, into) = scratch();
        let half = Cut(&bytes[..bytes.len() / 2]);
        let err = extract_bundle_from(half, &into, &BundleLimits::LOCAL).err().unwrap();
        assert_eq!(err, ExtractError::Source("connection reset".into()));
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
        let err = chain(
            &host_for(fs.clone(), &BundleLimits::LOCAL, PluginLimits::default())
                .project
                .load()
                .await
                .expect_err("a link out"),
        );
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
        let err = chain(
            &host_for(fs.clone(), &BundleLimits::LOCAL, PluginLimits::default())
                .project
                .load()
                .await
                .expect_err("a link within"),
        );
        assert!(err.contains("not a regular file in the project"), "{err}");
        assert!(err.contains("in.wasm"), "{err}");
        assert!(fs.read(Utf8Path::new("in.wasm")).await.is_err());
        assert_eq!(fs.read(Utf8Path::new("backend.wasm")).await.unwrap(), b"\0asm");

        // Dangling: a link is a link, wherever it leads or fails to.
        let (_dir, into) = scratch();
        let bytes = archive(&[("icp.yaml", manifest("gone.wasm").as_bytes())]);
        let fs = extract_bundle(&bytes, &into).unwrap();
        symlink(into.join("nowhere.wasm"), into.join("gone.wasm")).unwrap();
        let err = chain(
            &host_for(fs, &BundleLimits::LOCAL, PluginLimits::default())
                .project
                .load()
                .await
                .expect_err("a dangling link"),
        );
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
        let err = chain(
            &host_for(fs, &BundleLimits::LOCAL, PluginLimits::default())
                .project
                .load()
                .await
                .expect_err("a directory"),
        );
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
        let project = host_for(fs.clone(), &BundleLimits::LOCAL, PluginLimits::default())
            .project
            .load()
            .await
            .unwrap();
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
            let err = host_for(fs, &BundleLimits::LOCAL, PluginLimits::default()).project.load().await.expect_err(refused);
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

    // The spelling check cannot know every name a disk takes for `.icp`
    // (Windows drops a trailing dot or space, and reads a stream suffix as
    // the directory), so the disk is asked once the archive is out: state
    // that is there is refused, however it came to be.
    #[test]
    fn state_on_disk_is_refused_whatever_the_archive_called_it() {
        let (_dir, into) = scratch();
        refuse_state(&into).unwrap();
        std::fs::create_dir_all(into.join(".icp/data/mappings")).unwrap();
        let err = refuse_state(&into).unwrap_err();
        assert!(matches!(err, ExtractError::NotABundle(_)), "{err}");
        assert!(err.to_string().contains("`.icp/`"), "{err}");
    }

    // The alias itself, where the disk has it.
    #[cfg(windows)]
    #[test]
    fn a_windows_alias_of_the_state_directory_is_refused() {
        let (_dir, into) = scratch();
        let bytes = archive(&[
            ("icp.yaml", b"canisters: []"),
            (".icp./data/mappings/ic.ids.json", b"{\"backend\": \"aaaaa-aa\"}"),
        ]);
        let err = extract_bundle(&bytes, &into).unwrap_err();
        assert!(err.contains("`.icp/`"), "{err}");
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

    // The modes an archive names are not kept: a directory entry marked
    // read-only, written after its files, would otherwise leave a tree the
    // server's own user cannot remove, and the bundle would outlive its
    // deploy. What is extracted is the owner's alone, to read and to remove.
    #[cfg(unix)]
    #[test]
    fn what_is_extracted_can_be_removed_whatever_modes_the_archive_names() {
        use std::os::unix::fs::PermissionsExt;
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        let mut header = tar::Header::new_gnu();
        header.set_size(1);
        header.set_mode(0o444);
        header.set_cksum();
        archive.append_data(&mut header, "locked/x", &b"x"[..]).unwrap();
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_mode(0o555);
        header.set_cksum();
        archive.append_data(&mut header, "locked/", &b""[..]).unwrap();
        let bytes = archive.into_inner().unwrap().finish().unwrap();
        let (_dir, into) = scratch();
        // Not a bundle (no manifest), which is beside the point: the entries
        // were written before that is known.
        extract_bundle(&bytes, &into).unwrap_err();
        let mode = |path: &str| std::fs::metadata(into.join(path)).unwrap().permissions().mode();
        assert_eq!(mode("locked") & 0o777, 0o700);
        assert_eq!(mode("locked/x") & 0o777, 0o600);
        std::fs::remove_dir_all(into.join("locked")).unwrap();

        // An old-style header calls a directory a regular file whose name
        // ends in `/`: it is one on disk, and gets a directory's mode.
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        let mut header = tar::Header::new_gnu();
        header.set_size(1);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append_data(&mut header, "old/x", &b"x"[..]).unwrap();
        let mut header = tar::Header::new_old();
        header.set_path("old/").unwrap();
        header.set_size(0);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append(&header, &b""[..]).unwrap();
        let bytes = archive.into_inner().unwrap().finish().unwrap();
        let (_dir, into) = scratch();
        extract_bundle(&bytes, &into).unwrap_err();
        let mode = |path: &str| std::fs::metadata(into.join(path)).unwrap().permissions().mode();
        assert_eq!(mode("old") & 0o777, 0o700);
        std::fs::remove_dir_all(into.join("old")).unwrap();
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
        let host = host_within(fs, manifest.len() as u64 + 1500, PluginLimits::default());
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
        let host = host_within(fs, manifest.len() as u64 + 2000, PluginLimits::default());
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
        let env = host_for(fs.clone(), &BundleLimits::LOCAL, PluginLimits::default())
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
            (0, u64::MAX),
            &AllowedPlugins::Any,
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

    // The deploy keeps a copy of each canister's module beside the bundle,
    // one per canister however many name the same file: so what a bundle
    // will come to in its deploy's directory is the bundle and those copies,
    // and that is what is held to the limit, before any copy is made. A
    // small archive of one module and many canisters is the case it is for.
    #[tokio::test]
    async fn the_copies_a_deploy_makes_of_its_modules_count_against_the_limit() {
        let wasm = wat::parse_str("(module)").unwrap();
        let sha = hex::encode(Sha256::digest(&wasm));
        let canisters: String = (0..5)
            .map(|i| {
                format!(
                    "  - name: c{i}\n    build:\n      steps:\n        - type: pre-built\n          \
                     path: m.wasm\n          sha256: {sha}\n"
                )
            })
            .collect();
        let manifest = format!("canisters:\n{canisters}");
        let bytes = archive(&[("icp.yaml", manifest.as_bytes()), ("m.wasm", &wasm)]);
        let (_dir, fs, env) = environment(&bytes).await;
        // The bundle: a manifest and a module, a block and an entry each.
        let bundle = 2 * occupies(1);
        let check = |limit: u64| {
            check_bundle(
                &fs,
                &env.network,
                env.canisters.values().map(|(dir, canister)| (dir.as_path(), canister)),
                bundle,
                &BundleLimits { extracted_bytes: limit, ..BundleLimits::LOCAL },
                &AllowedPlugins::Any,
            )
        };
        // Five canisters, five copies of the one module.
        let in_all = bundle + 5 * occupies(wasm.len() as u64);
        check(in_all).unwrap();
        let err = check(in_all - 1).unwrap_err();
        assert!(err.contains("the copy of each canister's module"), "{err}");
        assert!(err.contains("canister 'c4'"), "{err}");
    }

    /// A bundle of one canister synced by the plugin `plugin`, at a path
    /// and under a canister name of the bundle's choosing.
    fn bundle_with_plugin(plugin: &[u8]) -> Vec<u8> {
        let wasm = wat::parse_str("(module)").unwrap();
        let sha = hex::encode(Sha256::digest(&wasm));
        let canister = format!(
            "name: frontend\nbuild:\n  steps:\n    - type: pre-built\n      path: frontend.wasm\n      \
             sha256: {sha}\nsync:\n  steps:\n    - type: plugin\n      path: sync.wasm\n"
        );
        archive(&[
            ("icp.yaml", b"canisters:\n  - canisters/frontend\n"),
            ("canisters/frontend/canister.yaml", canister.as_bytes()),
            ("canisters/frontend/frontend.wasm", &wasm),
            ("canisters/frontend/sync.wasm", plugin),
        ])
    }

    // The list a server that deploys for others starts from, and what an
    // operator adds to it: by the hash of a plugin's module, however it is
    // spelled, and nothing that is not one.
    #[test]
    fn the_plugins_a_server_runs_are_named_by_hash() {
        let known = AllowedPlugins::known();
        for (sha, _) in KNOWN_PLUGINS {
            assert_eq!(sha.len(), 64);
            assert!(known.allows(sha) && known.allows(&sha.to_ascii_uppercase()));
        }
        let other = "0".repeat(64);
        assert!(!known.allows(&other));
        let extended =
            AllowedPlugins::known_and([format!("  {}  ", other.to_uppercase())]).unwrap();
        assert!(extended.allows(&other) && extended.allows(KNOWN_PLUGINS[0].0));
        for not_a_hash in ["", "abc", &"g".repeat(64), &"0".repeat(63)] {
            let err = AllowedPlugins::known_and([not_a_hash]).unwrap_err();
            assert!(err.contains("not the sha256 of a plugin"), "{err}");
        }
        // On the user's own machine, whatever the bundle brings.
        assert!(AllowedPlugins::Any.allows(&other));
        assert_eq!(AllowedPlugins::default(), AllowedPlugins::Any);
    }

    // A bundle's sync plugin runs inside the server, so a server that
    // deploys for others runs only the ones it knows: a deploy is refused,
    // before anything is created, when a canister it is deploying is synced
    // by any other — whatever the bundle calls it, and whatever checksum the
    // manifest records for it. The refusal says which plugin, by its hash,
    // and what the server would run.
    #[tokio::test]
    async fn a_deploy_runs_only_the_plugins_its_server_knows() {
        let plugin = b"\0asm a plugin nobody vouched for";
        let sha = hex::encode(Sha256::digest(plugin));
        let (_dir, fs, env) = environment(&bundle_with_plugin(plugin)).await;
        let check = |plugins: &AllowedPlugins| {
            check_bundle(
                &fs,
                &env.network,
                env.canisters.values().map(|(dir, canister)| (dir.as_path(), canister)),
                0,
                &BundleLimits::LOCAL,
                plugins,
            )
        };
        check(&AllowedPlugins::Any).unwrap();
        let err = check(&AllowedPlugins::known()).unwrap_err();
        assert!(err.contains("canister 'frontend'"), "{err}");
        assert!(err.contains(&format!("'sync.wasm' (sha256 {sha})")), "{err}");
        assert!(err.contains("is not one this server runs"), "{err}");
        for (known, what) in KNOWN_PLUGINS {
            assert!(err.contains(known) && err.contains(what), "{err}");
        }
        // Allowed by its hash, it deploys.
        check(&AllowedPlugins::known_and([&sha]).unwrap()).unwrap();
        // A server that knows none runs none, and says so.
        let none = AllowedPlugins::Only(Arc::default());
        assert!(check(&none).unwrap_err().contains("it runs no sync plugin"));
    }

    // The same list, held on the upload: the whole project is looked at,
    // since the environment a deploy will name is not known yet, and a
    // bundle with a plugin the server does not run is refused whole. One
    // with no plugin passes; one whose project does not load is refused for
    // that; and a server that runs anything does not look at all.
    #[tokio::test]
    async fn an_upload_is_held_to_the_plugins_its_server_knows() {
        let plugin = b"\0asm a plugin nobody vouched for";
        let sha = hex::encode(Sha256::digest(plugin));
        let (_dir, into) = scratch();
        let fs = extract_bundle(&bundle_with_plugin(plugin), &into).unwrap();
        let limits = BundleLimits::LOCAL;

        let refused = vet_plugins(&fs, &limits, &AllowedPlugins::known()).await.unwrap_err();
        let VetError::PluginNotAllowed(why) = &refused else { panic!("{refused:?}") };
        assert!(why.contains("canister 'frontend'") && why.contains(&sha), "{why}");
        vet_plugins(&fs, &limits, &AllowedPlugins::known_and([&sha]).unwrap()).await.unwrap();
        vet_plugins(&fs, &limits, &AllowedPlugins::Any).await.unwrap();

        // No plugin, nothing to refuse.
        let (_dir, into) = scratch();
        let plain = extract_bundle(&archive(&[("icp.yaml", b"canisters: []\n")]), &into).unwrap();
        vet_plugins(&plain, &limits, &AllowedPlugins::known()).await.unwrap();

        // A project that does not load is not a bundle, and is said to be
        // here rather than at the deploy; unless nothing is looked at.
        let (_dir, into) = scratch();
        let broken = extract_bundle(&archive(&[("icp.yaml", b"canisters: 7\n")]), &into).unwrap();
        let refused = vet_plugins(&broken, &limits, &AllowedPlugins::known()).await.unwrap_err();
        assert!(matches!(refused, VetError::NotABundle(_)), "{refused:?}");
        vet_plugins(&broken, &limits, &AllowedPlugins::Any).await.unwrap();
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
            let err = chain(
                &host_for(fs, &BundleLimits::LOCAL, PluginLimits::default())
                    .project
                    .load()
                    .await
                    .expect_err(declared),
            );
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
