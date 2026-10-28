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
//! Everything the project library reads or writes — the manifest, the wasms,
//! the `.icp` id and artifact stores — lives under the extracted directory,
//! which is removed when the deploy ends.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use camino::{Utf8Path, Utf8PathBuf};
use icp_events::StepReporter;
use icp_project::{
    canister::{
        build::Builder,
        recipe::{Fetched, Resolve, ResolveError},
        sync::Syncer,
        wasm::{Fetch, FetchError},
    },
    files::{FileSystem, HostFileSystem},
    host::{Host, Ignore},
    manifest::{prebuilt::SourceField, ProjectRootLocate, ProjectRootLocateImpl, PROJECT_MANIFEST},
    network::{
        Access, AccessError, CollectFriendlyDomains, Configuration, NetworkAccess, NetworkUrls,
        RootKeySource, RootKeySpec,
    },
    prelude::IC_ROOT_KEY,
    random::HostRandom,
    store_artifact::ArtifactStore,
    store_id::AccessImpl,
    Lazy, Network, Project, ProjectLoadImpl,
};
use sha2::{Digest, Sha256};

/// Decoded bundles above this are refused before anything is written: a
/// bundle rides in a tool call (or a file the call names), and a runaway
/// input must not fill the disk or the heap.
pub const MAX_BUNDLE_BYTES: usize = 256 * 1024 * 1024;

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

/// Wasm resolution for a bundle: the archive carries every module it names,
/// so a source is a local path (verified against its recorded checksum) and a
/// remote one is a bundle this tool does not understand.
pub struct BundledWasm;

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

/// The host for the bundle extracted at `dir`: its manifest is the project,
/// its `.icp` directory the id and artifact stores.
pub fn host_for(dir: &Utf8Path) -> Host {
    // The directory IS the project root: no climbing to a workspace above it.
    let locate: Arc<dyn ProjectRootLocate> =
        Arc::new(ProjectRootLocateImpl::new(dir.to_path_buf(), Some(dir.to_path_buf())));
    let files: Arc<dyn FileSystem> = Arc::new(HostFileSystem);
    let wasm: Arc<dyn Fetch> = Arc::new(BundledWasm);
    let project = Lazy::<_, Project>::new(ProjectLoadImpl {
        project_root_locate: locate.clone(),
        recipe: Arc::new(NoRecipes),
        files: files.clone(),
    });
    Host {
        project: Arc::new(project),
        files: files.clone(),
        ids: Arc::new(AccessImpl::new(locate.clone())),
        artifacts: Arc::new(ArtifactStore::new(locate)),
        builder: Arc::new(Builder::new(wasm.clone(), files)),
        // Script sync steps are refused at bundle time, so the subprocess half
        // of the host syncer is never reached; plugin steps run in wasmtime.
        syncer: Arc::new(Syncer::host(wasm.clone(), Arc::new(icp_sync_plugin::Wasmtime))),
        wasm,
        network: Arc::new(ConnectedNetworks),
        random: Arc::new(HostRandom),
        observer: Arc::new(Ignore),
    }
}

/// Extract a bundle archive into `into`, which must exist and be empty.
///
/// `tar` refuses entries that would land outside `into`, so a crafted archive
/// cannot write elsewhere; what it extracts is then required to look like a
/// bundle, i.e. to carry a project manifest at its root.
pub fn extract_bundle(bytes: &[u8], into: &Utf8Path) -> Result<(), String> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(format!(
            "the bundle is {} bytes, above the {} byte limit",
            bytes.len(),
            MAX_BUNDLE_BYTES
        ));
    }
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    archive
        .unpack(into.as_std_path())
        .map_err(|e| format!("the bundle is not a readable .tar.gz archive: {e}"))?;
    if !into.join(PROJECT_MANIFEST).is_file() {
        return Err(format!(
            "the archive carries no `{PROJECT_MANIFEST}` at its root, so it is not an icp \
             project bundle (`icp project bundle` writes one)"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use icp_project::network::Managed;

    fn managed(name: &str) -> Network {
        Network {
            name: name.into(),
            configuration: Configuration::Managed { managed: Managed::default() },
        }
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
        let dir = tempfile::tempdir().unwrap();
        let into = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        let data = b"hello";
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append_data(&mut header, "README", &data[..]).unwrap();
        let bytes = archive.into_inner().unwrap().finish().unwrap();
        let err = extract_bundle(&bytes, &into).unwrap_err();
        assert!(err.contains(PROJECT_MANIFEST), "{err}");
    }

    #[test]
    fn garbage_is_not_an_archive() {
        let dir = tempfile::tempdir().unwrap();
        let into = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        let err = extract_bundle(b"not a tarball", &into).unwrap_err();
        assert!(err.contains("not a readable"), "{err}");
    }

    #[test]
    fn oversized_bundles_are_refused_before_extraction() {
        let dir = tempfile::tempdir().unwrap();
        let into = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        let big = vec![0u8; MAX_BUNDLE_BYTES + 1];
        let err = extract_bundle(&big, &into).unwrap_err();
        assert!(err.contains("limit"), "{err}");
    }
}
