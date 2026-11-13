//! The project library's one seam to the network, over this connection's
//! `ic-agent`: [`CanisterCalls`] signed as the user's management identity.
//!
//! Modelled on the icp CLI's own implementation (`icp_app::calls::AgentCalls`),
//! minus proxy-canister routing: this server never names a proxy, so every call
//! is made directly by the identity the agent carries. The certified reads are
//! what the deploy operation decides on — whether a canister exists, what is
//! installed on it, which subnet it sits on — so they are answered from
//! certificates rather than from anything a canister says about itself.

use async_trait::async_trait;
use candid::Principal;
use ic_agent::{
    agent::{CallResponse, EffectiveId, SubnetType},
    hash_tree::{HashTree, Label, LookupResult},
    Agent, AgentError,
};
use icp_project::calls::{Authority, Call, CallError, CanisterCalls, RouteTo};
use imcp2_core::guard_candid_text;

/// The metadata section the upgrade compatibility check reads from the
/// deployed canister and parses as Candid.
const CANDID_SERVICE: &str = "candid:service";

/// [`CanisterCalls`] over an `ic-agent`.
pub struct AgentCalls {
    agent: Agent,
    /// The agent's principal, read once here. [`CanisterCalls::caller`] is
    /// infallible while [`Agent::get_principal`] is not (an identity may
    /// decline to name its sender), so the one place the failure can be
    /// reported is construction; the agent's identity cannot change after it.
    caller: Principal,
}

impl AgentCalls {
    pub fn new(agent: Agent) -> Result<Self, String> {
        let caller = agent.get_principal()?;
        Ok(Self { agent, caller })
    }

    /// Turn an agent error into the shape the trait speaks in: a rejection is
    /// a verdict and keeps its code, a call that ran out of time or never got
    /// down the wire went unanswered, and anything else — a reply that would
    /// not parse, a certificate that would not verify — failed for good.
    fn wrap(canister: Principal, method: &str, err: AgentError) -> CallError {
        match &err {
            AgentError::CertifiedReject { reject, .. }
            | AgentError::UncertifiedReject { reject, .. } => CallError::Rejected {
                canister,
                method: method.to_owned(),
                code: reject.error_code.clone(),
                message: reject.reject_message.clone(),
            },
            AgentError::TimeoutWaitingForResponse() | AgentError::TransportError(_) => {
                CallError::unanswered(canister, method, err)
            }
            _ => CallError::failed(canister, method, err),
        }
    }

    /// Whether `canister` exists, which its controllers answer — see
    /// [`CanisterCalls::controllers`]. A check that could not be made reads as
    /// "does not exist": every caller asks this while deciding whether to
    /// report a read failure of its own, and an existence check that failed
    /// too is no reason to suppress it.
    async fn exists(&self, canister: Principal) -> bool {
        self.controllers(canister).await.is_ok_and(|controllers| controllers.is_some())
    }

    /// Ask the target's subnet to certify a metadata section, reporting only
    /// what the certificate proves — see [`certified_section`] for what that
    /// is.
    async fn certified_metadata_section(
        &self,
        canister: Principal,
        path: &str,
    ) -> Result<Option<Vec<u8>>, CallError> {
        let (metadata_path, controllers_path) = section_paths(canister, path);
        let cert = self
            .agent
            .read_state_raw(vec![metadata_path, controllers_path], canister)
            .await
            .map_err(|err| Self::wrap(canister, READ_STATE_METADATA, err))?;
        certified_section(canister, path, &cert.tree)
    }

    /// A subnet-scoped update: routed to a subnet rather than to any canister
    /// on it, which the agent only exposes through a signed submission.
    async fn to_subnet(&self, subnet: Principal, call: &Call) -> Result<Vec<u8>, CallError> {
        let effective = EffectiveId::Subnet(subnet);
        let fail = |e: AgentError| Self::wrap(call.canister, &call.method, e);

        let signed = self
            .agent
            .update(&call.canister, &call.method)
            .with_arg(call.arg.clone())
            .sign()
            .map_err(fail)?;
        let response =
            self.agent.update_signed(effective, signed.signed_update).await.map_err(fail)?;
        match response {
            CallResponse::Response(bytes) => Ok(bytes),
            CallResponse::Poll(request_id) => {
                let status = self.agent.sign_request_status(effective, request_id).map_err(fail)?;
                Ok(self
                    .agent
                    .wait_signed(&request_id, effective, status.signed_request_status)
                    .await
                    .map_err(fail)?
                    .0)
            }
        }
    }
}

/// The method name a certified metadata read reports itself under.
const READ_STATE_METADATA: &str = "read_state(metadata)";

/// A path into the state tree, label by label.
type StatePath = Vec<Label<Vec<u8>>>;

/// The two state-tree paths a metadata read asks for: the section, and the
/// canister's controllers (see [`certified_section`] for why both).
fn section_paths(canister: Principal, path: &str) -> (StatePath, StatePath) {
    let canister_path = || vec![Label::from("canister"), Label::from_bytes(canister.as_slice())];
    let mut metadata = canister_path();
    metadata.extend(["metadata".into(), path.into()]);
    let mut controllers = canister_path();
    controllers.push("controllers".into());
    (metadata, controllers)
}

/// What a certificate proves about section `path` of `canister`, and nothing
/// more: `Some` for a section it holds, `None` for a canister it proves has
/// no such section, and an error for a canister it proves absent or a path
/// it says nothing about.
///
/// The section is read together with `controllers`, because a metadata path
/// proven absent is equally what a canister that was never created looks
/// like — `controllers` is written at creation, so its presence is what
/// separates the two. A canister with no module installed has no sections
/// at all, which the certificate reports as an absent path under a canister
/// that exists, and so as `Ok(None)`.
fn certified_section(
    canister: Principal,
    path: &str,
    tree: &HashTree<Vec<u8>>,
) -> Result<Option<Vec<u8>>, CallError> {
    let (metadata_path, controllers_path) = section_paths(canister, path);
    let rejected = |message: String| CallError::Rejected {
        canister,
        method: READ_STATE_METADATA.to_owned(),
        code: None,
        message,
    };
    let unproven =
        |about: String| Err(rejected(format!("the certificate proves nothing about {about}")));
    match tree.lookup_path(&metadata_path) {
        LookupResult::Found(bytes) => Ok(Some(bytes.to_vec())),
        LookupResult::Absent => match tree.lookup_path(&controllers_path) {
            LookupResult::Found(_) => Ok(None),
            LookupResult::Absent => Err(rejected(format!("canister {canister} does not exist"))),
            _ => unproven(format!("canister {canister}")),
        },
        // Not proof of absence, just a certificate that says nothing about
        // the path — reporting the section missing off this would be a
        // guess, and a private section is exactly what it looks like.
        _ => unproven(format!("section `{path}` of canister {canister}")),
    }
}

#[async_trait]
impl CanisterCalls for AgentCalls {
    fn caller(&self) -> Principal {
        self.caller
    }

    async fn update(&self, call: Call) -> Result<Vec<u8>, CallError> {
        if let RouteTo::Subnet(subnet) = call.route {
            return self.to_subnet(subnet, &call).await;
        }
        let mut builder =
            self.agent.update(&call.canister, &call.method).with_arg(call.arg.clone());
        if let RouteTo::Canister(effective) = call.route {
            builder = builder.with_effective_canister_id(effective);
        }
        builder.await.map_err(|e| Self::wrap(call.canister, &call.method, e))
    }

    async fn query(&self, call: Call) -> Result<Vec<u8>, CallError> {
        let mut builder = self.agent.query(&call.canister, &call.method).with_arg(call.arg.clone());
        if let RouteTo::Canister(effective) = call.route {
            builder = builder.with_effective_canister_id(effective);
        }
        builder.call().await.map_err(|e| Self::wrap(call.canister, &call.method, e))
    }

    /// A `candid:service` section is parsed by the library's compatibility
    /// check, on the worker thread and without a depth guard, and the
    /// canister it comes from is whichever the caller's mapping named: so
    /// the interface is held to the same bound as the bundle's own before
    /// it is handed back ([`guard_candid_text`]). The check treats a
    /// failed read as "cannot tell" and skips, which is the right outcome
    /// for an interface too deep to compare.
    async fn metadata_section(
        &self,
        canister: Principal,
        path: &str,
        // With no proxy there is one authority, and both values mean it.
        _authority: Authority,
    ) -> Result<Option<Vec<u8>>, CallError> {
        let section = self.certified_metadata_section(canister, path).await?;
        if path == CANDID_SERVICE {
            if let Some(bytes) = &section {
                let text = String::from_utf8_lossy(bytes);
                guard_candid_text(&format!("the `{path}` section of {canister}"), &text).map_err(
                    |why| CallError::Rejected {
                        canister,
                        method: "read_state(metadata)".to_owned(),
                        code: None,
                        message: why,
                    },
                )?;
            }
        }
        Ok(section)
    }

    async fn controllers(&self, canister: Principal) -> Result<Option<Vec<Principal>>, CallError> {
        match self.agent.read_state_canister_controllers(canister).await {
            Ok(controllers) => Ok(Some(controllers)),
            Err(AgentError::LookupPathAbsent(_)) => Ok(None),
            Err(err) => Err(Self::wrap(canister, "read_state(controllers)", err)),
        }
    }

    async fn module_hash(&self, canister: Principal) -> Result<Option<Vec<u8>>, CallError> {
        let err = match self.agent.read_state_canister_module_hash(canister).await {
            Ok(hash) => return Ok(Some(hash)),
            Err(err) => err,
        };
        // No module-hash path means nothing is installed — or that there is no
        // canister to install into, which is not an answer this can give.
        if matches!(err, AgentError::LookupPathAbsent(_)) && self.exists(canister).await {
            return Ok(None);
        }
        Err(Self::wrap(canister, "read_state(module_hash)", err))
    }

    async fn subnet_of(&self, canister: Principal) -> Result<Principal, CallError> {
        Ok(self
            .agent
            .get_subnet_by_canister(&canister)
            .await
            .map_err(|e| Self::wrap(canister, "subnet_of", e))?
            .id())
    }

    async fn subnet_uses_engine_operator(&self, subnet: Principal) -> Result<bool, CallError> {
        let info = self
            .agent
            .get_subnet_by_id(&subnet)
            .await
            .map_err(|e| Self::wrap(subnet, "subnet_type", e))?;
        Ok(matches!(info.subnet_type(), Some(SubnetType::CloudEngine)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_agent::hash_tree::{fork, label, leaf, pruned};

    const PATH: &str = "candid:service";

    fn canister() -> Principal {
        Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap()
    }

    /// A state tree holding `node` under this canister's entry.
    fn under_canister(node: HashTree<Vec<u8>>) -> HashTree<Vec<u8>> {
        label("canister", label(Label::from_bytes(canister().as_slice()), node))
    }

    /// The `controllers` entry creation writes; its bytes are not read here.
    fn controllers() -> HashTree<Vec<u8>> {
        label("controllers", leaf(b"\x81\x41\x01".to_vec()))
    }

    fn rejection(result: Result<Option<Vec<u8>>, CallError>) -> String {
        match result {
            Err(CallError::Rejected { message, .. }) => message,
            other => panic!("expected a rejection, got {other:?}"),
        }
    }

    // A section the certificate holds is what the check parses.
    #[test]
    fn a_section_the_certificate_holds_is_returned() {
        let tree = under_canister(fork(
            controllers(),
            label("metadata", label(PATH, leaf(b"service : {}".to_vec()))),
        ));
        assert_eq!(
            certified_section(canister(), PATH, &tree).unwrap(),
            Some(b"service : {}".to_vec())
        );
    }

    // A canister that exists — its controllers are proven — with no such
    // section: none installed yet, or a module without one. Either reads as
    // "no section", not as "no canister".
    #[test]
    fn a_canister_proven_to_exist_without_the_section_has_none() {
        let no_module = under_canister(controllers());
        assert_eq!(certified_section(canister(), PATH, &no_module).unwrap(), None);
        let other_section = under_canister(fork(
            controllers(),
            label("metadata", label("other", leaf(b"x".to_vec()))),
        ));
        assert_eq!(certified_section(canister(), PATH, &other_section).unwrap(), None);
    }

    // The tree proves another canister's entry and no entry for this one:
    // the section is absent because the canister is.
    #[test]
    fn a_canister_the_certificate_proves_absent_does_not_exist() {
        let other = Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap();
        let tree = label("canister", label(Label::from_bytes(other.as_slice()), controllers()));
        let message = rejection(certified_section(canister(), PATH, &tree));
        assert_eq!(message, format!("canister {} does not exist", canister()));
    }

    // A pruned subtree where the section would be proves neither presence
    // nor absence — a private section looks exactly like this — so no
    // answer is given off it.
    #[test]
    fn a_pruned_section_proves_nothing() {
        let tree = under_canister(fork(controllers(), pruned([0u8; 32])));
        let message = rejection(certified_section(canister(), PATH, &tree));
        assert_eq!(
            message,
            format!(
                "the certificate proves nothing about section `{PATH}` of canister {}",
                canister()
            )
        );
    }

    // The section is proven absent but the controllers are pruned: whether
    // the canister exists is what the certificate does not say, so neither
    // "no section" nor "no canister" is reported.
    #[test]
    fn a_pruned_controllers_entry_proves_nothing_about_the_canister() {
        let tree = under_canister(fork(
            pruned([0u8; 32]),
            label("metadata", label("other", leaf(b"x".to_vec()))),
        ));
        let message = rejection(certified_section(canister(), PATH, &tree));
        assert_eq!(
            message,
            format!("the certificate proves nothing about canister {}", canister())
        );
    }
}
