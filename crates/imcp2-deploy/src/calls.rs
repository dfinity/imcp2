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
    hash_tree::{Label, LookupResult},
    Agent, AgentError,
};
use icp_project::calls::{Authority, Call, CallError, CanisterCalls, RouteTo};

/// [`CanisterCalls`] over an `ic-agent`.
pub struct AgentCalls {
    agent: Agent,
    /// Read once at construction: it cannot change for the life of the agent.
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
    /// what the certificate proves.
    ///
    /// The section path is requested together with `controllers`, because a
    /// metadata path proven absent is equally what a canister that was never
    /// created looks like — `controllers` is written at creation, so its
    /// presence is what separates the two. A canister with no module installed
    /// has no sections at all, which the certificate reports as an absent path
    /// under a canister that exists, and so as `Ok(None)`.
    async fn certified_metadata_section(
        &self,
        canister: Principal,
        path: &str,
    ) -> Result<Option<Vec<u8>>, CallError> {
        let metadata_path: Vec<Label<Vec<u8>>> = vec![
            "canister".into(),
            Label::from_bytes(canister.as_slice()),
            "metadata".into(),
            path.into(),
        ];
        let controllers_path: Vec<Label<Vec<u8>>> =
            vec!["canister".into(), Label::from_bytes(canister.as_slice()), "controllers".into()];
        let method = "read_state(metadata)";
        let cert = self
            .agent
            .read_state_raw(vec![metadata_path.clone(), controllers_path.clone()], canister)
            .await
            .map_err(|err| Self::wrap(canister, method, err))?;

        let unproven = |about: String| {
            Err(CallError::Rejected {
                canister,
                method: method.to_owned(),
                code: None,
                message: format!("the certificate proves nothing about {about}"),
            })
        };
        match cert.tree.lookup_path(&metadata_path) {
            LookupResult::Found(bytes) => Ok(Some(bytes.to_vec())),
            LookupResult::Absent => match cert.tree.lookup_path(&controllers_path) {
                LookupResult::Found(_) => Ok(None),
                LookupResult::Absent => Err(CallError::Rejected {
                    canister,
                    method: method.to_owned(),
                    code: None,
                    message: format!("canister {canister} does not exist"),
                }),
                _ => unproven(format!("canister {canister}")),
            },
            // Not proof of absence, just a certificate that says nothing about
            // the path — reporting the section missing off this would be a
            // guess, and a private section is exactly what it looks like.
            _ => unproven(format!("section `{path}` of canister {canister}")),
        }
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

    async fn metadata_section(
        &self,
        canister: Principal,
        path: &str,
        // With no proxy there is one authority, and both values mean it.
        _authority: Authority,
    ) -> Result<Option<Vec<u8>>, CallError> {
        self.certified_metadata_section(canister, path).await
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
