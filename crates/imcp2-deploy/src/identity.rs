//! An identity that stays signed in for as long as a deploy runs.
//!
//! The per-app delegations `imcp2_core::identities` mints are capped at five
//! minutes by Internet Identity, and the store re-derives one on request
//! when the cached one is near expiry. An `ic-agent` holds one `Identity`
//! for its lifetime, though, and `Identity::sign` is synchronous, so a deploy
//! that built its agent over a fixed `DelegatedIdentity` would start failing
//! signatures partway through an asset sync. [`RefreshingIdentity`] signs
//! with whatever delegation is current, and a task alongside it asks the
//! store for a fresh one on a short cadence until the identity is dropped.
//!
//! Two things a refresh must not do: change the principal — the account the
//! first derivation resolved to is the one asked for from then on, and a
//! delegation for any other principal is refused — and outlive the session.
//! When the store reports the grant over (expired, revoked at id.ai, or
//! replaced by a newer sign-in), the identity stops signing at once rather
//! than riding out the delegation it still holds.

use std::{
    sync::{Arc, RwLock, Weak},
    time::Duration,
};

use candid::Principal;
use ic_agent::{
    agent::EnvelopeContent,
    identity::{Delegation, SenderInfo, SignedDelegation},
    Identity, Signature,
};
use imcp2_core::identities::{Identities, RECONNECT_MSG};

/// How often the refresher asks the store for the session's delegation. The
/// store answers from its cache while that is fresh (no network), and
/// re-derives inside its 30-second expiry margin, so this cadence decides how
/// much of that margin is left when the new delegation lands.
const REFRESH_EVERY: Duration = Duration::from_secs(10);

/// An `Identity` whose signing delegation is swapped for a fresh one while a
/// deploy runs. Its `sender` is fixed at construction: a refresh is accepted
/// only from an identity for the same principal, so nothing signed by the
/// agent can change hands midway. Once [`revoked`](Self::revoke), it signs
/// nothing more.
pub struct RefreshingIdentity {
    sender: Principal,
    current: RwLock<Arc<dyn Identity>>,
}

impl RefreshingIdentity {
    /// Derive the session's default identity at `origin` now, and keep it
    /// fresh until the returned handle is dropped. The account that
    /// derivation resolves to is the one refreshed from then on: the default
    /// is the user's to change, and a deploy must finish as the principal it
    /// started as.
    pub async fn start(
        identities: Identities,
        session_id: String,
        origin: &'static str,
    ) -> Result<Arc<Self>, String> {
        let (initial, account) =
            identities.delegated_identity_resolved(&session_id, origin, None).await?;
        let this = Arc::new(Self::over(Arc::new(initial))?);
        let weak = Arc::downgrade(&this);
        tokio::spawn(refresh_loop(weak, identities, session_id, origin, account));
        Ok(this)
    }

    /// Wrap `initial`; refreshes come through [`Self::refresh_with`].
    pub fn over(initial: Arc<dyn Identity>) -> Result<Self, String> {
        let sender = initial.sender()?;
        Ok(Self { sender, current: RwLock::new(initial) })
    }

    /// Replace the signing identity. Refused when `fresh` is for another
    /// principal: a deploy must finish as the principal it started as.
    pub fn refresh_with(&self, fresh: Arc<dyn Identity>) -> Result<(), String> {
        let sender = fresh.sender()?;
        if sender != self.sender {
            return Err(format!(
                "refreshed identity is {sender}, not {} the deploy started as",
                self.sender
            ));
        }
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = fresh;
        Ok(())
    }

    /// Stop signing: every signature from now on fails with `why`. The
    /// principal stays, so the deploy still reports as whom it was running.
    pub fn revoke(&self, why: String) {
        let revoked: Arc<dyn Identity> = Arc::new(Revoked { sender: self.sender, why });
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = revoked;
    }

    fn current(&self) -> Arc<dyn Identity> {
        self.current.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// Runs until the identity it refreshes is gone: the deploy drops its agent,
/// the agent drops the identity, and the next tick finds nothing to refresh.
/// Or until the session is: the store's one terminal answer revokes the
/// identity, and the loop ends with it.
async fn refresh_loop(
    identity: Weak<RefreshingIdentity>,
    identities: Identities,
    session_id: String,
    origin: &'static str,
    account: Option<u64>,
) {
    loop {
        tokio::time::sleep(REFRESH_EVERY).await;
        let Some(identity) = identity.upgrade() else { return };
        match identities.delegated_identity(&session_id, origin, account).await {
            Ok(fresh) => {
                if let Err(e) = identity.refresh_with(Arc::new(fresh)) {
                    tracing::warn!("deploy identity not refreshed: {e}");
                }
            }
            // The grant is over — expired, revoked at id.ai, or replaced by a
            // newer sign-in — as Internet Identity itself reported it: the
            // delegation in hand may still verify for a few minutes, and
            // must not be used for them.
            Err(e) if e == RECONNECT_MSG => {
                tracing::warn!("deploy identity revoked: {e}");
                identity.revoke(e);
                return;
            }
            // Transient: the current delegation stays in use, and the next
            // tick tries again.
            Err(e) => tracing::warn!("deploy identity not refreshed: {e}"),
        }
    }
}

/// What a [`RefreshingIdentity`] signs with once its session is over: nothing.
struct Revoked {
    sender: Principal,
    why: String,
}

impl Identity for Revoked {
    fn sender(&self) -> Result<Principal, String> {
        Ok(self.sender)
    }
    fn public_key(&self) -> Option<Vec<u8>> {
        None
    }
    fn sign(&self, _content: &EnvelopeContent) -> Result<Signature, String> {
        Err(self.why.clone())
    }
    fn sign_delegation(&self, _content: &Delegation) -> Result<Signature, String> {
        Err(self.why.clone())
    }
    fn sign_arbitrary(&self, _content: &[u8]) -> Result<Signature, String> {
        Err(self.why.clone())
    }
}

impl Identity for RefreshingIdentity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(self.sender)
    }
    fn public_key(&self) -> Option<Vec<u8>> {
        self.current().public_key()
    }
    fn sign(&self, content: &EnvelopeContent) -> Result<Signature, String> {
        self.current().sign(content)
    }
    fn sign_delegation(&self, content: &Delegation) -> Result<Signature, String> {
        self.current().sign_delegation(content)
    }
    fn sign_arbitrary(&self, content: &[u8]) -> Result<Signature, String> {
        self.current().sign_arbitrary(content)
    }
    fn delegation_chain(&self) -> Vec<SignedDelegation> {
        self.current().delegation_chain()
    }
    fn sender_info(&self) -> Option<SenderInfo> {
        self.current().sender_info()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_agent::identity::BasicIdentity;

    fn key(seed: u8) -> Arc<dyn Identity> {
        Arc::new(BasicIdentity::from_raw_key(&[seed; 32]))
    }

    #[test]
    fn a_refresh_keeps_the_principal_and_takes_the_new_key() {
        let first = key(1);
        let identity = RefreshingIdentity::over(first.clone()).unwrap();
        assert_eq!(identity.sender().unwrap(), first.sender().unwrap());

        // Same key again: accepted, and the signer is the new object.
        let again = key(1);
        identity.refresh_with(again.clone()).unwrap();
        assert_eq!(
            identity.sign_arbitrary(b"x").unwrap().signature,
            again.sign_arbitrary(b"x").unwrap().signature
        );

        // A different principal is refused and leaves the current one in place.
        let other = key(2);
        let err = identity.refresh_with(other.clone()).unwrap_err();
        assert!(err.contains("not"), "{err}");
        assert_eq!(identity.public_key(), first.public_key());
        assert_ne!(identity.public_key(), other.public_key());
    }

    // Revoked, the identity keeps its principal and signs nothing: the
    // deploy's next call fails with the session's own reason, and a later
    // refresh cannot bring the signer back.
    #[test]
    fn a_revoked_identity_signs_nothing_more() {
        let first = key(1);
        let identity = RefreshingIdentity::over(first.clone()).unwrap();
        identity.revoke(RECONNECT_MSG.into());
        assert_eq!(identity.sender().unwrap(), first.sender().unwrap());
        assert_eq!(identity.sign_arbitrary(b"x").unwrap_err(), RECONNECT_MSG);
        assert!(identity.public_key().is_none());
        // The refresh loop has ended by then; a refresh that did arrive would
        // reinstate signing, so revocation is the loop's last act.
        identity.refresh_with(key(1)).unwrap();
        assert!(identity.sign_arbitrary(b"x").is_ok());
    }
}
