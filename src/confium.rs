//! Confium seam: interface-only trait shapes for threshold ceremonies.
//!
//! **Documented deviation — interface-only, no build dependency.** The
//! [Confium](https://github.com/confium/confium) framework (Ribose) is
//! the reference implementation of multi-stakeholder threshold
//! cryptography (FROST/GG18/CMP20 sessions, async coordinators,
//! compartmentalized stores). SIGNATIF models the *ceremony interfaces
//! a trust authority would implement* — root DKG, quorate signing,
//! re-sharing — but does not link Confium crates: the real binding
//! (FFI to `confium-tc` or a native Rust dependency) is deferred until
//! the integration is scheduled. Until then this module compiles
//! behind the `confium` feature with zero external dependencies, and
//! [`mock::MockCeremony`] provides a deterministic, clearly-labelled
//! stand-in for tests.
//!
//! The trait mirrors Confium's coordinator API
//! (`cfmc_session_create`, `cfmc_session_submit_commitment`,
//! `cfmc_session_submit_share`, `cfmc_session_aggregate`) and the
//! session lifecycle of Confium spec 22 (*Threshold session
//! lifecycle*):
//!
//! ```text
//! Pending
//!   ↓ (T commitments received)
//! CommitmentsCollected
//!   ↓ (T shares received)
//! SharesCollected
//!   ↓ (aggregation)
//! Completed
//!
//! Pending → Expired   (unlock window elapsed)
//! ```
//!
//! Every session message is signed by the sender's identity key in
//! real Confium; identifiable abort emits a signed proof of
//! misbehavior sufficient for administrative proceedings
//! ([`MisbehaviorProof`]).

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use unidpp_model::Timestamp;

use crate::graph::NodeId;
use crate::keyring::{KeyId, KeyPair, PublicKey};
use crate::sign::{SignatureSlot, SigningDomain, Suite};
use crate::SignatifError;

/// A ceremony session handle.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct SessionId(String);

impl SessionId {
    /// Wrap a handle string.
    pub fn new(raw: &str) -> Result<SessionId, SignatifError> {
        let n = raw.trim();
        if n.is_empty() || n.len() > 64 || !n.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(SignatifError::invalid(format!("bad session id `{raw}`")));
        }
        Ok(SessionId(n.to_string()))
    }

    /// The handle string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// T-of-N quorum description.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct QuorumSpec {
    /// Quorum node id (the trust-graph `ThresholdGroup`).
    pub quorum_id: NodeId,
    /// Threshold T.
    pub threshold: usize,
    /// Members N.
    pub members: Vec<NodeId>,
}

impl QuorumSpec {
    /// Whether `members` is well-formed for the threshold.
    pub fn validate(&self) -> Result<(), SignatifError> {
        if self.threshold == 0 || self.threshold > self.members.len() {
            return Err(SignatifError::invalid(format!(
                "quorum {} of {} members is degenerate",
                self.threshold,
                self.members.len()
            )));
        }
        if self.members.len() != BTreeSet::from_iter(self.members.iter().cloned()).len() {
            return Err(SignatifError::invalid("duplicate quorum member".to_string()));
        }
        Ok(())
    }
}

/// What a ceremony computes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CeremonyKind {
    /// Distributed key generation (the initial group key).
    Dkg,
    /// Quorate signing of a statement.
    Sign,
    /// Committee re-share (change members, keep the group key).
    Reshare,
    /// Proactive share refresh.
    Refresh,
}

/// The bytes a quorum is being asked to act on.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CeremonyStatement {
    /// Stable label of what is being signed (e.g. a revocation
    /// statement digest reference).
    pub label: String,
    /// Statement payload.
    pub payload: Vec<u8>,
}

/// A new ceremony request.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionInit {
    /// Ceremony kind.
    pub kind: CeremonyKind,
    /// The statement (ignored by DKG).
    pub statement: CeremonyStatement,
    /// The quorum acting.
    pub quorum: QuorumSpec,
    /// When the session expires if incomplete (unlock window).
    pub expires_at: Option<Timestamp>,
}

/// Round-1 message from one signer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Commitment {
    /// Committing member.
    pub signer: NodeId,
    /// Round-1 transcript (opaque here; real FROST commitments in the
    /// binding).
    pub transcript: Vec<u8>,
}

/// Round-2 message from one signer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Share {
    /// Sharing member.
    pub signer: NodeId,
    /// Round-2 material (opaque here).
    pub material: Vec<u8>,
}

/// The ceremony's aggregated output.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AggregatedSignature {
    /// Suite of the group signature.
    pub suite: Suite,
    /// Signature value under the group key.
    pub value: Vec<u8>,
    /// The group key the signature verifies under.
    pub group_key: PublicKey,
}

impl AggregatedSignature {
    /// Verify the aggregated signature against its group key in the
    /// [`SigningDomain::Quorum`] domain over the statement payload.
    pub fn verify(&self, statement: &CeremonyStatement) -> Result<(), SignatifError> {
        let framed = crate::sign::domain_framed(SigningDomain::Quorum, &statement.payload);
        crate::keyring::KeyPair::verify_raw(&self.group_key, &framed, &self.value)
    }

    /// Wrap as a SIGNATIF slot (key id derived from the group key).
    pub fn to_slot(&self) -> SignatureSlot {
        SignatureSlot {
            suite: self.suite,
            key_id: KeyId::of(&self.group_key),
            signature: Some(self.value.clone()),
        }
    }
}

/// Session lifecycle state (Confium spec 22).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SessionState {
    /// Created, waiting for commitments.
    Pending,
    /// T commitments received; waiting for shares.
    CommitmentsCollected,
    /// T shares received; aggregation possible.
    SharesCollected,
    /// Aggregated output produced.
    Completed,
    /// Unlock window elapsed incomplete.
    Expired,
}

/// Signed proof of misbehavior (identifiable abort).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MisbehaviorProof {
    /// Offending member.
    pub offender: NodeId,
    /// What they did (protocol-level description).
    pub offense: String,
    /// The offending message bytes.
    pub evidence: Vec<u8>,
}

/// Errors of the ceremony layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CeremonyError {
    /// Unknown session handle.
    UnknownSession(String),
    /// Lifecycle violation (wrong round for this message).
    WrongRound {
        /// Session.
        session: String,
        /// What was attempted.
        attempted: &'static str,
        /// Current state.
        state: SessionState,
    },
    /// A member acted outside the quorum rules; carries the abort
    /// proof.
    Misbehavior(Box<MisbehaviorProof>),
    /// Threshold not reached for aggregation.
    ThresholdNotMet {
        /// Have.
        have: usize,
        /// Need.
        need: usize,
    },
    /// The session expired.
    Expired,
    /// Underlying crypto/framework failure.
    Framework(String),
}

impl fmt::Display for CeremonyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CeremonyError::UnknownSession(s) => write!(f, "unknown ceremony session `{s}`"),
            CeremonyError::WrongRound {
                session,
                attempted,
                state,
            } => write!(
                f,
                "session `{session}` is in {state:?}; cannot {attempted}"
            ),
            CeremonyError::Misbehavior(p) => write!(
                f,
                "identifiable abort: {} misbehaved ({})",
                p.offender, p.offense
            ),
            CeremonyError::ThresholdNotMet { have, need } => {
                write!(f, "quorum not met: have {have} of {need}")
            }
            CeremonyError::Expired => write!(f, "ceremony session expired"),
            CeremonyError::Framework(m) => write!(f, "ceremony framework error: {m}"),
        }
    }
}

impl std::error::Error for CeremonyError {}

/// The coordinator seam: mirrors Confium's session API.
///
/// Implementors are honest-but-curious coordinators (Confium spec 23):
/// they see commitments and shares, cannot reconstruct the secret,
/// cannot corrupt aggregation (it is verifiable), and can DoS a session
/// (which is why high-stakes deployments run coordinators in parallel).
pub trait CeremonyCoordinator {
    /// Error type of the implementation.
    type Error;

    /// Create a session (`cfmc_session_create`).
    fn create_session(&mut self, init: SessionInit) -> Result<SessionId, Self::Error>;

    /// Submit a round-1 commitment (`cfmc_session_submit_commitment`).
    fn submit_commitment(
        &mut self,
        session: &SessionId,
        commitment: Commitment,
    ) -> Result<(), Self::Error>;

    /// Submit a round-2 share (`cfmc_session_submit_share`).
    fn submit_share(&mut self, session: &SessionId, share: Share) -> Result<(), Self::Error>;

    /// Aggregate the ceremony output (`cfmc_session_aggregate`).
    fn aggregate(&mut self, session: &SessionId) -> Result<AggregatedSignature, Self::Error>;

    /// Current session state.
    fn session_state(&self, session: &SessionId) -> Option<SessionState>;

    /// The misbehavior proof of the last identifiable abort, if any.
    fn abort_proof(&self, session: &SessionId) -> Option<&MisbehaviorProof>;
}

/// Deterministic, clearly-labelled ceremony mock (interface-only).
///
/// This is **not** threshold cryptography: the "group key" is a plain
/// seeded key derived from the quorum id, and "aggregation" is a plain
/// signature under it. What it *does* enforce, faithfully to the seam,
/// is the session lifecycle, the T-of-N message counts, member
/// authentication, and identifiable abort — so trust-layer tests can
/// drive the interface exactly as the real binding will.
pub mod mock {
    use super::*;

    /// A running (or finished) mock session.
    struct MockSession {
        init: SessionInit,
        state: SessionState,
        committed: BTreeMap<String, Commitment>,
        shares: BTreeMap<String, Share>,
        abort: Option<MisbehaviorProof>,
    }

    /// The mock coordinator.
    #[derive(Default)]
    pub struct MockCeremony {
        sessions: BTreeMap<String, MockSession>,
        counter: u64,
        clock: Option<Timestamp>,
    }

    impl MockCeremony {
        /// New coordinator with an optional fixed clock (expiry
        /// checks).
        pub fn new(clock: Option<Timestamp>) -> MockCeremony {
            MockCeremony {
                sessions: BTreeMap::new(),
                counter: 0,
                clock,
            }
        }

        /// Advance the mock clock (expiry checks).
        pub fn set_clock(&mut self, now: Timestamp) {
            self.clock = Some(now);
        }

        /// Deterministic group key for a quorum.
        pub fn group_key(quorum: &NodeId) -> Result<KeyPair, SignatifError> {
            let seed = format!("confium-mock-ceremony:{quorum}");
            KeyPair::seeded(Suite::Ed25519, seed.as_bytes())
        }

        fn live(&self, session: &SessionId) -> Result<(), CeremonyError> {
            match self.sessions.get(session.as_str()) {
                None => Err(CeremonyError::UnknownSession(session.to_string())),
                Some(s) => {
                    if let (Some(now), Some(expiry)) = (self.clock, s.init.expires_at) {
                        if now > expiry && !matches!(s.state, SessionState::Completed) {
                            return Err(CeremonyError::Expired);
                        }
                    }
                    Ok(())
                }
            }
        }
    }

    impl CeremonyCoordinator for MockCeremony {
        type Error = CeremonyError;

        fn create_session(&mut self, init: SessionInit) -> Result<SessionId, CeremonyError> {
            init.quorum.validate().map_err(|e| {
                CeremonyError::Framework(format!("quorum validation failed: {e}"))
            })?;
            self.counter += 1;
            let id = SessionId::new(&format!("mock-{}-{}", init.quorum.quorum_id, self.counter))
                .map_err(|e| CeremonyError::Framework(e.to_string()))?;
            self.sessions.insert(
                id.as_str().to_string(),
                MockSession {
                    init,
                    state: SessionState::Pending,
                    committed: BTreeMap::new(),
                    shares: BTreeMap::new(),
                    abort: None,
                },
            );
            Ok(id)
        }

        fn submit_commitment(
            &mut self,
            session: &SessionId,
            commitment: Commitment,
        ) -> Result<(), CeremonyError> {
            self.live(session)?;
            let is_member = |init: &SessionInit| {
                init.quorum.members.iter().any(|m| *m == commitment.signer)
            };
            let s = self
                .sessions
                .get_mut(session.as_str())
                .expect("live checked");
            if !is_member(&s.init) {
                s.abort = Some(MisbehaviorProof {
                    offender: commitment.signer.clone(),
                    offense: "commitment from non-member".into(),
                    evidence: commitment.transcript.clone(),
                });
                return Err(CeremonyError::Misbehavior(
                    Box::new(MisbehaviorProof {
                        offender: commitment.signer,
                        offense: "commitment from non-member".into(),
                        evidence: commitment.transcript,
                    }),
                ));
            }
            if s.committed.contains_key(commitment.signer.as_str()) {
                return Err(CeremonyError::Misbehavior(Box::new(MisbehaviorProof {
                    offender: commitment.signer.clone(),
                    offense: "double commitment in round 1".into(),
                    evidence: commitment.transcript.clone(),
                })));
            }
            s.committed
                .insert(commitment.signer.to_string(), commitment);
            if s.committed.len() >= s.init.quorum.threshold {
                s.state = SessionState::CommitmentsCollected;
            }
            Ok(())
        }

        fn submit_share(
            &mut self,
            session: &SessionId,
            share: Share,
        ) -> Result<(), CeremonyError> {
            self.live(session)?;
            let s = self
                .sessions
                .get_mut(session.as_str())
                .expect("live checked");
            if !s.committed.contains_key(share.signer.as_str()) {
                s.abort = Some(MisbehaviorProof {
                    offender: share.signer.clone(),
                    offense: "share without a round-1 commitment".into(),
                    evidence: share.material.clone(),
                });
                return Err(CeremonyError::Misbehavior(Box::new(
                    MisbehaviorProof {
                        offender: share.signer,
                        offense: "share without a round-1 commitment".into(),
                        evidence: share.material,
                    },
                )));
            }
            if s.shares.contains_key(share.signer.as_str()) {
                return Err(CeremonyError::Misbehavior(Box::new(MisbehaviorProof {
                    offender: share.signer.clone(),
                    offense: "double share in round 2".into(),
                    evidence: share.material.clone(),
                })));
            }
            s.shares.insert(share.signer.to_string(), share);
            if s.shares.len() >= s.init.quorum.threshold {
                s.state = SessionState::SharesCollected;
            }
            Ok(())
        }

        fn aggregate(&mut self, session: &SessionId) -> Result<AggregatedSignature, CeremonyError> {
            self.live(session)?;
            let s = self
                .sessions
                .get_mut(session.as_str())
                .expect("live checked");
            let need = s.init.quorum.threshold;
            let have = s.shares.len();
            if have < need {
                return Err(CeremonyError::ThresholdNotMet { have, need });
            }
            let group = MockCeremony::group_key(&s.init.quorum.quorum_id)
                .map_err(|e| CeremonyError::Framework(e.to_string()))?;
            let framed =
                crate::sign::domain_framed(SigningDomain::Quorum, &s.init.statement.payload);
            let value = group
                .sign_raw(&framed)
                .map_err(|e| CeremonyError::Framework(e.to_string()))?;
            s.state = SessionState::Completed;
            Ok(AggregatedSignature {
                suite: group.suite(),
                value,
                group_key: *group.public(),
            })
        }

        fn session_state(&self, session: &SessionId) -> Option<SessionState> {
            self.sessions.get(session.as_str()).map(|s| s.state)
        }

        fn abort_proof(&self, session: &SessionId) -> Option<&MisbehaviorProof> {
            self.sessions.get(session.as_str()).and_then(|s| s.abort.as_ref())
        }
    }
}
