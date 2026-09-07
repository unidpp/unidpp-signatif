//! Real ceremonies: the Confium seam driven by the crate's own M-of-K
//! threshold cryptography ([`crate::threshold`] — Feldman-verifiable
//! Shamir shares, threshold Schnorr partials, group signatures that
//! are standard Ed25519).
//!
//! # Which implementation to use
//!
//! - [`crate::confium::mock::MockCeremony`] — interface-only, no cryptography.
//!   Use it for lifecycle and interface tests of the trust layer that
//!   must not depend on the crypto: session states, message counts,
//!   member authentication, expiry, misbehavior plumbing.
//! - [`crate::confium::real::RealCeremony`] (this module) — the same
//!   [`crate::confium::CeremonyCoordinator`] trait over real threshold
//!   cryptography. Use it for cryptographic integration tests and as
//!   the reference for what a Confium binding will drive.
//! - the `ceremony` binary (`src/bin/ceremony.rs`) — operator runs
//!   across processes: an operator generates a group and distributes
//!   share files out of band, a qualifying set signs, anyone verifies
//!   the standard Ed25519 group signature.
//!
//! # Protocol mapping
//!
//! ```text
//! create_session      threshold::generate — the ceremony seed derives
//!                     from the quorum spec (below)
//! submit_commitment   round 1: the member's deterministic nonce point
//!                     (threshold::nonce_point) as the transcript
//! submit_share        round 2: the member's partial signature
//!                     (threshold::sign_partial) as JSON material
//! aggregate           threshold::combine → one standard Ed25519 group
//!                     signature under the group key
//! ```
//!
//! Rounds are strict — Confium spec 22 sessions are strict rounds, and
//! [`crate::threshold::combine`] takes exactly T partials: exactly T
//! commitments close round 1, exactly T shares close round 2, and a
//! late round-1 message is [`crate::confium::CeremonyError::WrongRound`], not
//! silently absorbed.
//!
//! Both [`crate::confium::CeremonyKind::Dkg`] and [`crate::confium::CeremonyKind::Sign`]
//! run the two cryptographic rounds and aggregate a group signature
//! over the framed statement — the seam's `aggregate` returns an
//! [`crate::confium::AggregatedSignature`] for every kind. For DKG the
//! statement is the *inauguration message* the new group key first
//! signs; the key derivation itself ignores it. Reshare and Refresh
//! are refused with [`crate::confium::CeremonyError::Framework`]: `threshold`
//! has no re-share, and this bridge does not fake one.
//!
//! # The ceremony seed — property and limits
//!
//! `create_session` derives the ceremony seed deterministically from
//! the [`crate::confium::QuorumSpec`] alone (quorum id, threshold, the sorted
//! member list), via [`crate::confium::real::RealCeremony::ceremony_seed`]. The property
//! this buys: the derivation is **stable across participants** — any
//! process holding the same quorum spec derives the same group key and
//! the same member shares, DKG and signing sessions for the same
//! quorum agree on the group regardless of their statements, and a
//! freshly created coordinator lands on the same key. Tests and
//! rehearsals are reproducible.
//!
//! The limit, stated plainly: **the seed is derived from public
//! data**. Anyone who knows the quorum spec can re-derive the group
//! scalar and every member share. `RealCeremony` is therefore a test,
//! rehearsal, and integration harness — not a production root
//! ceremony. Production groups derive from secret entropy (the
//! `ceremony` binary's `init` without `--seed` uses OS entropy) or a
//! real distributed key generation.
//!
//! # Trust assumptions
//!
//! `threshold` ships the honest-dealer form: the polynomial exists
//! whole inside [`crate::threshold::generate`]. `RealCeremony` plays
//! that dealer at `create_session` and holds the members' shares for
//! the session's lifetime — members fetch theirs via
//! [`crate::confium::real::RealCeremony::share_of`], and round messages are built with
//! [`crate::confium::real::RealCeremony::commitment_for`] / [`crate::confium::real::RealCeremony::share_for`].
//! In-process, the coordinator could therefore sign alone; the
//! threshold property is enforced by the protocol shape, not by
//! process isolation. Deployments that need isolation distribute
//! share files out of band (the `ceremony` binary) and centralize only
//! the combiner. A lying dealer is detectable by every member
//! ([`crate::threshold::verify_share`]); a misbehaving signer aborts
//! the ceremony with the culprit named (below).
//!
//! # Identifiable abort
//!
//! [`crate::threshold::combine`] verifies every partial against the
//! Feldman commitments; an invalid partial fails with the culprit's
//! member index. `aggregate` maps that onto the seam's misbehavior
//! path: a [`crate::confium::MisbehaviorProof`] naming the offending member
//! (the culprit's index identifies the quorum member; the coordinator
//! holds every member's honest partial, so the culprit is found by
//! comparison, deterministically), with the submitted material as
//! evidence, recorded for
//! [`crate::confium::CeremonyCoordinator::abort_proof`]. Malformed round-2
//! material, a partial claiming another member's index, and a partial
//! that does not bind to its round-1 commitment are identifiable
//! aborts too, caught at submission.

use std::collections::BTreeMap;

use unidpp_model::Timestamp;

use crate::graph::NodeId;
use crate::keyring::PublicKey;
use crate::sign::{domain_framed, SigningDomain, Suite};
use crate::threshold::{self, GroupKey, MemberShare, PartialSignature};

use super::{
    AggregatedSignature, CeremonyCoordinator, CeremonyError, CeremonyKind, Commitment,
    MisbehaviorProof, QuorumSpec, SessionId, SessionInit, SessionState, Share,
};

/// The dealer's bookkeeping for one quorum: the public group plus
/// every member's share (shares are secret to their members; here
/// they live in the coordinator because the coordinator *is* the
/// dealer — see the module's trust assumptions).
type QuorumGroup = (GroupKey, Vec<MemberShare>);

/// A running (or finished) real session.
struct RealSession {
    init: SessionInit,
    /// Canonical member order (the quorum's members, sorted): member
    /// index = position + 1, matching `threshold`'s 1-based indices.
    /// Sorting makes the index assignment stable across participants
    /// regardless of declaration order.
    members: Vec<NodeId>,
    state: SessionState,
    /// Round-1 commitments by member index.
    committed: BTreeMap<u32, Commitment>,
    /// Round-2 partials by member index.
    partials: BTreeMap<u32, PartialSignature>,
    /// Submitted round-2 material by member index (evidence for
    /// misbehavior proofs).
    materials: BTreeMap<u32, Vec<u8>>,
    abort: Option<MisbehaviorProof>,
}

impl RealSession {
    fn index_of(&self, member: &NodeId) -> Option<u32> {
        self.members
            .iter()
            .position(|m| m == member)
            .map(|position| position as u32 + 1)
    }

    fn member_at(&self, index: u32) -> Option<&NodeId> {
        self.members.get(index as usize - 1)
    }

    /// The bytes every partial is computed over: the statement
    /// payload framed in the quorum domain (the same framing the
    /// seam's [`AggregatedSignature::verify`] checks).
    fn framed(&self) -> Vec<u8> {
        domain_framed(SigningDomain::Quorum, &self.init.statement.payload)
    }

    /// Record the abort and return its error.
    fn record_abort(
        &mut self,
        offender: NodeId,
        offense: &str,
        evidence: Vec<u8>,
    ) -> CeremonyError {
        let proof = MisbehaviorProof {
            offender,
            offense: offense.to_string(),
            evidence,
        };
        self.abort = Some(proof.clone());
        CeremonyError::Misbehavior(Box::new(proof))
    }
}

/// The real coordinator: the seam's session API over the crate's
/// threshold cryptography. See the module docs for the protocol
/// mapping, the seed property and its limits, and the trust
/// assumptions.
pub struct RealCeremony {
    sessions: BTreeMap<String, RealSession>,
    groups: BTreeMap<String, QuorumGroup>,
    counter: u64,
    clock: Option<Timestamp>,
}

impl RealCeremony {
    /// New coordinator with an optional fixed clock (expiry checks).
    pub fn new(clock: Option<Timestamp>) -> RealCeremony {
        RealCeremony {
            sessions: BTreeMap::new(),
            groups: BTreeMap::new(),
            counter: 0,
            clock,
        }
    }

    /// Advance the clock (expiry checks).
    pub fn set_clock(&mut self, now: Timestamp) {
        self.clock = Some(now);
    }

    /// The deterministic ceremony seed of a quorum: SHA-256 over a
    /// domain tag, the threshold, the quorum id, and the sorted
    /// member ids (sorted so the derivation — and with it the group
    /// key and every member share — does not depend on declaration
    /// order). Public so participants and tests can state the
    /// derivation; see the module docs for the limits of a
    /// public-data-derived seed.
    pub fn ceremony_seed(quorum: &QuorumSpec) -> Vec<u8> {
        let mut members = quorum.members.clone();
        members.sort();
        let threshold = quorum.threshold.to_le_bytes();
        let mut parts: Vec<&[u8]> = vec![
            b"UNIDPP-SIGNATIF/CONFIUM-REAL/CEREMONY-SEED",
            &threshold,
            quorum.quorum_id.as_str().as_bytes(),
        ];
        parts.extend(members.iter().map(|m| m.as_str().as_bytes()));
        sha256_of(&parts).to_vec()
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

    fn session(&self, session: &SessionId) -> Result<&RealSession, CeremonyError> {
        self.sessions
            .get(session.as_str())
            .ok_or_else(|| CeremonyError::UnknownSession(session.to_string()))
    }

    /// The public group a session's quorum acts under (Feldman
    /// commitments included — pin it as the group's trust anchor).
    pub fn group(&self, session: &SessionId) -> Result<GroupKey, CeremonyError> {
        let s = self.session(session)?;
        group_at(&self.groups, s.init.quorum.quorum_id.as_str())
    }

    /// One member's share for the session's group — the dealer-side
    /// handout. The member verifies it against the group's Feldman
    /// commitments ([`threshold::verify_share`]) and keeps it secret.
    pub fn share_of(
        &self,
        session: &SessionId,
        member: &NodeId,
    ) -> Result<MemberShare, CeremonyError> {
        let s = self.session(session)?;
        let index = s.index_of(member).ok_or_else(|| {
            CeremonyError::Framework(format!(
                "{member} is not a member of quorum {}",
                s.init.quorum.quorum_id
            ))
        })?;
        share_at(&self.groups, s.init.quorum.quorum_id.as_str(), index)
    }

    /// The member's round-1 message: their deterministic nonce point
    /// for this session's framed statement, hex-encoded as the
    /// commitment transcript.
    pub fn commitment_for(
        &self,
        session: &SessionId,
        member: &NodeId,
    ) -> Result<Commitment, CeremonyError> {
        let s = self.session(session)?;
        let share = self.share_of(session, member)?;
        let nonce = threshold::nonce_point(&share, &s.framed())
            .map_err(|e| CeremonyError::Framework(format!("nonce point: {e}")))?;
        Ok(Commitment {
            signer: member.clone(),
            transcript: nonce.into_bytes(),
        })
    }

    /// The member's round-2 message: their partial signature over the
    /// qualifying set's group nonce, JSON-encoded as the share
    /// material. Needs round 1 closed (the partial binds to the
    /// qualifying set's committed nonce points).
    pub fn share_for(&self, session: &SessionId, member: &NodeId) -> Result<Share, CeremonyError> {
        let s = self.session(session)?;
        if s.state != SessionState::CommitmentsCollected {
            return Err(CeremonyError::WrongRound {
                session: session.to_string(),
                attempted: "build a round-2 share",
                state: s.state,
            });
        }
        let partial = honest_partial_at(
            &self.groups,
            s,
            s.index_of(member).ok_or_else(|| {
                CeremonyError::Framework(format!("{member} is not a member of this quorum"))
            })?,
        )
        .map_err(|e| CeremonyError::Framework(format!("partial signing: {e}")))?;
        let material = serde_json::to_vec(&partial)
            .map_err(|e| CeremonyError::Framework(format!("partial encoding: {e}")))?;
        Ok(Share {
            signer: member.clone(),
            material,
        })
    }

    /// Generate (once per quorum) and cache the group the quorum acts
    /// under. Deterministic in the ceremony seed, so a re-creation is
    /// the same group.
    fn generate_for(&mut self, quorum: &QuorumSpec) -> Result<(), CeremonyError> {
        if !self.groups.contains_key(quorum.quorum_id.as_str()) {
            let seed = RealCeremony::ceremony_seed(quorum);
            let generated = threshold::generate(&seed, quorum.threshold, quorum.members.len())
                .map_err(|e| CeremonyError::Framework(format!("threshold generation: {e}")))?;
            self.groups.insert(quorum.quorum_id.to_string(), generated);
        }
        Ok(())
    }
}

impl CeremonyCoordinator for RealCeremony {
    type Error = CeremonyError;

    fn create_session(&mut self, init: SessionInit) -> Result<SessionId, CeremonyError> {
        init.quorum
            .validate()
            .map_err(|e| CeremonyError::Framework(format!("quorum validation failed: {e}")))?;
        match init.kind {
            CeremonyKind::Dkg | CeremonyKind::Sign => {}
            other => {
                return Err(CeremonyError::Framework(format!(
                    "a {other:?} ceremony is not implemented in this bridge: threshold has \
                     no re-share — run a fresh Dkg (new quorum id) or use the ceremony binary"
                )))
            }
        }
        self.generate_for(&init.quorum)?;
        self.counter += 1;
        let id = SessionId::new(&format!("real-{}-{}", init.quorum.quorum_id, self.counter))
            .map_err(|e| CeremonyError::Framework(format!("session id: {e}")))?;
        let mut members = init.quorum.members.clone();
        members.sort();
        self.sessions.insert(
            id.as_str().to_string(),
            RealSession {
                init,
                members,
                state: SessionState::Pending,
                committed: BTreeMap::new(),
                partials: BTreeMap::new(),
                materials: BTreeMap::new(),
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
        let s = self
            .sessions
            .get_mut(session.as_str())
            .expect("live checked");
        if s.state != SessionState::Pending {
            return Err(CeremonyError::WrongRound {
                session: session.to_string(),
                attempted: "submit a round-1 commitment",
                state: s.state,
            });
        }
        let Some(index) = s.index_of(&commitment.signer) else {
            return Err(s.record_abort(
                commitment.signer.clone(),
                "commitment from non-member",
                commitment.transcript.clone(),
            ));
        };
        if s.committed.contains_key(&index) {
            return Err(s.record_abort(
                commitment.signer.clone(),
                "double commitment in round 1",
                commitment.transcript.clone(),
            ));
        }
        // Round-1 binding: the transcript must be the member's
        // deterministic nonce point for this session's framed
        // statement — anything else is a commitment that does not
        // correspond to the member's share.
        let share = share_at(&self.groups, s.init.quorum.quorum_id.as_str(), index)?;
        let expected = threshold::nonce_point(&share, &s.framed())
            .map_err(|e| CeremonyError::Framework(format!("nonce point: {e}")))?;
        if commitment.transcript != expected.as_bytes() {
            return Err(s.record_abort(
                commitment.signer.clone(),
                "commitment transcript is not the member's deterministic nonce point for \
                 this statement",
                commitment.transcript.clone(),
            ));
        }
        s.committed.insert(index, commitment);
        if s.committed.len() >= s.init.quorum.threshold {
            s.state = SessionState::CommitmentsCollected;
        }
        Ok(())
    }

    fn submit_share(&mut self, session: &SessionId, share: Share) -> Result<(), CeremonyError> {
        self.live(session)?;
        let s = self
            .sessions
            .get_mut(session.as_str())
            .expect("live checked");
        if s.state != SessionState::CommitmentsCollected {
            return Err(CeremonyError::WrongRound {
                session: session.to_string(),
                attempted: "submit a round-2 share",
                state: s.state,
            });
        }
        let Some(index) = s.index_of(&share.signer) else {
            return Err(s.record_abort(
                share.signer.clone(),
                "share from non-member",
                share.material.clone(),
            ));
        };
        if !s.committed.contains_key(&index) {
            return Err(s.record_abort(
                share.signer.clone(),
                "share without a round-1 commitment",
                share.material.clone(),
            ));
        }
        if s.partials.contains_key(&index) {
            return Err(s.record_abort(
                share.signer.clone(),
                "double share in round 2",
                share.material.clone(),
            ));
        }
        let partial: PartialSignature = match serde_json::from_slice(&share.material).ok() {
            Some(partial) => partial,
            None => {
                return Err(s.record_abort(
                    share.signer.clone(),
                    "share material is not a threshold partial signature",
                    share.material.clone(),
                ))
            }
        };
        if partial.index != index {
            return Err(s.record_abort(
                share.signer.clone(),
                "partial claims another member's index",
                share.material.clone(),
            ));
        }
        // Round-2 binding: the partial must be over the nonce the
        // member committed in round 1.
        let committed = String::from_utf8(s.committed[&index].transcript.clone())
            .map_err(|e| CeremonyError::Framework(format!("commitment transcript: {e}")))?;
        if partial.nonce != committed {
            return Err(s.record_abort(
                share.signer.clone(),
                "partial nonce does not match the member's round-1 commitment",
                share.material.clone(),
            ));
        }
        s.partials.insert(index, partial);
        s.materials.insert(index, share.material);
        if s.partials.len() >= s.init.quorum.threshold {
            s.state = SessionState::SharesCollected;
        }
        Ok(())
    }

    fn aggregate(&mut self, session: &SessionId) -> Result<AggregatedSignature, CeremonyError> {
        self.live(session)?;
        // Below threshold is the seam's refusal — never a panic. (With
        // strict rounds the count can only be below or exactly at the
        // threshold; `combine` takes exactly T partials.)
        let (framed, partials, quorum_id) = {
            let s = self
                .sessions
                .get_mut(session.as_str())
                .expect("live checked");
            let need = s.init.quorum.threshold;
            let have = s.partials.len();
            if have < need {
                return Err(CeremonyError::ThresholdNotMet { have, need });
            }
            (
                s.framed(),
                s.partials.values().cloned().collect::<Vec<_>>(),
                s.init.quorum.quorum_id.to_string(),
            )
        };
        let group = group_at(&self.groups, &quorum_id)?;
        match threshold::combine(&group, &framed, &partials) {
            Ok(signature) => {
                // The bridging resolution: `combine`'s output is *one
                // standard Ed25519 signature* under the group key
                // (`R || s`, verifiable by any Ed25519 verifier), so
                // the seam's AggregatedSignature carries it natively
                // — no type extension needed. `verify` and `to_slot`
                // work unchanged because the partials were computed
                // over the Quorum-domain-framed statement payload.
                let value = signature.to_ed25519_bytes().map_err(|e| {
                    CeremonyError::Framework(format!("group signature encoding: {e}"))
                })?;
                let group_key =
                    PublicKey::Ed25519(unhex32(&group.group_public).ok_or_else(|| {
                        CeremonyError::Framework("the group public key is not hex".to_string())
                    })?);
                let s = self
                    .sessions
                    .get_mut(session.as_str())
                    .expect("live checked");
                s.state = SessionState::Completed;
                Ok(AggregatedSignature {
                    suite: Suite::Ed25519,
                    value: value.to_vec(),
                    group_key,
                })
            }
            Err(e) => {
                // `combine` names the culprit by member index; the
                // coordinator holds every member's honest partial, so
                // the culprit is identified by comparison (the honest
                // partial is the unique scalar satisfying the
                // commitment equation for this nonce and challenge).
                let s = self
                    .sessions
                    .get_mut(session.as_str())
                    .expect("live checked");
                let mut culprit: Option<(NodeId, Vec<u8>)> = None;
                for (index, submitted) in s.partials.iter() {
                    let honest = honest_partial_at(&self.groups, s, *index).map_err(|e| {
                        CeremonyError::Framework(format!("culprit identification: {e}"))
                    })?;
                    if &honest != submitted {
                        let offender = s.member_at(*index).cloned().ok_or_else(|| {
                            CeremonyError::Framework(format!(
                                "culprit index {index} has no quorum member"
                            ))
                        })?;
                        culprit = Some((
                            offender,
                            s.materials.get(index).cloned().unwrap_or_default(),
                        ));
                        break;
                    }
                }
                match culprit {
                    Some((offender, evidence)) => Err(s.record_abort(
                        offender,
                        "threshold partial failed the Feldman commitment verification \
                         (combine aborted, culprit identified)",
                        evidence,
                    )),
                    None => Err(CeremonyError::Framework(format!(
                        "threshold combination failed: {e}"
                    ))),
                }
            }
        }
    }

    fn session_state(&self, session: &SessionId) -> Option<SessionState> {
        self.sessions.get(session.as_str()).map(|s| s.state)
    }

    fn abort_proof(&self, session: &SessionId) -> Option<&MisbehaviorProof> {
        self.sessions
            .get(session.as_str())
            .and_then(|s| s.abort.as_ref())
    }
}

// ---------------------------------------------------------------------------
// Free helpers (they take the group table explicitly so coordinator
// methods can mix a session borrow with group lookups).
// ---------------------------------------------------------------------------

fn group_at(
    groups: &BTreeMap<String, QuorumGroup>,
    quorum_id: &str,
) -> Result<GroupKey, CeremonyError> {
    groups
        .get(quorum_id)
        .map(|(group, _)| group.clone())
        .ok_or_else(|| {
            CeremonyError::Framework(format!("quorum `{quorum_id}` has no generated group"))
        })
}

fn share_at(
    groups: &BTreeMap<String, QuorumGroup>,
    quorum_id: &str,
    index: u32,
) -> Result<MemberShare, CeremonyError> {
    groups
        .get(quorum_id)
        .and_then(|(_, shares)| shares.get(index as usize - 1).cloned())
        .ok_or_else(|| {
            CeremonyError::Framework(format!(
                "quorum `{quorum_id}` has no share for member {index}"
            ))
        })
}

/// The partial member `index` would honestly submit in this session
/// (the dealer can always recompute one; used to name the culprit
/// when `combine` aborts).
fn honest_partial_at(
    groups: &BTreeMap<String, QuorumGroup>,
    s: &RealSession,
    index: u32,
) -> Result<PartialSignature, CeremonyError> {
    let group = group_at(groups, s.init.quorum.quorum_id.as_str())?;
    let share = share_at(groups, s.init.quorum.quorum_id.as_str(), index)?;
    let nonce_points: Vec<(u32, String)> = s
        .committed
        .iter()
        .map(|(i, commitment)| {
            let transcript = String::from_utf8(commitment.transcript.clone())
                .map_err(|e| CeremonyError::Framework(format!("commitment transcript: {e}")))?;
            Ok::<_, CeremonyError>((*i, transcript))
        })
        .collect::<Result<Vec<_>, _>>()?;
    threshold::sign_partial(&group, &share, &s.framed(), &nonce_points)
        .map_err(|e| CeremonyError::Framework(format!("partial signing: {e}")))
}

fn sha256_of(parts: &[&[u8]]) -> [u8; 32] {
    unidpp_model::sha256(parts).0
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}
