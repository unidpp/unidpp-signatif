//! The verification pipeline: produces the core's `Verdict` types from
//! real trust state — the three readings, coverage reports, and
//! time-stamped historical verification valid as-of its anchors.
//!
//! The pipeline composes the layers:
//!
//! 1. **cryptographic reading** — the artifact event log's chain plus
//!    every co-signature slot verified with real crypto against the
//!    trust graph's registered keys;
//! 2. **trust-path reading** — each verifying key resolved through the
//!    scoped delegation graph to a root the verifier's anchor bundle
//!    accepts, with the path's executable scope conditions evaluated
//!    at verification time (the typed `scope_condition_failed`
//!    failure) and the §12 condition-withdrawal overlay applied;
//! 3. **current-state reading** — the revocation ledger's taints
//!    (window-scoped, cascading through the provenance DAG) fed to the
//!    core's `CurrentStateReading`;
//! 4. **coverage + freshness** — the profile's data points and
//!    freshness requirement via the core's `VerdictBuilder`, which
//!    owns the degradation ladder.
//!
//! The core `Verdict` reports the carrier-framing view (its trust
//! marker counts the core-suite slots); the SIGNATIF wrapper
//! ([`SignatifVerdict`]) carries the full multi-suite trust report and
//! the policy-scoped acceptance decision, so nothing the core cannot
//! express is lost.
//!
//! Historical verification ([`HistoricalVerification`]) is the
//! good-faith instrument: a verdict computed *as-of* a moment, over the
//! event-log prefix that existed then, with only the revocations a
//! diligent verifier could then know, and notarized against the
//! as-of state hash. [`HistoricalVerification::still_stands`] answers
//! whether it survives later retroactive (void-ab-initio) declarations.

use std::collections::BTreeSet;

use unidpp_event::EventLog;
use unidpp_model::{Hash, PassportId, ProfileManifest, Timestamp};
use unidpp_transform::ProvenanceGraph;
use unidpp_verdict::{Degradation, Outcome, Reading, Verdict, VerdictBuilder};

use crate::anchor::SignedTreeHead;
use crate::graph::{AnchorBundle, TrustGraph, TrustPath};
use crate::keyring::{KeyId, KeyPair, PublicKey};
use crate::revoke::{IssuanceIndex, RevocationLedger, Standing};
use crate::scope::ScopeRequest;
use crate::sign::{
    Acceptance, AcceptancePolicy, CoSignature, CoSignatureReport, SignatureSlot, SigningDomain,
    SlotVerdict, Suite,
};
use crate::SignatifError;

/// Everything the pipeline verifies about one target artifact.
pub struct VerificationTarget<'a> {
    /// The artifact's append-only event log (authoritative record).
    pub log: &'a EventLog,
    /// The artifact's co-signature over the core canonical payload.
    pub co_signature: CoSignature,
    /// The expected log head, as witnessed by a transparency-log
    /// anchor (None = offline; the verdict degrades, never silently
    /// passes).
    pub anchor: Option<Hash>,
    /// The profile lens the render claims (None = no coverage check).
    pub profile: Option<&'a ProfileManifest>,
    /// Data points the render actually provided.
    pub provided: BTreeSet<String>,
    /// Active relationship edges of the subject (for the current-state
    /// reading).
    pub active_links: usize,
}

/// Trust-layer facts about one signature slot.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SlotTrust {
    /// The slot's suite.
    pub suite: Suite,
    /// The slot's key id.
    pub key_id: KeyId,
    /// Raw cryptographic verification result.
    pub crypto: Result<(), String>,
    /// Revocation standing of the key at the verification moment.
    pub standing: Standing,
    /// Trust-path resolution result (scope + credentials).
    pub path: Result<TrustPath, String>,
    /// Scope-condition evaluation result (CC/SIGNATIF §14 hard check):
    /// the resolved path's effective-scope conditions evaluated against
    /// the verifier's request, plus the §12 condition-withdrawal
    /// overlay — a condition still carried by the scope but withdrawn
    /// in the ledger at the verification moment fails. `Ok(())` when
    /// the scope carries no conditions or all hold.
    pub conditions: Result<(), String>,
}

/// The trust report wrapping the core verdict.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TrustReport {
    /// Per-slot trust facts, in co-signature order.
    pub slots: Vec<SlotTrust>,
    /// Policy-scoped acceptance decision.
    pub acceptance: Acceptance,
    /// The co-signature cryptographic report (distinct verified suites
    /// etc.).
    pub crypto: CoSignatureReport,
}

/// The pipeline output: the core's [`Verdict`] plus the SIGNATIF trust
/// wrapper.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SignatifVerdict {
    /// The core graded verdict (three readings, coverage, freshness,
    /// degradation ladder).
    pub verdict: Verdict,
    /// The SIGNATIF trust report.
    pub trust: TrustReport,
}

impl SignatifVerdict {
    /// Which reading this verdict answers.
    pub fn reading_answered(&self) -> Reading {
        self.verdict.reading_answered
    }

    /// Overall acceptance: the acceptance policy is satisfied by at
    /// least one slot that also cryptographically verifies, has a
    /// resolved trust path whose **scope conditions evaluate true at
    /// verification time** (CC/SIGNATIF §3.6.4/§14: the request must
    /// satisfy every effective condition, and no condition may have
    /// been withdrawn in the ledger — the §12 condition-withdrawal
    /// track), the core outcome did not fail outright, and the
    /// current-state reading does not void ab initio (fraud
    /// laundering prevention: a retroactively misissued artifact is
    /// never accepted, however sound its signatures).
    ///
    /// Prospective key standing is *reported* per slot
    /// ([`SlotTrust::standing`]) rather than hard-blocking here: an
    /// artifact signed before a prospective revocation stands; one
    /// signed inside a voiding window is caught by the taint cascade.
    /// Degradation (stale data, offline without anchor) still counts
    /// as *accepted-but-degraded* — the core verdict states how.
    pub fn accepted(&self) -> bool {
        let slot_ok = self
            .trust
            .slots
            .iter()
            .any(|s| s.crypto.is_ok() && s.path.is_ok() && s.conditions.is_ok());
        self.trust.acceptance.is_accepted()
            && slot_ok
            && !matches!(self.verdict.outcome, Outcome::Fail(_))
            && !self.verdict.current_state.voids_ab_initio
    }

    /// Whether the current-state reading voids ab initio (fraud
    /// laundering prevention).
    pub fn voids_ab_initio(&self) -> bool {
        self.verdict.current_state.voids_ab_initio
    }
}

/// The verifier: trust graph, anchor bundle, revocation ledger, the
/// scope request the artifact claims, and the acceptance policy.
pub struct SignatifVerifier<'a> {
    /// The delegation trust graph.
    pub graph: &'a TrustGraph,
    /// The verifier's anchor bundle.
    pub bundle: &'a AnchorBundle,
    /// The revocation ledger.
    pub ledger: &'a RevocationLedger,
    /// The act the artifact is being verified for.
    pub request: ScopeRequest,
    /// The verifier's acceptance policy.
    pub policy: AcceptancePolicy,
}

impl<'a> SignatifVerifier<'a> {
    /// Evaluate a resolved path's scope conditions at verification
    /// time (CC/SIGNATIF §3.6.4, §11 `scope-conditions`):
    ///
    /// 1. every condition of the path's **effective scope** must hold
    ///    for the verifier's request (typed
    ///    [`SignatifError::ScopeConditionFailed`] on the first
    ///    failure — the standard's `scope_condition_failed` failure
    ///    reason);
    /// 2. no condition the scope still carries may have been
    ///    **withdrawn** (§12 `revocation-condition-withdrawal`): a
    ///    ledger declaration withdrawing a condition from a delegated
    ///    node, in force at `now`, fails any path whose credentials
    ///    granted that condition to that node.
    fn evaluate_conditions(&self, path: &TrustPath, now: Timestamp) -> Result<(), SignatifError> {
        if let Some(condition) = path.effective_scope.first_failed_condition(&self.request) {
            return Err(SignatifError::ScopeConditionFailed {
                condition: condition.clone(),
            });
        }
        for cred in &path.credentials {
            let withdrawn = self.ledger.withdrawn_conditions_at(&cred.child, now);
            for condition in &cred.scope.conditions {
                if withdrawn.contains(&condition) {
                    return Err(SignatifError::ScopeViolation(format!(
                        "scope condition `{condition}` granted to {} was withdrawn in the \
                         ledger (CC/SIGNATIF §12 condition withdrawal)",
                        cred.child
                    )));
                }
            }
        }
        Ok(())
    }

    /// Assemble the trust facts of one signature slot (plain or
    /// composite member): revocation standing, trust-path resolution,
    /// and the verify-time scope-condition evaluation.
    fn slot_trust(
        &self,
        slot: &SignatureSlot,
        crypto: Result<(), String>,
        now: Timestamp,
    ) -> SlotTrust {
        let standing = self.ledger.key_standing(&slot.key_id, now);
        let path = self
            .graph
            .resolve(&slot.key_id, &self.request, self.bundle)
            .map_err(|e| e.to_string());
        // CC/SIGNATIF §14 hard check: evaluate the effective scope's
        // conditions at verification time, with the §12 withdrawal
        // overlay from the ledger.
        let conditions = match &path {
            Ok(p) => self.evaluate_conditions(p, now).map_err(|e| e.to_string()),
            Err(e) => Err(format!(
                "no resolved path to evaluate scope conditions: {e}"
            )),
        };
        SlotTrust {
            suite: slot.suite,
            key_id: slot.key_id.clone(),
            crypto,
            standing,
            path,
            conditions,
        }
    }

    /// Verify a target `now`, answering the requested reading.
    ///
    /// `issuers` and `provenance` drive the current-state reading's
    /// taint cascade (which key issued which passport, and how
    /// passports derive from one another).
    pub fn verify(
        &self,
        target: &VerificationTarget<'_>,
        now: Timestamp,
        issuers: &IssuanceIndex,
        provenance: &ProvenanceGraph,
        reading: Reading,
    ) -> SignatifVerdict {
        let dir = self.graph.key_directory();
        let crypto_report = target.co_signature.verify(&dir);

        // Per-slot trust facts: plain slots, plus every composite's
        // members (a composite's crypto verdict is per-member; its
        // AND-composition lives in the crypto report).
        let mut slots = Vec::with_capacity(
            target.co_signature.slots.len()
                + target
                    .co_signature
                    .composites
                    .iter()
                    .map(|c| c.members.len())
                    .sum::<usize>(),
        );
        let mut any_verified = false;
        for slot in &target.co_signature.slots {
            let crypto = match dir.resolve(&slot.key_id) {
                None => Err(format!(
                    "key `{}` is not registered in the trust graph",
                    slot.key_id
                )),
                Some(public) => slot
                    .verify(
                        target.co_signature.domain,
                        &target.co_signature.payload,
                        public,
                    )
                    .map_err(|e| e.to_string()),
            };
            if crypto.is_ok() {
                any_verified = true;
            }
            slots.push(self.slot_trust(slot, crypto, now));
        }
        for composite in &target.co_signature.composites {
            let verdict = composite.verify(&dir);
            for (member, member_verdict) in composite.members.iter().zip(&verdict.members) {
                let crypto = match member_verdict {
                    SlotVerdict::Verified { .. } => Ok(()),
                    SlotVerdict::Invalid { why, .. } => Err(why.clone()),
                    SlotVerdict::Deferred { detail, .. } => Err(detail.clone()),
                    SlotVerdict::UnknownKey { .. } => Err(format!(
                        "composite member key `{}` is not registered in the trust graph",
                        member.key_id
                    )),
                };
                if crypto.is_ok() {
                    any_verified = true;
                }
                slots.push(self.slot_trust(member, crypto, now));
            }
        }

        let acceptance = self.policy.evaluate(&crypto_report);
        let taints = self
            .ledger
            .current_taints(target.log.subject(), issuers, provenance);

        let core_slots: Vec<unidpp_model::SigSlot> = target
            .co_signature
            .slots
            .iter()
            .filter_map(|s| s.to_sig_slot())
            .collect();

        let mut builder = VerdictBuilder::new(target.log, now)
            .with_signatures(core_slots)
            .attested_by_third_party(any_verified)
            .with_taints(taints)
            .with_active_links(target.active_links)
            .answering(reading);
        if let Some(anchor) = target.anchor {
            builder = builder.with_anchor(anchor);
        }
        if let Some(profile) = target.profile {
            builder = builder
                .with_profile(profile)
                .with_provided(target.provided.clone());
        }
        let verdict = builder.build();

        SignatifVerdict {
            verdict,
            trust: TrustReport {
                slots,
                acceptance,
                crypto: crypto_report,
            },
        }
    }

    /// Time-stamped historical verification: what a diligent verifier
    /// could know at `at`, over the as-of prefix of the event log and
    /// the as-of trust state, notarized against the as-of state hash.
    ///
    /// Prefix reconstruction appends the prefix's events unsalted, so
    /// for unsalted chains the prefix head *is* the original
    /// [`EventLog::state_hash_at`]; chains using salted commitments
    /// keep their authoritative anchor in the notary stamp's
    /// `state_hash` (recorded from the source log, not the
    /// reconstruction).
    pub fn verify_historical(
        &self,
        log: &EventLog,
        at: Timestamp,
        issuers: &IssuanceIndex,
        provenance: &ProvenanceGraph,
        notary_key: &KeyPair,
    ) -> Result<HistoricalVerification, SignatifError> {
        let mut prefix = EventLog::new(log.subject().clone());
        for sealed in log.as_of(at) {
            prefix
                .append(sealed.event.clone(), None, None)
                .map_err(|e| SignatifError::invalid(e.to_string()))?;
        }
        let state_hash = log
            .state_hash_at(at)
            .ok_or_else(|| SignatifError::invalid(format!("log has no state as of {at}")))?;
        let anchor = prefix.head();

        let taints = self
            .ledger
            .taints_known_at(log.subject(), issuers, provenance, at);
        let mut builder = VerdictBuilder::new(&prefix, at)
            .with_taints(taints)
            .answering(Reading::Evidentiary);
        if let Some(anchor) = anchor {
            builder = builder.with_anchor(anchor);
        }
        let verdict = builder.build();

        let stamp = HistoricalVerification::stamp_bytes(log.subject(), at, &state_hash);
        let notary = SignatureSlot::sign(notary_key, SigningDomain::HistoricalStamp, &stamp)?;

        Ok(HistoricalVerification {
            subject: log.subject().clone(),
            as_of: at,
            state_hash,
            verdict,
            notary,
        })
    }
}

/// A notarized as-of snapshot: a photograph, in the lens vocabulary.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HistoricalVerification {
    /// The subject passport.
    pub subject: PassportId,
    /// The as-of moment.
    pub as_of: Timestamp,
    /// The as-of state hash from the *source* log.
    pub state_hash: Hash,
    /// The verdict a diligent verifier reached at `as_of`.
    pub verdict: Verdict,
    /// The notary's signature slot.
    pub notary: SignatureSlot,
}

impl HistoricalVerification {
    /// Canonical stamped bytes.
    pub fn stamp_bytes(subject: &PassportId, as_of: Timestamp, state_hash: &Hash) -> Vec<u8> {
        let mut w = unidpp_model::CanonicalWriter::new();
        w.write_str(subject.as_str());
        w.write_i64(as_of.secs);
        w.write_u32(as_of.nanos);
        w.write_hash(state_hash);
        w.into_bytes()
    }

    /// Verify the notary's signature.
    pub fn verify_notary(&self, notary_public: &PublicKey) -> Result<(), SignatifError> {
        let stamp =
            HistoricalVerification::stamp_bytes(&self.subject, self.as_of, &self.state_hash);
        self.notary
            .verify(SigningDomain::HistoricalStamp, &stamp, notary_public)
    }

    /// Whether this historical verification still stands against the
    /// *current* trust state.
    ///
    /// - [`HistoricalStanding::Stands`] — the as-of evidence stands;
    ///   nothing retroactive has touched what it certified. (Whether
    ///   the verdict itself passed is reported, not assumed: a
    ///   diligent verifier may have concluded *degraded* or *fail*.)
    /// - [`HistoricalStanding::RetroactivelyInvalidated`] — a later
    ///   void-ab-initio declaration invalidated what it certified.
    ///   The stamp's *evidentiary* value (proof of diligence) stands;
    ///   its *conclusion* does not — exactly the browser root-store
    ///   semantics for timestamped-but-misissued certificates.
    pub fn still_stands(
        &self,
        ledger: &RevocationLedger,
        issuers: &IssuanceIndex,
        provenance: &ProvenanceGraph,
    ) -> HistoricalStanding {
        let now_taints = ledger.current_taints(&self.subject, issuers, provenance);
        let then_taints = ledger.taints_known_at(&self.subject, issuers, provenance, self.as_of);
        if now_taints.voids_ab_initio() && !then_taints.voids_ab_initio() {
            let retro = now_taints
                .entries()
                .iter()
                .find(|t| t.retroactive())
                .cloned();
            let (kind, window) = match retro {
                Some(t) => (t.kind.to_string(), t.window),
                None => ("retroactive".to_string(), None),
            };
            return HistoricalStanding::RetroactivelyInvalidated {
                kind,
                window,
                declared_via: format!("distrust window covering {}", self.subject),
            };
        }
        HistoricalStanding::Stands {
            evidentiary_pass: !matches!(self.verdict.outcome, Outcome::Fail(_)),
        }
    }
}

/// The fate of a historical verification under later declarations.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum HistoricalStanding {
    /// The as-of evidence stands.
    Stands {
        /// Whether the diligent verifier's verdict itself passed
        /// (Pass or Degraded, vs Fail).
        evidentiary_pass: bool,
    },
    /// A retroactive declaration voided what it certified ab initio.
    RetroactivelyInvalidated {
        /// The taint kind that voided it.
        kind: String,
        /// The voiding distrust window, when known.
        window: Option<unidpp_model::Interval>,
        /// Human-facing detail.
        declared_via: String,
    },
}

impl HistoricalStanding {
    /// Whether the historical conclusion survives.
    pub fn survives(&self) -> bool {
        matches!(self, HistoricalStanding::Stands { .. })
    }
}

/// Derive the anchor a verifier may pin for an artifact log from a
/// witnessed STH plus an inclusion proof of the log head: if the head
/// is included in the tree the STH signs, the head itself is the
/// anchor the core verdict should pin.
pub fn anchor_from_inclusion(
    log_head: &Hash,
    proof: &crate::anchor::InclusionProof,
    sth: &SignedTreeHead,
) -> Result<Hash, SignatifError> {
    crate::anchor::verify_inclusion(log_head, proof, &sth.root)?;
    Ok(*log_head)
}

/// Label a core outcome for stamping/logging (compact stable token).
pub fn outcome_token(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Pass => "pass",
        Outcome::Degraded(Degradation::StaleData { .. }) => "degraded/stale-data",
        Outcome::Degraded(Degradation::NoFreshnessEvidence) => "degraded/no-freshness-evidence",
        Outcome::Degraded(Degradation::OfflineNoAnchor) => "degraded/offline-no-anchor",
        Outcome::Degraded(Degradation::SignaturesFramedOnly) => "degraded/signatures-framed-only",
        Outcome::Degraded(Degradation::CoverageIncomplete { .. }) => "degraded/coverage-incomplete",
        Outcome::Fail(unidpp_verdict::Failure::BrokenChain) => "fail/broken-chain",
        Outcome::Fail(unidpp_verdict::Failure::AnchorMismatch) => "fail/anchor-mismatch",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_tokens_are_distinct() {
        assert_eq!(outcome_token(&Outcome::Pass), "pass");
        assert_ne!(
            outcome_token(&Outcome::Fail(unidpp_verdict::Failure::BrokenChain)),
            outcome_token(&Outcome::Fail(unidpp_verdict::Failure::AnchorMismatch))
        );
        assert_ne!(
            outcome_token(&Outcome::Degraded(Degradation::OfflineNoAnchor)),
            outcome_token(&Outcome::Degraded(Degradation::SignaturesFramedOnly))
        );
    }
}
