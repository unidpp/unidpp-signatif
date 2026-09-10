//! Spine↔log anchoring (CN-4): one anchoring chain, not two.
//!
//! The spine proves segment state; the transparency log proves the
//! spine. A custodian's spine is anchored as ONE public commitment
//! in the log — its digest, in the SPINE-DIGEST domain (spec Annex
//! B, Table B.1) — and the receipt (inclusion proof + signed tree
//! head) is re-servable and verifiable offline: it rides the
//! dossier (XB-5). There is no second anchoring path: anything that
//! wants to prove a spine proves it through this log.

use crate::anchor::{verify_inclusion, InclusionProof, LogEntry, SignedTreeHead, TransparencyLog};
use crate::grid::SignedSpine;
use crate::keyring::{KeyPair, PublicKey};
use crate::SignatifError;
use unidpp_model::time::Timestamp;
use unidpp_model::Hash;

/// Anchor a spine in the transparency log — the one anchoring path.
/// Returns the leaf's sequence number.
pub fn anchor_spine(log: &mut TransparencyLog, spine: &SignedSpine) -> u64 {
    log.append(LogEntry::public(Hash(spine.spine.digest())))
}

/// The receipt: a re-servable, offline-verifiable proof that a
/// spine's digest is committed in the log.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SpineReceipt {
    /// The anchored spine digest (the leaf's commitment).
    pub spine_digest: Hash,
    /// The log that holds it.
    pub log_id: String,
    /// The leaf's sequence number.
    pub seq: u64,
    /// Inclusion proof of the leaf in the signed tree.
    pub proof: InclusionProof,
    /// The operator's signed tree head over the containing tree.
    pub head: SignedTreeHead,
}

impl SpineReceipt {
    /// Serve a receipt for the leaf at `seq` (re-servable: any
    /// number of servings verify against the same tree growth —
    /// proofs extend, never rewind).
    pub fn serve(
        log: &TransparencyLog,
        seq: u64,
        at: Timestamp,
        operator: &KeyPair,
    ) -> Result<SpineReceipt, SignatifError> {
        let entry = log.entry(seq)?;
        let spine_digest = entry.commitment;
        let proof = log.inclusion_proof(seq)?;
        let head = log.sign_tree_head(at, operator)?;
        Ok(SpineReceipt {
            spine_digest,
            log_id: log.log_id.clone(),
            seq,
            proof,
            head,
        })
    }

    /// Verify OFFLINE: the operator's tree-head signature holds, and
    /// the inclusion proof reconstructs the signed root over the
    /// spine digest.
    pub fn verify(&self, operator: &PublicKey) -> Result<(), SignatifError> {
        self.head.verify(operator)?;
        verify_inclusion(&self.spine_digest, &self.proof, &self.head.root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grid::SignedPolicy;
    use crate::sign::Suite;
    use std::collections::BTreeMap;
    use unidpp_grid::{PolicyObject, RevealClass, Segment, Spine};

    fn spine() -> SignedSpine {
        let custodian = KeyPair::seeded(Suite::Ed25519, b"anchor/custodian").unwrap();
        let mut commitments = BTreeMap::new();
        commitments.insert(
            "eu-static".to_string(),
            Segment::commit_state(b"cell_model=H-2231"),
        );
        commitments.insert(
            "cn-dynamic".to_string(),
            Segment::commit_state(b"cycle_count=412"),
        );
        let policy = PolicyObject {
            policy_id: "p".into(),
            version: 1,
            authority: "cn-samr".into(),
            readers: vec![],
            verifiers: vec![],
            writers: vec![],
            reveal: RevealClass::Open,
            suites: vec![],
            valid_from: "2027-01-01T00:00:00Z".into(),
            valid_to: None,
            superseded_by: None,
        };
        let _ = SignedPolicy::issue(policy, &custodian); // keys warmed
        SignedSpine::issue(Spine::over(1, commitments), "weilian-shenzhen", &custodian).unwrap()
    }

    // CN-4's verify: the spine root of a subject appears as a log
    // commitment with a re-servable receipt.
    #[test]
    fn the_spine_root_appears_as_a_log_commitment_with_a_reservable_receipt() {
        let operator = KeyPair::seeded(Suite::Ed25519, b"anchor/operator").unwrap();
        let mut log = TransparencyLog::new("unidpp-main");
        let anchored = spine();
        let seq = anchor_spine(&mut log, &anchored);
        let at = Timestamp::from_secs(1_900_000_000);

        let first = SpineReceipt::serve(&log, seq, at, &operator).unwrap();
        assert_eq!(first.spine_digest, Hash(anchored.spine.digest()));
        assert!(first.verify(operator.public()).is_ok());

        // Re-servable: a second serving after growth still proves the
        // same leaf (the tree extends; the proof re-derives).
        let mut grown = spine();
        grown.spine.version = 2;
        anchor_spine(&mut log, &grown);
        let second = SpineReceipt::serve(&log, seq, at, &operator).unwrap();
        assert_eq!(second.spine_digest, first.spine_digest);
        assert_eq!(second.seq, first.seq);
        assert!(second.verify(operator.public()).is_ok());
        assert_eq!(second.head.tree_size, 2);
    }

    // A spine never anchored yields no receipt — stated, not silent.
    #[test]
    fn unanchored_spines_have_no_receipt_stated() {
        let operator = KeyPair::seeded(Suite::Ed25519, b"anchor/operator").unwrap();
        let mut log = TransparencyLog::new("unidpp-main");
        let seq = anchor_spine(&mut log, &spine());
        // A second spine anchored elsewhere (or not at all): asking
        // for its leaf is a stated error, never an empty receipt.
        let err = SpineReceipt::serve(&log, seq + 5, Timestamp::from_secs(1), &operator);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("no entry"));
    }

    // A tampered receipt (a different digest under the proof) fails
    // offline verification.
    #[test]
    fn tampered_receipts_fail_offline() {
        let operator = KeyPair::seeded(Suite::Ed25519, b"anchor/operator").unwrap();
        let mut log = TransparencyLog::new("unidpp-main");
        let seq = anchor_spine(&mut log, &spine());
        let mut receipt =
            SpineReceipt::serve(&log, seq, Timestamp::from_secs(1), &operator).unwrap();
        receipt.spine_digest = Hash([9u8; 32]);
        assert!(receipt.verify(operator.public()).is_err());
    }
}
