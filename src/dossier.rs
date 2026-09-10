//! The dossier (XB-5): every cross-border assurance flow works from
//! exchanged signed objects alone.
//!
//! A dossier is what the custodian hands a foreign verifier for one
//! subject: the signed policies, the signed spine with the inclusion
//! proofs, the sovereign attestations, the S13 journal — documents,
//! not API calls. The verifier's side is fully offline: its OWN
//! trust graph (its anchors, its acceptance policy), the dossier
//! file, and nothing else. A complete foreign verdict with zero
//! calls to foreign synchronous systems.

use crate::grid::{SignedPolicy, SignedSpine};
use crate::s13::S13Journal;
use crate::sovereign::SovereignAttestation;
use crate::spine_anchor::SpineReceipt;
use crate::SignatifError;
use unidpp_grid::SpineProof;
use unidpp_model::Hash;

/// The exchanged object set for one subject.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Dossier {
    /// The subject (passport id).
    pub subject: String,
    /// The governing policy objects, signed by their authorities.
    pub policies: Vec<SignedPolicy>,
    /// The commitment spine, signed by its custodian.
    pub spine: SignedSpine,
    /// Inclusion proofs for the segments the verifier needs.
    pub proofs: Vec<SpineProof>,
    /// The sovereign attestations substituting for sealed classes.
    pub attestations: Vec<SovereignAttestation>,
    /// The S13 exchange journal (requests and answers, signed).
    pub journal: S13Journal,
    /// The spine's log receipt (CN-4), when served.
    #[serde(default)]
    pub receipt: Option<SpineReceipt>,
}

impl Dossier {
    /// The exchange form (one JSON document).
    pub fn to_json(&self) -> Result<String, SignatifError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| SignatifError::crypto(format!("dossier serialization: {e}")))
    }

    /// Read the exchange form.
    pub fn from_json(json: &str) -> Result<Dossier, SignatifError> {
        serde_json::from_str(json)
            .map_err(|e| SignatifError::crypto(format!("dossier deserialization: {e}")))
    }

    /// Verify the dossier OFFLINE under the verifier's own trust
    /// graph — the only inputs are the dossier and the graph:
    ///
    /// * every policy signature resolves to its declared authority;
    /// * the spine signature resolves to its declared custodian, and
    ///   every inclusion proof verifies against the spine root;
    /// * every attestation verifies and binds a governing policy the
    ///   dossier actually carries;
    /// * the journal replays (every entry verifies; every answer is
    ///   bound to a journaled request).
    pub fn verify(&self, graph: &crate::graph::TrustGraph) -> Result<DossierCheck, SignatifError> {
        let mut check = DossierCheck::default();

        for policy in &self.policies {
            policy.verify(graph)?;
            check.policies_ok += 1;
        }

        self.spine.verify(graph)?;
        for proof in &self.proofs {
            if !proof.verifies_against(&self.spine.spine.root) {
                return Err(SignatifError::crypto(format!(
                    "dossier: inclusion proof for `{}` fails the spine root",
                    proof.segment_id
                )));
            }
            check.proofs_ok += 1;
        }

        for attestation in &self.attestations {
            attestation.verify(graph)?;
            let bound = self
                .policies
                .iter()
                .any(|p| attestation.binds_policy(&p.policy));
            if !bound {
                return Err(SignatifError::crypto(format!(
                    "dossier: an attestation names governing policy `{}` v{} which the dossier does not carry",
                    attestation.statement.governing_policy,
                    attestation.statement.governing_policy_version
                )));
            }
            check.attestations_ok += 1;
        }

        if let Some(receipt) = &self.receipt {
            if receipt.spine_digest != Hash(self.spine.spine.digest()) {
                return Err(SignatifError::crypto(
                    "dossier: the log receipt binds a different spine".to_string(),
                ));
            }
        }

        check.journal_decisions = self.journal.replay(graph)?;
        Ok(check)
    }
}

/// What the offline verification established.
#[derive(Debug, Clone, PartialEq, Default, serde::Serialize, serde::Deserialize)]
pub struct DossierCheck {
    /// Policies verified under their declared authorities.
    pub policies_ok: usize,
    /// Inclusion proofs verified against the spine root.
    pub proofs_ok: usize,
    /// Attestations verified and policy-bound.
    pub attestations_ok: usize,
    /// The S13 decisions reconstructed from the journal.
    pub journal_decisions: Vec<crate::s13::S13Decision>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acceptance::AcceptancePolicy;
    use crate::graph::{DelegationNode, NodeId, NodeKind, RegisteredKey, TrustGraph};
    use crate::keyring::{KeyId, KeyPair};
    use crate::s13::{S13JournalEntry, S13Side, SignedS13Request, SignedS13Response};
    use crate::sign::Suite;
    use crate::sovereign::{AttestationStatement, ClaimClass, CoverageGrade};
    use std::collections::BTreeMap;
    use unidpp_grid::{PolicyObject, RevealClass, Segment, Spine};
    use unidpp_s13::{S13Request, S13Response};

    struct Cast {
        graph: TrustGraph,
        authority: KeyPair,
        custodian: KeyPair,
        verifier: KeyPair,
        service: KeyPair,
        quorum: [KeyPair; 2],
    }

    fn cast() -> Cast {
        let authority = KeyPair::seeded(Suite::Ed25519, b"dossier/cn-samr").unwrap();
        let custodian = KeyPair::seeded(Suite::Ed25519, b"dossier/weilian").unwrap();
        let verifier = KeyPair::seeded(Suite::Ed25519, b"dossier/de-zoll").unwrap();
        let service = KeyPair::seeded(Suite::Ed25519, b"dossier/cn-attest").unwrap();
        let quorum = [
            KeyPair::seeded(Suite::Ed25519, b"dossier/quorum-a").unwrap(),
            KeyPair::seeded(Suite::Ed25519, b"dossier/quorum-b").unwrap(),
        ];
        let mut graph = TrustGraph::new();
        for (id, key) in [
            ("cn-samr", &authority),
            ("weilian-shenzhen", &custodian),
            ("de-zoll", &verifier),
            ("cn-attestation-service", &service),
            ("cn-quorum-a", &quorum[0]),
            ("cn-quorum-b", &quorum[1]),
        ] {
            let mut node = DelegationNode::new(NodeId::new(id).unwrap(), NodeKind::Delegated);
            node.register(RegisteredKey {
                key_id: KeyId::of(key.public()),
                public: *key.public(),
            });
            graph.add_node(node);
        }
        Cast {
            graph,
            authority,
            custodian,
            verifier,
            service,
            quorum,
        }
    }

    // The full document-orientation verify: dossier → file →
    // separate verification under the verifier's own anchors, zero
    // foreign calls; the foreign verdict re-derives the battery
    // case's coverage report.
    #[test]
    fn foreign_verdict_from_exchanged_objects_alone() {
        let cast = cast();
        let dossier = battery_dossier(&cast);
        let json = dossier.to_json().unwrap();
        let back = Dossier::from_json(&json).unwrap();
        assert_eq!(back, dossier);

        let check = back.verify(&cast.graph).unwrap();
        assert_eq!(check.policies_ok, 2);
        assert_eq!(check.proofs_ok, 1);
        assert_eq!(check.attestations_ok, 1);
        assert_eq!(check.journal_decisions.len(), 1);
        assert_eq!(check.journal_decisions[0].outcome, "attestation-offer");

        // The verifier's OWN acceptance policy grades the sealed
        // class from the dossier's attestation alone.
        let acceptance = AcceptancePolicy {
            profile: "urn:unidpp:profile:eu-battery".into(),
            attestation_services: vec!["cn-attestation-service".into()],
            accepted_claims: vec![ClaimClass::Conformity],
            minimum_quorum: 2,
            max_age_secs: None,
            element_modes: Default::default(),
        };
        let grade = acceptance.grade(&back.attestations[0], "cn-dynamic", "2030-06-01T08:30:00Z");
        assert_eq!(grade, CoverageGrade::AttestedByAuthority);
    }

    // Tampering anywhere in the exchange fails the offline verify.
    #[test]
    fn tampered_dossiers_fail_offline_verification() {
        let cast = cast();

        let mut swapped = battery_dossier(&cast);
        swapped.attestations[0].statement.value = "fail".into();
        assert!(swapped.verify(&cast.graph).is_err());

        let mut spliced = battery_dossier(&cast);
        spliced.proofs[0].commitment = [9u8; 32];
        assert!(spliced.verify(&cast.graph).is_err());

        // An attestation naming a policy the dossier does not carry.
        let mut orphan = battery_dossier(&cast);
        orphan.policies.truncate(1); // drop the sealed policy
        assert!(orphan.verify(&cast.graph).is_err());
    }

    fn battery_dossier(cast: &Cast) -> Dossier {
        let open_policy = SignedPolicy::issue(
            PolicyObject {
                policy_id: "eu-static-open".into(),
                version: 1,
                authority: "cn-samr".into(),
                readers: vec!["any-verifier".into()],
                verifiers: vec!["any-verifier".into()],
                writers: vec!["weilian-shenzhen".into()],
                reveal: RevealClass::Open,
                suites: vec!["ecdsa-p256".into()],
                valid_from: "2027-01-01T00:00:00Z".into(),
                valid_to: None,
                superseded_by: None,
            },
            &cast.authority,
        )
        .unwrap();
        let sealed_policy = SignedPolicy::issue(
            PolicyObject {
                policy_id: "cn-dynamic-bms".into(),
                version: 1,
                authority: "cn-samr".into(),
                readers: vec!["cn-customs".into()],
                verifiers: vec!["cn-customs".into(), "de-zoll".into()],
                writers: vec!["weilian-shenzhen".into()],
                reveal: RevealClass::OriginSealed,
                suites: vec!["sm2".into()],
                valid_from: "2027-01-01T00:00:00Z".into(),
                valid_to: None,
                superseded_by: None,
            },
            &cast.authority,
        )
        .unwrap();

        let mut commitments = BTreeMap::new();
        commitments.insert(
            "eu-static".to_string(),
            Segment::commit_state(b"cell_model=H-2231"),
        );
        commitments.insert(
            "cn-dynamic".to_string(),
            Segment::commit_state(b"cycle_count=412"),
        );
        let spine = Spine::over(1, commitments);
        let signed_spine =
            SignedSpine::issue(spine.clone(), "weilian-shenzhen", &cast.custodian).unwrap();
        let proof = spine.proof("cn-dynamic").unwrap();

        let statement = AttestationStatement {
            segment: "cn-dynamic".into(),
            state_commitment: spine.commitments["cn-dynamic"],
            claim: ClaimClass::Conformity,
            value: "pass".into(),
            as_of: "2030-06-01T08:00:00Z".into(),
            governing_policy: "cn-dynamic-bms".into(),
            governing_policy_version: 1,
            subject: "urn:unidpp:passport:pack-0001".into(),
        };
        let quorum_id = NodeId::new("cn-attestation-quorum").unwrap();
        let attestation = SovereignAttestation::issue(
            statement,
            "cn-attestation-service",
            &cast.service,
            Some((&quorum_id, 2, &[&cast.quorum[0], &cast.quorum[1]])),
        )
        .unwrap();

        let request = S13Request {
            verifier: "de-zoll".into(),
            subject: "urn:unidpp:passport:pack-0001".into(),
            profile: "urn:unidpp:profile:eu-battery".into(),
            segment: "cn-dynamic".into(),
            at: "2030-06-01T08:00:00Z".into(),
        };
        let signed_request = SignedS13Request::issue(request, "de-zoll", &cast.verifier).unwrap();
        let response = S13Response::evaluate(
            &signed_request.request,
            &sealed_policy.policy,
            "weilian-shenzhen",
        );
        let signed_response = SignedS13Response::issue(response, &cast.custodian).unwrap();
        let mut journal = S13Journal::new(S13Side::Custodian);
        journal.append(S13JournalEntry::Request(signed_request));
        journal.append(S13JournalEntry::Response(signed_response));

        Dossier {
            subject: "urn:unidpp:passport:pack-0001".into(),
            policies: vec![open_policy, sealed_policy],
            spine: signed_spine,
            proofs: vec![proof],
            attestations: vec![attestation],
            journal,
            receipt: None,
        }
    }
}
