//! Sovereign attestations (XB-2): signed, as-of statements ABOUT
//! sealed classes — substitution for cross-border verifiers.
//!
//! A sovereign attestation service speaks about a segment it can see
//! (its jurisdiction's origin-sealed data) to verifiers who cannot:
//! the statement names the segment's COMMITMENT (never its contents),
//! the claim class (conformity / commitment-hash / freshness), the
//! as-of moment, and the governing policy. High-stakes classes carry
//! a quorum co-signature. The verifier accepts the attestation under
//! its OWN anchors and grades coverage `attested-by-authority` —
//! assurance without access, across a border.

use crate::graph::{NodeId, TrustGraph};
use crate::keyring::KeyPair;
use crate::revoke::QuorumAttestation;
use crate::sign::{SignatureSlot, SigningDomain};
use crate::SignatifError;
use unidpp_grid::PolicyObject;

/// What the attestation claims about the sealed class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimClass {
    /// The segment's state conforms to the governing profile.
    Conformity,
    /// The segment's current state commitment is the stated hash.
    CommitmentHash,
    /// The segment's last commitment is within the freshness window.
    Freshness,
}

impl ClaimClass {
    /// Stable wire token.
    pub fn token(self) -> &'static str {
        match self {
            ClaimClass::Conformity => "conformity",
            ClaimClass::CommitmentHash => "commitment-hash",
            ClaimClass::Freshness => "freshness",
        }
    }

    /// High-stakes claims (the disclosure-adjacent ones) require the
    /// sovereign service's quorum co-signature; the rest the
    /// service's single signature suffices.
    pub fn high_stakes(self) -> bool {
        matches!(self, ClaimClass::Conformity)
    }
}

/// The statement (canonical, signable).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AttestationStatement {
    /// The segment attested about (by id, in its subject's grid).
    pub segment: String,
    /// sha256 of the segment's sealed state — what the attestation
    /// is ABOUT; contents never ride.
    pub state_commitment: [u8; 32],
    /// The claim class.
    pub claim: ClaimClass,
    /// The claim's value: a verdict token (conformity), the
    /// commitment itself (redundant but binding), or an ISO 8601
    /// duration (freshness window).
    /// The claim's value (verdict token / duration).
    pub value: String,
    /// As-of moment (RFC 3339).
    /// As-of moment (RFC 3339).
    pub as_of: String,
    /// The governing policy the claim was evaluated under.
    pub governing_policy: String,
    /// The governing policy's version.
    pub governing_policy_version: u64,
    /// The subject (passport id).
    pub subject: String,
}

impl AttestationStatement {
    /// The canonical, signable form (fixed field order, length-prefixed).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut w = unidpp_model::CanonicalWriter::new();
        w.write_bytes(self.segment.as_bytes());
        w.write_bytes(&self.state_commitment);
        w.write_bytes(self.claim.token().as_bytes());
        w.write_bytes(self.value.as_bytes());
        w.write_bytes(self.as_of.as_bytes());
        w.write_bytes(self.governing_policy.as_bytes());
        let v = self.governing_policy_version.to_le_bytes();
        w.write_bytes(&v);
        w.write_bytes(self.subject.as_bytes());
        w.into_bytes()
    }

    /// The statement's digest.
    pub fn digest(&self) -> [u8; 32] {
        unidpp_model::sha256(&[&self.canonical_bytes()]).0
    }
}

/// The issued attestation: the statement, the sovereign service's
/// signature, and (for high-stakes claims) the quorum co-signature.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SovereignAttestation {
    /// The attested statement.
    pub statement: AttestationStatement,
    /// The attestation service (trust-graph node).
    pub service: String,
    /// The service's signature over the statement.
    pub signature: SignatureSlot,
    /// Present iff [`ClaimClass::high_stakes`].
    pub quorum: Option<QuorumAttestation>,
}

impl SovereignAttestation {
    /// Issue: the service signs the statement; high-stakes claims
    /// additionally assemble the M-of-K quorum over the same bytes.
    pub fn issue(
        statement: AttestationStatement,
        service: &str,
        key: &KeyPair,
        quorum: Option<(&crate::graph::NodeId, usize, &[&KeyPair])>,
    ) -> Result<SovereignAttestation, SignatifError> {
        let payload = statement.canonical_bytes();
        // CN-3: the service's own signature rides its OWN domain —
        // the quorum co-signature (below) rides Quorum. A statement
        // signed in one domain does not verify in the other.
        let signature = SignatureSlot::sign(key, SigningDomain::SovereignAttestation, &payload)?;
        let quorum_att = match (statement.claim.high_stakes(), quorum) {
            (true, Some((quorum_id, threshold, member_keys))) => {
                let att =
                    QuorumAttestation::mint_sign(quorum_id, threshold, &payload, member_keys)?;
                Some(att)
            }
            (true, None) => {
                return Err(SignatifError::invalid(
                    "high-stakes claims require the sovereign service's quorum co-signature"
                        .to_string(),
                ))
            }
            (false, _) => None,
        };
        Ok(SovereignAttestation {
            statement,
            service: service.to_string(),
            signature,
            quorum: quorum_att,
        })
    }

    /// Verify under the VERIFIER's own trust graph: the service's
    /// key resolves to the declared node; the quorum co-signature
    /// (when the claim is high-stakes) reaches its threshold. Returns
    /// the coverage grade the verifier may claim.
    pub fn verify(&self, graph: &TrustGraph) -> Result<CoverageGrade, SignatifError> {
        let service = NodeId::new(&self.service)
            .map_err(|e| SignatifError::crypto(format!("attestation service: {e}")))?;
        let public = graph
            .node(&service)
            .and_then(|node| node.key(&self.signature.key_id))
            .ok_or_else(|| {
                SignatifError::crypto(format!(
                    "attestation service `{}` has no such key",
                    self.service
                ))
            })?;
        self.signature.verify(
            SigningDomain::SovereignAttestation,
            &self.statement.canonical_bytes(),
            public,
        )?;
        if self.statement.claim.high_stakes() {
            let att = self.quorum.as_ref().ok_or_else(|| {
                SignatifError::crypto(format!(
                    "claim `{}` is high-stakes: the quorum co-signature is required",
                    self.statement.claim.token()
                ))
            })?;
            let quorate = att
                .is_quorate(&self.statement.canonical_bytes(), &graph.key_directory())
                .map_err(|e| SignatifError::crypto(format!("attestation quorum check: {e}")))?;
            if !quorate {
                return Err(SignatifError::crypto(format!(
                    "high-stakes claim `{}`: the quorum co-signature does not reach its threshold",
                    self.statement.claim.token()
                )));
            }
        }
        Ok(CoverageGrade::AttestedByAuthority)
    }

    /// Bind to the governing policy: the attestation must name the
    /// policy the segment actually pins (XB-3's naming).
    pub fn binds_policy(&self, policy: &PolicyObject) -> bool {
        self.statement.governing_policy == policy.policy_id
            && self.statement.governing_policy_version == policy.version
    }
}

/// The evidence tier a data point carries in a coverage-graded
/// verdict (XB-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageGrade {
    /// The verifier saw the evidence itself.
    VerifiedDirect,
    /// A named authority attests; the verifier accepts under its own anchors.
    AttestedByAuthority,
    /// The class is sealed and no admissible attestation exists.
    ExplicitlyUnavailable,
}

impl CoverageGrade {
    /// Stable wire token.
    pub fn token(self) -> &'static str {
        match self {
            CoverageGrade::VerifiedDirect => "verified-direct",
            CoverageGrade::AttestedByAuthority => "attested-by-authority",
            CoverageGrade::ExplicitlyUnavailable => "explicitly-unavailable",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::NodeId as N;
    use crate::graph::{DelegationNode, NodeKind, RegisteredKey, TrustGraph};
    use crate::keyring::KeyId;
    use crate::sign::Suite;

    fn graph_with(nodes: &[(&str, &KeyPair)]) -> TrustGraph {
        let mut graph = TrustGraph::new();
        for (id, key) in nodes {
            let mut node = DelegationNode::new(N::new(id).unwrap(), NodeKind::Delegated);
            node.register(RegisteredKey {
                key_id: KeyId::of(key.public()),
                public: *key.public(),
            });
            graph.add_node(node);
        }
        graph
    }

    fn statement(claim: ClaimClass) -> AttestationStatement {
        AttestationStatement {
            segment: "cn-dynamic".into(),
            state_commitment: [7u8; 32],
            claim,
            value: "pass".into(),
            as_of: "2030-06-01T08:00:00Z".into(),
            governing_policy: "cn-dynamic-bms".into(),
            governing_policy_version: 1,
            subject: "urn:unidpp:passport:pack-0001".into(),
        }
    }

    #[test]
    fn sealed_substitution_verifies_under_the_verifiers_own_anchors() {
        let service = KeyPair::seeded(Suite::Ed25519, b"cn-attestation-service").unwrap();
        let members = [
            KeyPair::seeded(Suite::Ed25519, b"cn-a").unwrap(),
            KeyPair::seeded(Suite::Ed25519, b"cn-b").unwrap(),
        ];
        let graph = graph_with(&[
            ("cn-attestation-service", &service),
            ("cn-a", &members[0]),
            ("cn-b", &members[1]),
        ]);
        let quorum_id = N::new("cn-attestation-quorum").unwrap();
        let attestation = SovereignAttestation::issue(
            statement(ClaimClass::Conformity),
            "cn-attestation-service",
            &service,
            Some((&quorum_id, 2, &[&members[0], &members[1]])),
        )
        .unwrap();
        let grade = attestation.verify(&graph).unwrap();
        assert_eq!(grade, CoverageGrade::AttestedByAuthority);

        // The statement carries no facts: only the commitment.
        let json = serde_json::to_string(&attestation.statement).unwrap();
        assert!(
            !json.contains("voltage") && !json.contains("cycle_count"),
            "{json}"
        );
    }

    #[test]
    fn high_stakes_without_quorum_refused_low_stakes_dont_need_it() {
        let service = KeyPair::seeded(Suite::Ed25519, b"cn-attestation-service").unwrap();
        let graph = graph_with(&[("cn-attestation-service", &service)]);

        // High-stakes without a quorum: refused at ISSUE time.
        let err = SovereignAttestation::issue(
            statement(ClaimClass::Conformity),
            "cn-attestation-service",
            &service,
            None,
        );
        assert!(err.is_err());

        // Low-stakes: fine, verifies to the same grade.
        let attestation = SovereignAttestation::issue(
            statement(ClaimClass::Freshness),
            "cn-attestation-service",
            &service,
            None,
        )
        .unwrap();
        assert_eq!(
            attestation.verify(&graph).unwrap(),
            CoverageGrade::AttestedByAuthority
        );
        assert!(attestation.quorum.is_none());
    }

    // CN-3's signature-side pin: the same statement bytes signed in
    // the QUORUM domain (the old confusion) do not verify as a
    // sovereign attestation — domains are disjoint, and the
    // co-signature does not substitute for the service's own.
    #[test]
    fn cross_domain_signature_substitution_fails() {
        let service = KeyPair::seeded(Suite::Ed25519, b"cn-attestation-service").unwrap();
        let graph = graph_with(&[("cn-attestation-service", &service)]);
        let mut attestation = SovereignAttestation::issue(
            statement(ClaimClass::Freshness),
            "cn-attestation-service",
            &service,
            None,
        )
        .unwrap();
        assert!(attestation.verify(&graph).is_ok());
        // Re-sign the same bytes in the Quorum domain: refused.
        attestation.signature = SignatureSlot::sign(
            &service,
            crate::sign::SigningDomain::Quorum,
            &attestation.statement.canonical_bytes(),
        )
        .unwrap();
        assert!(attestation.verify(&graph).is_err());
    }

    #[test]
    fn wrong_service_and_tampered_statements_fail() {
        let service = KeyPair::seeded(Suite::Ed25519, b"cn-attestation-service").unwrap();
        let impostor = KeyPair::seeded(Suite::Ed25519, b"impostor").unwrap();
        let graph = graph_with(&[("cn-attestation-service", &service)]);

        let foreign = SovereignAttestation::issue(
            statement(ClaimClass::Freshness),
            "cn-attestation-service",
            &impostor,
            None,
        )
        .unwrap();
        assert!(foreign.verify(&graph).is_err());

        let mut tampered = SovereignAttestation::issue(
            statement(ClaimClass::Freshness),
            "cn-attestation-service",
            &service,
            None,
        )
        .unwrap();
        tampered.statement.value = "fail".into(); // verdict swap under the signature
        assert!(tampered.verify(&graph).is_err());
    }
}
