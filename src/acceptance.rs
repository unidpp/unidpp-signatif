//! Acceptance policies (XB-4): the RECEIVING profile's rules for
//! what evidence it will count.
//!
//! Substitution is not automatic. Whether a sovereign attestation is
//! EVIDENCE is the verifier's profile's call: which attestation
//! services it anchors, which claim classes it accepts, the quorum
//! strength it demands, the freshness it requires, and — per element
//! — the truth mode it tolerates. The grade an attestation earns is
//! the MINIMUM of what it proves and what the profile accepts: the
//! same evidence under two profiles yields two different, both
//! correct, verdicts.

use std::collections::BTreeMap;

use crate::sovereign::{ClaimClass, CoverageGrade, SovereignAttestation};
use unidpp_model::time::Timestamp;

/// What the receiving profile will accept for one element (data
/// class).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TruthMode {
    /// Only opened evidence counts; attestations are refused — the
    /// element reads explicitly-unavailable under substitution.
    RequireDirect,
    /// Attestations from accepted services are admissible evidence.
    AcceptAttestation,
    /// Attestations admissible AND explicit unavailability a
    /// tolerable final grade (informational elements).
    TolerateUnavailable,
}

impl TruthMode {
    /// Stable wire token.
    pub fn token(self) -> &'static str {
        match self {
            TruthMode::RequireDirect => "require-direct",
            TruthMode::AcceptAttestation => "accept-attestation",
            TruthMode::TolerateUnavailable => "tolerate-unavailable",
        }
    }

    fn admits_attestation(self) -> bool {
        matches!(
            self,
            TruthMode::AcceptAttestation | TruthMode::TolerateUnavailable
        )
    }
}

/// The receiving profile's acceptance policy (XB-4).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AcceptancePolicy {
    /// The profile this acceptance belongs to (the receiving
    /// verifier's profile context).
    pub profile: String,
    /// Attestation services anchored by this profile (node ids). An
    /// attestation from any other service — however valid — grades
    /// explicitly-unavailable here.
    pub attestation_services: Vec<String>,
    /// Claim classes accepted as substitution evidence.
    pub accepted_claims: Vec<ClaimClass>,
    /// The minimum quorum threshold demanded for high-stakes claims
    /// (a service's 2-of-3 does not satisfy a profile demanding 3).
    pub minimum_quorum: usize,
    /// Maximum tolerated attestation age, in seconds (None: no
    /// freshness constraint).
    pub max_age_secs: Option<i64>,
    /// Per-element truth modes; elements not listed default to
    /// accept-attestation (substitution is the designed behavior for
    /// sealed classes — profiles opt elements OUT, not in).
    pub element_modes: BTreeMap<String, TruthMode>,
}

impl AcceptancePolicy {
    /// The mode declared for an element (or the default).
    pub fn mode_for(&self, element: &str) -> TruthMode {
        self.element_modes
            .get(element)
            .copied()
            .unwrap_or(TruthMode::AcceptAttestation)
    }

    /// Grade an attestation as evidence for `element`, evaluated at
    /// `now` (RFC 3339): the minimum of what the attestation proves
    /// and what this profile accepts. Every refusal is
    /// explicitly-unavailable — stated, never silent.
    pub fn grade(
        &self,
        attestation: &SovereignAttestation,
        element: &str,
        now: &str,
    ) -> CoverageGrade {
        if !self.mode_for(element).admits_attestation() {
            return CoverageGrade::ExplicitlyUnavailable;
        }
        if !self
            .attestation_services
            .iter()
            .any(|s| s == &attestation.service)
        {
            return CoverageGrade::ExplicitlyUnavailable;
        }
        if !self.accepted_claims.contains(&attestation.statement.claim) {
            return CoverageGrade::ExplicitlyUnavailable;
        }
        if attestation.statement.claim.high_stakes() {
            let threshold = attestation
                .quorum
                .as_ref()
                .map(|q| q.threshold)
                .unwrap_or(0);
            if threshold < self.minimum_quorum {
                return CoverageGrade::ExplicitlyUnavailable;
            }
        }
        if let Some(max_age) = self.max_age_secs {
            let age = match (
                Timestamp::parse(now),
                Timestamp::parse(&attestation.statement.as_of),
            ) {
                (Ok(n), Ok(a)) => n.signed_secs_since(a),
                _ => return CoverageGrade::ExplicitlyUnavailable,
            };
            if age < 0 || age > max_age {
                return CoverageGrade::ExplicitlyUnavailable;
            }
        }
        CoverageGrade::AttestedByAuthority
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::NodeId;
    use crate::keyring::KeyPair;
    use crate::sign::Suite;
    use crate::sovereign::{AttestationStatement, ClaimClass as CC};

    fn attestation() -> SovereignAttestation {
        let service = KeyPair::seeded(Suite::Ed25519, b"cn-attestation-service").unwrap();
        let a = KeyPair::seeded(Suite::Ed25519, b"cn-a").unwrap();
        let b = KeyPair::seeded(Suite::Ed25519, b"cn-b").unwrap();
        let statement = AttestationStatement {
            segment: "cn-dynamic".into(),
            state_commitment: [0x42; 32],
            claim: CC::Conformity,
            value: "pass".into(),
            as_of: "2030-06-01T08:00:00Z".into(),
            governing_policy: "cn-dynamic-bms".into(),
            governing_policy_version: 1,
            subject: "urn:unidpp:passport:pack-0001".into(),
        };
        let quorum = NodeId::new("cn-attestation-quorum").unwrap();
        SovereignAttestation::issue(
            statement,
            "cn-attestation-service",
            &service,
            Some((&quorum, 2, &[&a, &b])),
        )
        .unwrap()
    }

    // XB-4's verify: the same evidence, two profiles, two different
    // — both correct — verdicts.
    #[test]
    fn same_evidence_two_profiles_two_verdicts() {
        let attestation = attestation();
        let now = "2030-06-01T08:30:00Z";

        let accepting = AcceptancePolicy {
            profile: "urn:unidpp:profile:eu-battery".into(),
            attestation_services: vec!["cn-attestation-service".into()],
            accepted_claims: vec![CC::Conformity, CC::Freshness],
            minimum_quorum: 2,
            max_age_secs: Some(3600),
            element_modes: BTreeMap::new(),
        };
        let strict = AcceptancePolicy {
            profile: "urn:unidpp:profile:eu-battery-strict".into(),
            attestation_services: vec![], // anchors no CN service
            accepted_claims: vec![],
            minimum_quorum: 3,
            max_age_secs: None,
            element_modes: BTreeMap::new(),
        };

        assert_eq!(
            accepting.grade(&attestation, "cycle-count", now),
            CoverageGrade::AttestedByAuthority
        );
        assert_eq!(
            strict.grade(&attestation, "cycle-count", now),
            CoverageGrade::ExplicitlyUnavailable,
            "an unanchored service is not evidence, however valid"
        );
    }

    // Per-element truth mode: a require-direct element refuses the
    // same attestation a sibling element accepts.
    #[test]
    fn per_element_truth_mode_gates_the_same_evidence() {
        let attestation = attestation();
        let policy = AcceptancePolicy {
            profile: "p".into(),
            attestation_services: vec!["cn-attestation-service".into()],
            accepted_claims: vec![CC::Conformity],
            minimum_quorum: 2,
            max_age_secs: None,
            element_modes: BTreeMap::from([(
                "origin-and-vintage".to_string(),
                TruthMode::RequireDirect,
            )]),
        };
        let now = "2030-06-01T08:00:00Z";
        assert_eq!(
            policy.grade(&attestation, "cycle-count", now),
            CoverageGrade::AttestedByAuthority
        );
        assert_eq!(
            policy.grade(&attestation, "origin-and-vintage", now),
            CoverageGrade::ExplicitlyUnavailable
        );
    }

    // Each acceptance dimension refuses on its own: claim class,
    // quorum strength, freshness.
    #[test]
    fn claim_quorum_and_freshness_each_refuse_alone() {
        let attestation = attestation();
        let now = "2030-06-01T08:30:00Z";

        let wrong_claim = AcceptancePolicy {
            accepted_claims: vec![CC::Freshness], // conformity not accepted
            ..base()
        };
        assert_eq!(
            wrong_claim.grade(&attestation, "cycle-count", now),
            CoverageGrade::ExplicitlyUnavailable
        );

        let weak_quorum = AcceptancePolicy {
            minimum_quorum: 3, // the attestation carries 2-of-3
            ..base()
        };
        assert_eq!(
            weak_quorum.grade(&attestation, "cycle-count", now),
            CoverageGrade::ExplicitlyUnavailable
        );

        let stale = AcceptancePolicy {
            max_age_secs: Some(60), // 30 minutes old
            ..base()
        };
        assert_eq!(
            stale.grade(&attestation, "cycle-count", now),
            CoverageGrade::ExplicitlyUnavailable
        );

        assert_eq!(
            base().grade(&attestation, "cycle-count", now),
            CoverageGrade::AttestedByAuthority
        );
    }

    fn base() -> AcceptancePolicy {
        AcceptancePolicy {
            profile: "p".into(),
            attestation_services: vec!["cn-attestation-service".into()],
            accepted_claims: vec![CC::Conformity],
            minimum_quorum: 2,
            max_age_secs: None,
            element_modes: BTreeMap::new(),
        }
    }
}
