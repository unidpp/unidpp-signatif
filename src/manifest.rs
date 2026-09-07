//! The deployment manifest (CC/SIGNATIF §18): the serializable
//! declaration of a deployment's **active algorithms**, **migration
//! phase**, **topology profile**, and **scope extensions**, with a
//! validation function.
//!
//! The manifest is the algorithm-agility substrate of §20: deprecation
//! and migration are *scheduled* here (a suite moves
//! `active → deprecated → retired` across manifest versions), while
//! the registry service (`unidpp-registry`) hosts the operational
//! state. A [`DeploymentManifest`] travels alongside the deployment's
//! [`crate::graph::AnchorBundle`] so a verifier can check that the
//! algorithms an artifact was signed under were active when the
//! artifact was verified.
//!
//! All fields are data — the manifest constrains and reports, it never
//! performs computation.

use std::collections::{BTreeMap, BTreeSet};

use unidpp_model::Timestamp;

use crate::scope::LayerConstraint;
use crate::sign::Suite;
use crate::SignatifError;

/// The post-quantum migration phase a deployment is in
/// (CC/SIGNATIF §9 `algorithms-migration`, §20
/// `algorithm-agility-migration`). Serializes as its stable token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationPhase {
    /// Classical algorithms only (the starting state).
    Classical,
    /// Hybrid via **co-signature collection**: classical and
    /// post-quantum suites sign the same payload as independent slots
    /// (acceptance policy-scoped).
    HybridCoSigned,
    /// Hybrid via **composite signatures**: classical and
    /// post-quantum suites are AND-composed into single composite
    /// signatures ([`crate::sign::CompositeSignature`]).
    HybridComposite,
    /// Post-quantum only (classical suites retired).
    PostQuantum,
}

impl MigrationPhase {
    /// Stable phase token.
    pub fn token(&self) -> &'static str {
        match self {
            MigrationPhase::Classical => "classical",
            MigrationPhase::HybridCoSigned => "hybrid-co-signed",
            MigrationPhase::HybridComposite => "hybrid-composite",
            MigrationPhase::PostQuantum => "post-quantum",
        }
    }

    /// Parse a phase token (case-insensitive).
    pub fn parse_token(s: &str) -> Result<MigrationPhase, SignatifError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "classical" => Ok(MigrationPhase::Classical),
            "hybrid-co-signed" => Ok(MigrationPhase::HybridCoSigned),
            "hybrid-composite" => Ok(MigrationPhase::HybridComposite),
            "post-quantum" => Ok(MigrationPhase::PostQuantum),
            _ => Err(SignatifError::invalid(format!(
                "unknown migration phase `{s}`"
            ))),
        }
    }

    /// Whether this phase requires a classical+post-quantum mix of
    /// active algorithms.
    pub fn requires_hybrid_mix(self) -> bool {
        matches!(
            self,
            MigrationPhase::HybridCoSigned | MigrationPhase::HybridComposite
        )
    }
}

impl serde::Serialize for MigrationPhase {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.token())
    }
}

impl<'de> serde::Deserialize<'de> for MigrationPhase {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        MigrationPhase::parse_token(&s).map_err(serde::de::Error::custom)
    }
}

/// The trust-topology profile a deployment instantiates (CC/SIGNATIF
/// §19 `governance-profiles`): the four enumerated shapes. Serializes
/// as its stable token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopologyProfile {
    /// Single root (or root tree) delegating downward.
    Hierarchical,
    /// Threshold/federated groups of independent authorities at the
    /// root ([`crate::graph::NodeKind::ThresholdGroup`]).
    Federated,
    /// Independent roots whose certificates cross-recognize each
    /// other's delegations.
    CrossRecognized,
    /// Many pairwise-recognized roots with no common apex.
    Mesh,
}

impl TopologyProfile {
    /// Stable profile token.
    pub fn token(&self) -> &'static str {
        match self {
            TopologyProfile::Hierarchical => "hierarchical",
            TopologyProfile::Federated => "federated",
            TopologyProfile::CrossRecognized => "cross-recognized",
            TopologyProfile::Mesh => "mesh",
        }
    }

    /// Parse a profile token (case-insensitive).
    pub fn parse_token(s: &str) -> Result<TopologyProfile, SignatifError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "hierarchical" => Ok(TopologyProfile::Hierarchical),
            "federated" => Ok(TopologyProfile::Federated),
            "cross-recognized" => Ok(TopologyProfile::CrossRecognized),
            "mesh" => Ok(TopologyProfile::Mesh),
            _ => Err(SignatifError::invalid(format!(
                "unknown topology profile `{s}`"
            ))),
        }
    }
}

impl serde::Serialize for TopologyProfile {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.token())
    }
}

impl<'de> serde::Deserialize<'de> for TopologyProfile {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        TopologyProfile::parse_token(&s).map_err(serde::de::Error::custom)
    }
}

/// A suite's standing under a manifest (the §20 agility status).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AlgorithmStatus {
    /// Active: signatures under this suite are accepted.
    Active,
    /// Deprecated: still accepted, scheduled for retirement.
    Deprecated,
    /// Not listed by this manifest (treated as retired/foreign by the
    /// deployment's policy).
    NotListed,
}

/// A deployment manifest: active algorithms, migration phase,
/// topology profile, and scope extensions (CC/SIGNATIF §18).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeploymentManifest {
    /// Manifest version identifier (monotone per deployment; the
    /// standard's bundle-versioning companion).
    pub version: String,
    /// The deploying jurisdiction/operator identifier.
    pub operator: String,
    /// Algorithm suites accepted for *new* signatures.
    pub active_algorithms: BTreeSet<Suite>,
    /// Algorithm suites accepted for verification but scheduled for
    /// retirement (the §20 deprecation window).
    #[serde(default)]
    pub deprecated_algorithms: BTreeSet<Suite>,
    /// The migration phase this deployment is in.
    pub migration_phase: MigrationPhase,
    /// The trust-topology profile this deployment instantiates.
    pub topology_profile: TopologyProfile,
    /// Profile-defined scope dimensions beyond the standard's set
    /// (CC/SIGNATIF §3.5: "additional dimensions may be defined by
    /// profiles") — dimension name → constraint.
    #[serde(default)]
    pub scope_extensions: BTreeMap<String, LayerConstraint>,
    /// When this manifest takes effect.
    pub effective_from: Timestamp,
}

impl DeploymentManifest {
    /// The status of a suite under this manifest.
    pub fn algorithm_status(&self, suite: Suite) -> AlgorithmStatus {
        if self.active_algorithms.contains(&suite) {
            AlgorithmStatus::Active
        } else if self.deprecated_algorithms.contains(&suite) {
            AlgorithmStatus::Deprecated
        } else {
            AlgorithmStatus::NotListed
        }
    }

    /// Whether a suite may still be *verified* under this manifest
    /// (active or deprecated — deprecated is a retirement window, not
    /// a hard cut).
    pub fn accepts_verification(&self, suite: Suite) -> bool {
        !matches!(self.algorithm_status(suite), AlgorithmStatus::NotListed)
    }

    /// Validate the manifest (CC/SIGNATIF §18 + the §20 agility
    /// coherence rules):
    ///
    /// 1. `version` and `operator` are non-empty;
    /// 2. at least one active algorithm;
    /// 3. no suite is simultaneously active and deprecated;
    /// 4. hybrid phases require ≥ 2 active algorithms mixing at least
    ///    one classical and one post-quantum suite;
    /// 5. the post-quantum phase has only post-quantum active
    ///    algorithms (classical is retired there);
    /// 6. scope-extension names are non-empty and their constraints
    ///    are not contradictions.
    pub fn validate(&self) -> Result<(), SignatifError> {
        if self.version.trim().is_empty() {
            return Err(SignatifError::invalid("manifest version is empty"));
        }
        if self.operator.trim().is_empty() {
            return Err(SignatifError::invalid("manifest operator is empty"));
        }
        if self.active_algorithms.is_empty() {
            return Err(SignatifError::invalid(
                "manifest declares no active algorithms",
            ));
        }
        let overlap: Vec<Suite> = self
            .active_algorithms
            .intersection(&self.deprecated_algorithms)
            .copied()
            .collect();
        if !overlap.is_empty() {
            return Err(SignatifError::invalid(format!(
                "suites both active and deprecated: {}",
                overlap
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        let classical = self.active_algorithms.iter().any(|s| !s.is_post_quantum());
        let post_quantum = self.active_algorithms.iter().any(|s| s.is_post_quantum());
        if self.migration_phase.requires_hybrid_mix()
            && (self.active_algorithms.len() < 2 || !classical || !post_quantum)
        {
            return Err(SignatifError::invalid(format!(
                "migration phase `{}` requires a mixed active set (≥1 classical and ≥1 \
                 post-quantum algorithm)",
                self.migration_phase.token()
            )));
        }
        if self.migration_phase == MigrationPhase::PostQuantum && classical {
            return Err(SignatifError::invalid(format!(
                "migration phase `{}` must not list classical active algorithms",
                self.migration_phase.token()
            )));
        }
        for (name, constraint) in &self.scope_extensions {
            if name.trim().is_empty() {
                return Err(SignatifError::invalid(
                    "scope extension with an empty dimension name",
                ));
            }
            if constraint.is_contradiction() {
                return Err(SignatifError::invalid(format!(
                    "scope extension `{name}` is a contradiction (empty allowed set)"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs: i64) -> Timestamp {
        Timestamp::from_secs(secs)
    }

    fn classical_only() -> BTreeSet<Suite> {
        [Suite::Ed25519, Suite::EcdsaP256].into()
    }

    fn hybrid() -> BTreeSet<Suite> {
        [Suite::Ed25519, Suite::MlDsa65].into()
    }

    fn manifest(active: BTreeSet<Suite>, phase: MigrationPhase) -> DeploymentManifest {
        DeploymentManifest {
            version: "eu-2026-09".into(),
            operator: "EU-DPP-Registry".into(),
            active_algorithms: active,
            deprecated_algorithms: BTreeSet::new(),
            migration_phase: phase,
            topology_profile: TopologyProfile::Federated,
            scope_extensions: BTreeMap::new(),
            effective_from: t(1_000_000),
        }
    }

    #[test]
    fn valid_manifests_pass_validation() {
        // Classical starting state.
        let m = manifest(classical_only(), MigrationPhase::Classical);
        assert!(m.validate().is_ok());
        // Hybrid co-signed: classical + PQ mix.
        assert!(manifest(hybrid(), MigrationPhase::HybridCoSigned)
            .validate()
            .is_ok());
        // Hybrid composite (the AND-composition form).
        assert!(manifest(hybrid(), MigrationPhase::HybridComposite)
            .validate()
            .is_ok());
        // Post-quantum end state.
        assert!(manifest(
            [Suite::MlDsa65, Suite::SlhDsa128s].into(),
            MigrationPhase::PostQuantum
        )
        .validate()
        .is_ok());
        // All four topology profiles are carried as data.
        for profile in [
            TopologyProfile::Hierarchical,
            TopologyProfile::Federated,
            TopologyProfile::CrossRecognized,
            TopologyProfile::Mesh,
        ] {
            assert!(profile.token().len() > 2);
        }
    }

    #[test]
    fn validation_catches_each_rule_violation() {
        // Empty version.
        let mut m = manifest(classical_only(), MigrationPhase::Classical);
        m.version = "  ".into();
        assert!(m.validate().is_err());
        // No active algorithms.
        let m = manifest(BTreeSet::new(), MigrationPhase::Classical);
        assert!(m.validate().is_err());
        // Suite both active and deprecated.
        let mut m = manifest(classical_only(), MigrationPhase::Classical);
        m.deprecated_algorithms = [Suite::Ed25519].into();
        let err = m.validate().unwrap_err();
        assert!(err.to_string().contains("ed25519"), "{err}");
        // Hybrid phase without a PQ algorithm.
        let err = manifest(classical_only(), MigrationPhase::HybridCoSigned)
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("hybrid"), "{err}");
        // Hybrid phase without a classical algorithm.
        let err = manifest([Suite::MlDsa65].into(), MigrationPhase::HybridComposite)
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("mixed"), "{err}");
        // Post-quantum phase with a classical algorithm still active.
        let err = manifest(hybrid(), MigrationPhase::PostQuantum)
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("classical"), "{err}");
        // Contradictory scope extension.
        let mut m = manifest(classical_only(), MigrationPhase::Classical);
        m.scope_extensions
            .insert("market".into(), LayerConstraint::Only(BTreeSet::new()));
        assert!(m.validate().is_err());
        // Empty extension name.
        let mut m = manifest(classical_only(), MigrationPhase::Classical);
        m.scope_extensions.insert(" ".into(), LayerConstraint::Any);
        assert!(m.validate().is_err());
    }

    #[test]
    fn algorithm_status_and_deprecation_window() {
        let mut m = manifest(classical_only(), MigrationPhase::Classical);
        m.deprecated_algorithms = [Suite::Sm2].into();
        assert_eq!(m.algorithm_status(Suite::Ed25519), AlgorithmStatus::Active);
        assert_eq!(m.algorithm_status(Suite::Sm2), AlgorithmStatus::Deprecated);
        assert_eq!(
            m.algorithm_status(Suite::MlDsa87),
            AlgorithmStatus::NotListed
        );
        assert_eq!(
            m.algorithm_status(Suite::SlhDsa192s),
            AlgorithmStatus::NotListed
        );
        // Deprecated is still verifiable (retirement window); unlisted
        // is not.
        assert!(m.accepts_verification(Suite::Sm2));
        assert!(!m.accepts_verification(Suite::MlDsa87));
    }

    #[test]
    fn manifest_serializes_round_trip() {
        let mut m = manifest(hybrid(), MigrationPhase::HybridComposite);
        m.scope_extensions
            .insert("market".into(), LayerConstraint::only(["eu", "us"]));
        m.validate().unwrap();
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("hybrid-composite"));
        assert!(json.contains("ml-dsa-65"));
        assert!(json.contains("federated"));
        let back: DeploymentManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.migration_phase.token(), "hybrid-composite");
        // Token parsing round-trips both enums.
        for phase in [
            MigrationPhase::Classical,
            MigrationPhase::HybridCoSigned,
            MigrationPhase::HybridComposite,
            MigrationPhase::PostQuantum,
        ] {
            assert_eq!(MigrationPhase::parse_token(phase.token()).unwrap(), phase);
        }
        for profile in [
            TopologyProfile::Hierarchical,
            TopologyProfile::Federated,
            TopologyProfile::CrossRecognized,
            TopologyProfile::Mesh,
        ] {
            assert_eq!(
                TopologyProfile::parse_token(profile.token()).unwrap(),
                profile
            );
        }
        assert!(MigrationPhase::parse_token("quantum").is_err());
        assert!(TopologyProfile::parse_token("star").is_err());
    }
}
