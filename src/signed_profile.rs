//! Signed profiles (PR-1): the issuer signs the profile; the issuer
//! CLASS grades every judgment under it.
//!
//! The typology lives in the model (`IssuerClass`); this layer adds
//! what only SIGNATIF can — the signature and its resolution through
//! the trust graph, with the class carried on the check so callers
//! cannot grade above it.

use crate::graph::{NodeId, TrustGraph};
use crate::keyring::KeyPair;
use crate::sign::{SignatureSlot, SigningDomain};
use crate::SignatifError;
use unidpp_model::{IssuerClass, ProfileManifest, TrustGrade};

/// A profile manifest plus its issuer's signature.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SignedProfile {
    /// The profile content (its canonical JSON form is what is signed).
    pub manifest: ProfileManifest,
    /// The issuing node's id (the signer of record).
    pub issuer: String,
    /// The issuer's signature in the Profile domain.
    pub signature: SignatureSlot,
}

impl SignedProfile {
    /// The canonical signable form: serde_json's struct-order
    /// serialization (field order is fixed by the type — stable for a
    /// given build, versioned by the profile id inside it).
    fn canonical_bytes(manifest: &ProfileManifest) -> Result<Vec<u8>, SignatifError> {
        serde_json::to_vec(manifest)
            .map_err(|e| SignatifError::crypto(format!("profile serialization: {e}")))
    }

    /// The issuer signs the profile's canonical bytes.
    pub fn issue(
        manifest: ProfileManifest,
        issuer: &str,
        key: &KeyPair,
    ) -> Result<SignedProfile, SignatifError> {
        let signature = SignatureSlot::sign(
            key,
            SigningDomain::Profile,
            &Self::canonical_bytes(&manifest)?,
        )?;
        Ok(SignedProfile {
            manifest,
            issuer: issuer.to_string(),
            signature,
        })
    }

    /// Verify: the signature must check under a key registered to the
    /// declared issuer, and the class caps the grade — returned on the
    /// check so no caller can grade a Declaration above self-declared.
    pub fn verify(&self, graph: &TrustGraph) -> Result<ProfileCheck, SignatifError> {
        let issuer = NodeId::new(&self.issuer)
            .map_err(|e| SignatifError::crypto(format!("profile issuer: {e}")))?;
        let public = graph
            .node(&issuer)
            .and_then(|node| node.key(&self.signature.key_id))
            .ok_or_else(|| {
                SignatifError::crypto(format!("profile issuer `{}` has no such key", self.issuer))
            })?;
        self.signature.verify(
            SigningDomain::Profile,
            &Self::canonical_bytes(&self.manifest)?,
            public,
        )?;
        Ok(ProfileCheck {
            issuer,
            class: self.manifest.issuer_class,
            grade_ceiling: self.manifest.issuer_class.grade_ceiling(),
        })
    }
}

/// The graded profile check: who issued it, under which class, and
/// the strongest grade any judgment under it may claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileCheck {
    /// The issuer the signature resolved to.
    pub issuer: NodeId,
    /// The profile's issuer class (retained through the signature).
    pub class: IssuerClass,
    /// The strongest grade any judgment under this profile may claim.
    pub grade_ceiling: TrustGrade,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{DelegationNode, NodeKind, RegisteredKey, TrustGraph};
    use crate::keyring::KeyId;
    use crate::sign::Suite;
    use unidpp_model::{
        CapabilityClass, DataPointRef, FreshnessRequirement, Interval, ProfileAxes, ProfileId,
        Resolution, Timestamp, Traversal, TriggerPredicate, VisibilityClass,
    };

    fn graph_with(node_id: &str, key: &KeyPair) -> TrustGraph {
        let mut graph = TrustGraph::new();
        let mut node = DelegationNode::new(NodeId::new(node_id).unwrap(), NodeKind::Delegated);
        node.register(RegisteredKey {
            key_id: KeyId::of(key.public()),
            public: *key.public(),
        });
        graph.add_node(node);
        graph
    }

    fn manifest(class: IssuerClass) -> ProfileManifest {
        ProfileManifest {
            id: ProfileId::new("urn:unidpp:profile:test").unwrap(),
            issuer_class: class,
            axes: ProfileAxes::default(),
            trigger: TriggerPredicate::Any,
            min_capability: CapabilityClass::Silent,
            freshness: FreshnessRequirement::Static,
            effective: Interval::starting(Timestamp::from_secs(0)),
            data_points: vec![DataPointRef::new("untded", "1005", None).unwrap()],
            crypto_suites: vec![],
            confidential: false,
            resolution: Resolution::Public,
            edge_visibility: VisibilityClass::Public,
            traversal: Traversal::Public,
        }
    }

    #[test]
    fn every_class_round_trips_and_caps_the_grade() {
        let issuer_key = KeyPair::seeded(Suite::Ed25519, b"profile-issuer").unwrap();
        let graph = graph_with("samr", &issuer_key);
        for (class, grade) in [
            (IssuerClass::Law, TrustGrade::Regulatory),
            (IssuerClass::Treaty, TrustGrade::Regulatory),
            (IssuerClass::Consensus, TrustGrade::MarketPractice),
            (IssuerClass::Attestation, TrustGrade::ThirdParty),
            (IssuerClass::Declaration, TrustGrade::SelfDeclared),
        ] {
            let signed = SignedProfile::issue(manifest(class), "samr", &issuer_key).unwrap();
            // Class retained through the signed round trip.
            assert_eq!(signed.manifest.issuer_class, class);
            let check = signed.verify(&graph).unwrap();
            assert_eq!(check.class, class, "class retained on the check");
            // A declaration is NEVER stronger than self-declared,
            // however well signed.
            assert_eq!(check.grade_ceiling, grade);
        }
    }

    #[test]
    fn tampered_and_foreign_profiles_fail() {
        let issuer_key = KeyPair::seeded(Suite::Ed25519, b"profile-issuer").unwrap();
        let impostor = KeyPair::seeded(Suite::Ed25519, b"impostor").unwrap();
        let graph = graph_with("samr", &issuer_key);

        let signed = SignedProfile::issue(manifest(IssuerClass::Law), "samr", &issuer_key).unwrap();
        let mut tampered = signed.clone();
        tampered.manifest.issuer_class = IssuerClass::Attestation; // class swap under the signature
        assert!(tampered.verify(&graph).is_err());

        let foreign = SignedProfile::issue(manifest(IssuerClass::Law), "samr", &impostor).unwrap();
        assert!(foreign.verify(&graph).is_err());
    }
}
