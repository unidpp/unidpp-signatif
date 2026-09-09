//! The grid seam: signing and verifying segment policy objects and
//! commitment spines (ARCHITECTURE §1; SG-2/SG-3).
//!
//! The pure model lives in `unidpp-grid` (canonical bytes, Merkle
//! arithmetic, supersession); this layer supplies what only SIGNATIF
//! can — real signatures over those bytes and key resolution through
//! the trust graph. A policy is signed by its **authority**; a spine
//! root by its **custodian**. Verification is graded, never boolean.

use crate::graph::{NodeId, TrustGraph};
use crate::keyring::KeyPair;
use crate::sign::{SignatureSlot, SigningDomain};
use crate::SignatifError;

pub use unidpp_grid::{PolicyObject, PolicyVerdict, Spine};

/// A policy object plus its authority's signature slot.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SignedPolicy {
    /// The policy content (its canonical bytes are what is signed).
    pub policy: PolicyObject,
    /// The authority's signature in the SegmentPolicy domain.
    pub signature: SignatureSlot,
}

impl SignedPolicy {
    /// The authority signs the policy's canonical bytes in the
    /// SegmentPolicy domain.
    pub fn issue(policy: PolicyObject, key: &KeyPair) -> Result<SignedPolicy, SignatifError> {
        let signature =
            SignatureSlot::sign(key, SigningDomain::SegmentPolicy, &policy.canonical_bytes())?;
        Ok(SignedPolicy { policy, signature })
    }

    /// Verify against a key directory: the signature must check under
    /// a key registered to the policy's DECLARED authority node — any
    /// other signer, however valid cryptographically, does not
    /// constitute this policy. The freshness verdict is returned
    /// alongside (graded: stale policies verify but say so).
    pub fn verify(&self, graph: &TrustGraph) -> Result<PolicyCheck, SignatifError> {
        let authority = NodeId::new(&self.policy.authority)
            .map_err(|e| SignatifError::crypto(format!("policy authority: {e}")))?;
        // The key must be REGISTERED TO the declared authority — a
        // perfectly valid signature from any other node's key does
        // not constitute this policy (TR-2's intake discipline at the
        // grid seam).
        let public = graph
            .node(&authority)
            .and_then(|node| node.key(&self.signature.key_id))
            .ok_or_else(|| {
                SignatifError::crypto(format!(
                    "policy `{}` references authority `{}` with no such key",
                    self.policy.policy_id, self.policy.authority
                ))
            })?;
        self.signature.verify(
            SigningDomain::SegmentPolicy,
            &self.policy.canonical_bytes(),
            public,
        )?;
        Ok(PolicyCheck {
            signer: authority,
            signature_ok: true,
            fresh: PolicyVerdict::Current,
        })
    }

    /// Verify + freshness against the LIVE policy (the caller holds
    /// the current object; usually `self`): SG-2's stale detection as
    /// part of verification.
    pub fn verify_with_freshness(&self, graph: &TrustGraph) -> Result<PolicyCheck, SignatifError> {
        let mut check = self.verify(graph)?;
        check.fresh = {
            let referenced = unidpp_grid::PolicyRef {
                policy_id: self.policy.policy_id.clone(),
                version: self.policy.version,
            };
            self.policy.status_for(&referenced)
        };
        Ok(check)
    }
}

/// A signed spine: the custodian binds the root (what a transparency
/// log would anchor and a verifier would pin).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SignedSpine {
    /// The spine (its digest is what is signed).
    pub spine: Spine,
    /// The custodian's node id.
    pub custodian: String,
    /// The custodian's signature in the SpineRoot domain.
    pub signature: SignatureSlot,
}

impl SignedSpine {
    /// The custodian signs the spine's digest in the SpineRoot domain.
    pub fn issue(
        spine: Spine,
        custodian: &str,
        key: &KeyPair,
    ) -> Result<SignedSpine, SignatifError> {
        let signature =
            SignatureSlot::sign(key, SigningDomain::SpineRoot, spine.digest().as_ref())?;
        Ok(SignedSpine {
            spine,
            custodian: custodian.to_string(),
            signature,
        })
    }

    /// Verify under the custodian's registered key.
    pub fn verify(&self, graph: &TrustGraph) -> Result<(), SignatifError> {
        let custodian = NodeId::new(&self.custodian)
            .map_err(|e| SignatifError::crypto(format!("spine custodian: {e}")))?;
        let public = graph
            .node(&custodian)
            .and_then(|node| node.key(&self.signature.key_id))
            .ok_or_else(|| {
                SignatifError::crypto(format!(
                    "spine custodian `{}` has no such key",
                    self.custodian
                ))
            })?;
        self.signature.verify(
            SigningDomain::SpineRoot,
            self.spine.digest().as_ref(),
            public,
        )
    }
}

/// The graded policy check outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyCheck {
    /// The authority the signature resolved to.
    pub signer: NodeId,
    /// The cryptographic check passed.
    pub signature_ok: bool,
    /// The freshness reading (stale policies verify but say so).
    pub fresh: PolicyVerdict,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{DelegationNode, NodeKind, RegisteredKey, TrustGraph};
    use crate::keyring::KeyId;
    use crate::sign::Suite;

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

    fn policy() -> PolicyObject {
        PolicyObject {
            policy_id: "cn-dynamic-bms".into(),
            version: 1,
            authority: "cn-samr".into(),
            readers: vec!["cn-customs".into()],
            verifiers: vec!["cn-customs".into()],
            writers: vec!["bms-oem".into()],
            reveal: unidpp_grid::RevealClass::OriginSealed,
            suites: vec!["sm2".into()],
            valid_from: "2027-01-01T00:00:00Z".into(),
            valid_to: None,
            superseded_by: None,
        }
    }

    #[test]
    fn policies_verify_under_their_authority_only() {
        let authority = KeyPair::seeded(Suite::Ed25519, b"cn-samr-authority").unwrap();
        let impostor = KeyPair::seeded(Suite::Ed25519, b"impostor").unwrap();
        let graph = graph_with("cn-samr", &authority);

        let signed = SignedPolicy::issue(policy(), &authority).unwrap();
        let check = signed.verify(&graph).unwrap();
        assert!(check.signature_ok);
        assert_eq!(check.signer.as_str(), "cn-samr");

        // A cryptographically perfect signature from the WRONG key is
        // not this policy: the impostor's key is not registered to
        // the declared authority.
        let forged = SignedPolicy::issue(policy(), &impostor).unwrap();
        assert!(forged.verify(&graph).is_err());

        // A tampered policy under the real signature fails.
        let mut tampered = signed.clone();
        tampered.policy.reveal = unidpp_grid::RevealClass::Open;
        assert!(tampered.verify(&graph).is_err());
    }

    #[test]
    fn freshness_rides_verification() {
        let authority = KeyPair::seeded(Suite::Ed25519, b"cn-samr-authority").unwrap();
        let graph = graph_with("cn-samr", &authority);
        let mut superseded = policy();
        superseded.superseded_by = Some(2);
        let signed = SignedPolicy::issue(superseded, &authority).unwrap();
        let check = signed.verify_with_freshness(&graph).unwrap();
        assert_eq!(
            check.fresh,
            PolicyVerdict::Stale {
                have: 1,
                current: 2
            }
        );
    }

    #[test]
    fn spines_verify_under_their_custodian() {
        let custodian = KeyPair::seeded(Suite::Ed25519, b"custodian").unwrap();
        let other = KeyPair::seeded(Suite::Ed25519, b"other").unwrap();
        let graph = graph_with("weilian-shenzhen", &custodian);
        let mut commitments = std::collections::BTreeMap::new();
        commitments.insert("cn-dynamic".to_string(), [7u8; 32]);
        let spine = Spine::over(1, commitments);

        let signed = SignedSpine::issue(spine, "weilian-shenzhen", &custodian).unwrap();
        signed.verify(&graph).unwrap();
        let wrong = SignedSpine::issue(signed.spine.clone(), "weilian-shenzhen", &other).unwrap();
        assert!(wrong.verify(&graph).is_err());
    }
}
