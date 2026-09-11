//! Certified hierarchies (TR-4): CNML-style tiered chains and
//! DCC-style calibration evidence, scope checked at every link at
//! USE time.
//!
//! A CNML chain runs root → issuing authority → test lab →
//! manufacturer model → instance: each link is a scoped delegation
//! (the scope machinery of `scope.rs` — authority, profile-version,
//! product-group, window layers plus executable conditions). The
//! chain is INGESTED as typed objects and CHECKED at use time: an
//! act performed by the instance is admitted only when EVERY link's
//! scope admits it, and the refusing link is named. Ingestion-time
//! validity is not sufficient — a lab certifying outside its
//! accredited scope is rejected when the evidence is verified, not
//! when the chain is filed.

use crate::graph::{NodeId, TrustGraph};
use crate::keyring::KeyPair;
use crate::scope::{DelegationScope, ScopeRequest};
use crate::sign::{SignatureSlot, SigningDomain};
use crate::SignatifError;
use unidpp_model::{sha256, CanonicalWriter};

/// The five CNML tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HierarchyTier {
    /// The root of the certification hierarchy.
    Root,
    /// The issuing authority (accredits labs, admits models).
    IssuingAuthority,
    /// The test laboratory (performs measurements, issues DCCs).
    TestLab,
    /// The manufacturer's model (type-level certification).
    ManufacturerModel,
    /// The physical instance.
    Instance,
}

impl HierarchyTier {
    /// The stable token.
    pub fn token(self) -> &'static str {
        match self {
            HierarchyTier::Root => "root",
            HierarchyTier::IssuingAuthority => "issuing-authority",
            HierarchyTier::TestLab => "test-lab",
            HierarchyTier::ManufacturerModel => "manufacturer-model",
            HierarchyTier::Instance => "instance",
        }
    }
}

/// One link of the chain: a scoped delegation from a parent tier's
/// node to a child tier's node.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ChainLink {
    /// The parent tier.
    pub from: HierarchyTier,
    /// The child tier.
    pub to: HierarchyTier,
    /// The child node.
    pub child: String,
    /// The scope the parent delegates (checked at USE time).
    pub scope: DelegationScope,
    /// The parent's signature over the link (the delegation
    /// credential).
    pub signature: SignatureSlot,
}

impl ChainLink {
    /// What the parent signs: both tiers, the child, and the
    /// scope's four layers (canonical, CN-1).
    fn payload(
        from: HierarchyTier,
        to: HierarchyTier,
        child: &str,
        scope: &DelegationScope,
    ) -> Vec<u8> {
        let mut w = CanonicalWriter::new();
        w.write_bytes(from.token().as_bytes());
        w.write_bytes(to.token().as_bytes());
        w.write_bytes(child.as_bytes());
        w.write_bytes(&scope.canonical_bytes());
        w.into_bytes()
    }

    /// Issue a link (the parent's key signs).
    pub fn issue(
        from: HierarchyTier,
        to: HierarchyTier,
        child: &str,
        scope: DelegationScope,
        parent_key: &KeyPair,
    ) -> Result<ChainLink, SignatifError> {
        let payload = Self::payload(from, to, child, &scope);
        let signature = SignatureSlot::sign(parent_key, SigningDomain::Delegation, &payload)?;
        Ok(ChainLink {
            from,
            to,
            child: child.into(),
            scope,
            signature,
        })
    }

    /// Verify the link's credential under the graph (the parent
    /// node is resolved by the chain's carrier).
    pub fn verify_signed_by(&self, parent: &str, graph: &TrustGraph) -> Result<(), SignatifError> {
        let node =
            NodeId::new(parent).map_err(|e| SignatifError::crypto(format!("chain parent: {e}")))?;
        let public = graph
            .node(&node)
            .and_then(|n| n.key(&self.signature.key_id))
            .ok_or_else(|| {
                SignatifError::crypto(format!("chain parent `{parent}` has no such key"))
            })?;
        let payload = Self::payload(self.from, self.to, &self.child, &self.scope);
        self.signature
            .verify(SigningDomain::Delegation, &payload, public)
    }
}

/// A DCC-style calibration certificate: measurement evidence issued
/// by a test laboratory in the chain.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CalibrationCertificate {
    /// The device under test (the instance or model node).
    pub device_under_test: String,
    /// The measurand (what was measured).
    pub measurand: String,
    /// The measured result.
    pub result: String,
    /// The GUM uncertainty of the result.
    pub uncertainty: String,
    /// The unit (registry-registered).
    pub unit: String,
    /// The calibration interval (RFC 3339 from).
    pub valid_from: String,
    /// The calibration interval end (absent: open).
    pub valid_to: Option<String>,
    /// The issuing laboratory (chain node).
    pub laboratory: String,
    /// The laboratory's signature in the CALIBRATION domain.
    pub signature: SignatureSlot,
}

impl CalibrationCertificate {
    /// The canonical, signable form (CN-1).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut w = CanonicalWriter::new();
        w.write_bytes(self.device_under_test.as_bytes());
        w.write_bytes(self.measurand.as_bytes());
        w.write_bytes(self.result.as_bytes());
        w.write_bytes(self.uncertainty.as_bytes());
        w.write_bytes(self.unit.as_bytes());
        w.write_bytes(self.valid_from.as_bytes());
        w.write_bytes(self.valid_to.as_deref().unwrap_or("").as_bytes());
        w.write_bytes(self.laboratory.as_bytes());
        w.into_bytes()
    }

    /// The certificate's digest.
    pub fn digest(&self) -> [u8; 32] {
        sha256(&[&self.canonical_bytes()]).0
    }

    /// Issue (the laboratory's key signs).
    #[allow(clippy::too_many_arguments)] // the DCC's fields are the evidence
    pub fn issue(
        device_under_test: &str,
        measurand: &str,
        result: &str,
        uncertainty: &str,
        unit: &str,
        valid_from: &str,
        valid_to: Option<&str>,
        laboratory: &str,
        lab_key: &KeyPair,
    ) -> Result<CalibrationCertificate, SignatifError> {
        let mut w = CanonicalWriter::new();
        w.write_bytes(device_under_test.as_bytes());
        w.write_bytes(measurand.as_bytes());
        w.write_bytes(result.as_bytes());
        w.write_bytes(uncertainty.as_bytes());
        w.write_bytes(unit.as_bytes());
        w.write_bytes(valid_from.as_bytes());
        w.write_bytes(valid_to.unwrap_or("").as_bytes());
        w.write_bytes(laboratory.as_bytes());
        let payload = w.into_bytes();
        let signature = SignatureSlot::sign(lab_key, SigningDomain::Calibration, &payload)?;
        Ok(CalibrationCertificate {
            device_under_test: device_under_test.into(),
            measurand: measurand.into(),
            result: result.into(),
            uncertainty: uncertainty.into(),
            unit: unit.into(),
            valid_from: valid_from.into(),
            valid_to: valid_to.map(Into::into),
            laboratory: laboratory.into(),
            signature,
        })
    }

    /// Verify the laboratory's signature under the graph.
    pub fn verify(&self, graph: &TrustGraph) -> Result<(), SignatifError> {
        let node = NodeId::new(&self.laboratory)
            .map_err(|e| SignatifError::crypto(format!("calibration laboratory: {e}")))?;
        let public = graph
            .node(&node)
            .and_then(|n| n.key(&self.signature.key_id))
            .ok_or_else(|| {
                SignatifError::crypto(format!(
                    "calibration laboratory `{}` has no such key",
                    self.laboratory
                ))
            })?;
        self.signature
            .verify(SigningDomain::Calibration, &self.canonical_bytes(), public)
    }
}

/// An ingested certified chain: its links, ordered root → instance.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CertifiedChain {
    /// The chain's nodes by tier (root → instance order).
    pub nodes: Vec<(HierarchyTier, String)>,
    /// The links between them.
    pub links: Vec<ChainLink>,
}

impl CertifiedChain {
    /// The use-time check (TR-4's verify clause): does the chain
    /// admit `act` — EVERY link's scope must admit it, and every
    /// link's credential must verify. The refusing link is named.
    pub fn admits(&self, act: &ScopeRequest, graph: &TrustGraph) -> Result<(), SignatifError> {
        for (i, link) in self.links.iter().enumerate() {
            let parent = self.nodes[i].1.clone();
            link.verify_signed_by(&parent, graph)?;
            if !link.scope.matches(act) {
                return Err(SignatifError::ScopeViolation(format!(
                    "certified chain: link {} (`{}` → `{}`) does not admit the act — \
                     out-of-scope delegation rejected at use time",
                    i + 1,
                    link.from.token(),
                    link.to.token()
                )));
            }
            link.scope.check_conditions(act).map_err(|c| {
                SignatifError::ScopeViolation(format!(
                    "certified chain: link {} fails its condition `{}` at use time",
                    i + 1,
                    c.label()
                ))
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{DelegationNode, NodeKind, RegisteredKey};
    use crate::keyring::KeyId;
    use crate::sign::Suite;
    use unidpp_model::time::Timestamp;

    fn cast() -> (TrustGraph, KeyPair, KeyPair, KeyPair, KeyPair) {
        let root = KeyPair::seeded(Suite::Ed25519, b"cnml/root").unwrap();
        let authority = KeyPair::seeded(Suite::Ed25519, b"cnml/cnas").unwrap();
        let lab = KeyPair::seeded(Suite::Ed25519, b"cnml/lab").unwrap();
        let maker = KeyPair::seeded(Suite::Ed25519, b"cnml/maker").unwrap();
        let mut graph = TrustGraph::new();
        for (id, key) in [
            ("cnml-root", &root),
            ("cnml-issuing", &authority),
            ("cnml-bms-lab", &lab),
            ("weilian-model", &maker),
        ] {
            let mut node = DelegationNode::new(NodeId::new(id).unwrap(), NodeKind::Delegated);
            node.register(RegisteredKey {
                key_id: KeyId::of(key.public()),
                public: *key.public(),
            });
            graph.add_node(node);
        }
        (graph, root, authority, lab, maker)
    }

    fn chain(cast: &(TrustGraph, KeyPair, KeyPair, KeyPair, KeyPair)) -> CertifiedChain {
        let (_, root, authority, lab, maker) = cast;
        // The lab is scoped to the battery group only.
        let lab_scope = DelegationScope::unconstrained()
            .product_group(["battery-bms"])
            .within(unidpp_model::time::Interval {
                from: Timestamp::parse("2027-01-01T00:00:00Z").unwrap(),
                to: Some(Timestamp::parse("2031-12-31T23:59:59Z").unwrap()),
            });
        let links = vec![
            ChainLink::issue(
                HierarchyTier::Root,
                HierarchyTier::IssuingAuthority,
                "cnml-issuing",
                DelegationScope::unconstrained(),
                root,
            )
            .unwrap(),
            ChainLink::issue(
                HierarchyTier::IssuingAuthority,
                HierarchyTier::TestLab,
                "cnml-bms-lab",
                lab_scope.clone(),
                authority,
            )
            .unwrap(),
            ChainLink::issue(
                HierarchyTier::TestLab,
                HierarchyTier::ManufacturerModel,
                "weilian-model",
                lab_scope,
                lab,
            )
            .unwrap(),
            ChainLink::issue(
                HierarchyTier::ManufacturerModel,
                HierarchyTier::Instance,
                "pack-0001",
                DelegationScope::unconstrained(),
                maker,
            )
            .unwrap(),
        ];
        CertifiedChain {
            nodes: vec![
                (HierarchyTier::Root, "cnml-root".into()),
                (HierarchyTier::IssuingAuthority, "cnml-issuing".into()),
                (HierarchyTier::TestLab, "cnml-bms-lab".into()),
                (HierarchyTier::ManufacturerModel, "weilian-model".into()),
                (HierarchyTier::Instance, "pack-0001".into()),
            ],
            links,
        }
    }

    fn act(product_group: &str) -> ScopeRequest {
        ScopeRequest::new(
            "cnml-bms-lab",
            "bms-conformity@1",
            product_group,
            Timestamp::parse("2030-06-01T00:00:00Z").unwrap(),
        )
    }

    // TR-4's verify: a full chain verifies in scope; an out-of-scope
    // act is rejected AT USE TIME with the refusing link named.
    #[test]
    fn full_chains_verify_and_out_of_scope_acts_are_rejected_at_use() {
        let c = cast();
        let (graph, _, _, lab, _) = &c;
        let certified = chain(&c);

        // In scope: every link admits the battery act.
        certified.admits(&act("battery-bms"), graph).unwrap();

        // Out of scope: the lab link refuses, named.
        let err = certified
            .admits(&act("medical-devices"), graph)
            .unwrap_err()
            .to_string();
        assert!(err.contains("link 2"), "{err}");
        assert!(err.contains("issuing-authority"), "{err}");
        assert!(err.contains("test-lab"), "{err}");

        // DCC-style calibration evidence verifies under the chain's
        // lab; a forged certificate fails.
        let dcc = CalibrationCertificate::issue(
            "pack-0001",
            "capacity",
            "52.0",
            "0.1",
            "Ah",
            "2030-06-01T00:00:00Z",
            Some("2031-06-01T00:00:00Z"),
            "cnml-bms-lab",
            lab,
        )
        .unwrap();
        dcc.verify(graph).unwrap();
        let impostor = KeyPair::seeded(Suite::Ed25519, b"cnml/impostor").unwrap();
        let forged = CalibrationCertificate::issue(
            "pack-0001",
            "capacity",
            "99.9",
            "0.1",
            "Ah",
            "2030-06-01T00:00:00Z",
            None,
            "cnml-bms-lab",
            &impostor,
        )
        .unwrap();
        assert!(forged.verify(graph).is_err());
    }

    // A broken link credential fails the whole chain at use time —
    // ingestion validity is not sufficient.
    #[test]
    fn broken_credentials_fail_at_use_time() {
        let c = cast();
        let lab = &c.3;
        let mut certified = chain(&c);
        // Re-sign the first link with the WRONG key (the lab's).
        let bad = ChainLink::issue(
            HierarchyTier::Root,
            HierarchyTier::IssuingAuthority,
            "cnml-issuing",
            DelegationScope::unconstrained(),
            lab,
        )
        .unwrap();
        certified.links[0] = bad;
        assert!(certified.admits(&act("battery-bms"), &c.0).is_err());
    }
}
