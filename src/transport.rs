//! Transport modes (SI-2): connected protocol (S13), document
//! exchange, and hub relay — chosen per pair, willingness enforced.
//!
//! Willingness is a precondition, never a variable a transport mode
//! can compensate for: every delivery consults the publisher's
//! interop declaration (SI-8) before anything moves, and a refusal
//! or a missing permission surfaces as a stated coverage gap or an
//! escalation — never bypassed, never silent. Within that boundary
//! the three modes carry the same evidence; a hub is a stateless
//! signed relay between WILING pairs divided by protocols (the CAN
//! gap, never the WILL gap — the full hub CONTRACT is Phase 3's
//! SI-3; this module carries the mechanics).
//!
//! MECE with the rest of the seam: declaration.rs owns the posture
//! (what is offered), s13.rs owns the protocol envelopes (request/
//! response), dossier.rs and frozen.rs own the document forms, and
//! this module owns the DELIVERY: the gate, the relay, and the gap.

use crate::declaration::{DeclarationSet, TransportMode};
use crate::graph::{NodeId, TrustGraph};
use crate::keyring::KeyPair;
use crate::sign::{SignatureSlot, SigningDomain};
use crate::SignatifError;
use unidpp_model::{sha256, CanonicalWriter};

/// What a delivery attempt concluded.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum DeliveryOutcome {
    /// Delivered: the evidence reached the verifier; the digest names
    /// exactly the bytes that crossed.
    Delivered {
        /// sha256 of the delivered evidence bytes.
        evidence_digest: [u8; 32],
        /// The mode that carried it.
        mode: TransportMode,
    },
    /// The publisher's declaration refuses this transport for this
    /// class toward this counterpart — a STATED coverage gap; the
    /// verifier's report renders explicitly-unavailable, never a
    /// silent pass (the reason names the refusing posture).
    Gap {
        /// Why the posture refuses (from the declaration
        /// consultation, or the absence itself).
        reason: String,
    },
}

/// The willingness gate at exchange time: consult the declarer's
/// declaration for (counterpart, class) and deliver or state the
/// gap. Pure — the same inputs always yield the same outcome.
pub fn deliver(
    declarations: &DeclarationSet,
    declarer: &str,
    counterpart: &str,
    data_class: &str,
    mode: TransportMode,
    evidence: &[u8],
) -> DeliveryOutcome {
    match declarations.permits(declarer, counterpart, data_class, mode) {
        crate::declaration::Permission::Permitted { .. } => DeliveryOutcome::Delivered {
            evidence_digest: sha256(&[evidence]).0,
            mode,
        },
        crate::declaration::Permission::Refused { reason } => DeliveryOutcome::Gap { reason },
        crate::declaration::Permission::NoDeclaration => DeliveryOutcome::Gap {
            reason: format!(
                "`{}` publishes no interop declaration covering class `{}` toward `{}` — \
                 absence of willingness is stated, never assumed",
                declarer, data_class, counterpart
            ),
        },
    }
}

/// A translation hub: a stateless signed relay between willing pairs
/// divided by protocols. It carries no storage — relaying is a pure
/// function of the declarations and the bytes; after a relay the hub
/// holds nothing (enforced structurally: there is nowhere to put
/// anything).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Hub {
    /// The hub's trust-graph node id.
    pub hub_id: String,
}

impl Hub {
    /// Relay evidence from `from` to `to` for `data_class`.
    ///
    /// The hub checks BOTH sides' declarations before relaying: a
    /// scheme that declines interop is never brokered around (the
    /// WILL gap is not the hub's to bridge). On success the hub
    /// signs the forwarded bytes plus the relay metadata — what was
    /// forwarded, from whom, to whom, under which class — and
    /// returns the relayed evidence; nothing is retained.
    pub fn relay(
        &self,
        evidence: &[u8],
        from: &str,
        to: &str,
        data_class: &str,
        declarations: &DeclarationSet,
        key: &KeyPair,
    ) -> Result<RelayedEvidence, SignatifError> {
        for (declarer, counterpart) in [(from, to), (to, from)] {
            match declarations.permits(declarer, counterpart, data_class, TransportMode::Hub) {
                crate::declaration::Permission::Permitted { .. } => {}
                crate::declaration::Permission::Refused { reason } => {
                    return Err(SignatifError::crypto(format!(
                        "hub `{}` refuses the relay: {reason}",
                        self.hub_id
                    )))
                }
                crate::declaration::Permission::NoDeclaration => {
                    return Err(SignatifError::crypto(format!(
                        "hub `{}` refuses the relay: `{}` publishes no interop \
                         declaration covering class `{}` toward `{}`",
                        self.hub_id, declarer, data_class, counterpart
                    )))
                }
            }
        }
        let signature = SignatureSlot::sign(
            key,
            SigningDomain::HubRelay,
            &Self::relay_payload(&self.hub_id, evidence, from, to, data_class),
        )?;
        Ok(RelayedEvidence {
            hub_id: self.hub_id.clone(),
            from: from.into(),
            to: to.into(),
            data_class: data_class.into(),
            evidence_digest: sha256(&[evidence]).0,
            signature,
        })
    }
}

impl Hub {
    /// What the hub signs: its identity, the forwarded bytes'
    /// digest, the endpoints, and the class — a faithful-relay
    /// attestation over exactly what crossed.
    fn relay_payload(
        hub_id: &str,
        evidence: &[u8],
        from: &str,
        to: &str,
        data_class: &str,
    ) -> Vec<u8> {
        let mut w = CanonicalWriter::new();
        w.write_bytes(hub_id.as_bytes());
        w.write_bytes(&sha256(&[evidence]).0);
        w.write_bytes(from.as_bytes());
        w.write_bytes(to.as_bytes());
        w.write_bytes(data_class.as_bytes());
        w.into_bytes()
    }
}

/// The relayed evidence: the hub's signed statement of what it
/// forwarded (the bytes themselves travel beside it — the relay
/// attests, it does not custody).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RelayedEvidence {
    /// The relaying hub.
    pub hub_id: String,
    /// The sender (declaring scheme).
    pub from: String,
    /// The recipient.
    pub to: String,
    /// The data class relayed.
    pub data_class: String,
    /// sha256 of the forwarded bytes.
    pub evidence_digest: [u8; 32],
    /// The hub's signature in the HUB-RELAY domain.
    pub signature: SignatureSlot,
}

impl RelayedEvidence {
    /// Verify under the graph: the signature resolves to the DECLARED
    /// hub's key, and the attested digest matches the bytes that
    /// arrived beside it.
    pub fn verify(&self, evidence: &[u8], graph: &TrustGraph) -> Result<(), SignatifError> {
        let node = NodeId::new(&self.hub_id)
            .map_err(|e| SignatifError::crypto(format!("hub relay: {e}")))?;
        let public = graph
            .node(&node)
            .and_then(|n| n.key(&self.signature.key_id))
            .ok_or_else(|| {
                SignatifError::crypto(format!("hub `{}` has no such key", self.hub_id))
            })?;
        let payload = Hub::relay_payload(
            &self.hub_id,
            evidence,
            &self.from,
            &self.to,
            &self.data_class,
        );
        self.signature
            .verify(SigningDomain::HubRelay, &payload, public)?;
        if self.evidence_digest != sha256(&[evidence]).0 {
            return Err(SignatifError::crypto(
                "hub relay: the attested digest does not match the arrived bytes".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::declaration::{
        ClassPosture, HarmonizationLevel, InteropDeclaration, RecognitionMode,
    };
    use crate::graph::{DelegationNode, NodeKind, RegisteredKey};
    use crate::keyring::KeyId;
    use crate::sign::Suite;

    fn graph_with(nodes: &[(&str, &KeyPair)]) -> TrustGraph {
        let mut graph = TrustGraph::new();
        for (id, key) in nodes {
            let mut node = DelegationNode::new(NodeId::new(id).unwrap(), NodeKind::Delegated);
            node.register(RegisteredKey {
                key_id: KeyId::of(key.public()),
                public: *key.public(),
            });
            graph.add_node(node);
        }
        graph
    }

    fn declaring(declarer: &str, counterpart: &str, key: &KeyPair) -> InteropDeclaration {
        InteropDeclaration::issue(
            declarer,
            counterpart,
            1,
            vec![ClassPosture {
                data_class: "cn-dynamic".into(),
                level: HarmonizationLevel::L3,
                recognition: RecognitionMode::BilateralAnchors,
                transports: vec![
                    TransportMode::Protocol,
                    TransportMode::Document,
                    TransportMode::Hub,
                ],
                escalation: None,
                reciprocity: None,
            }],
            "2027-01-01T00:00:00Z",
            None,
            key,
        )
        .unwrap()
    }

    const EVIDENCE: &[u8] = b"urn:unidpp:passport:pack-0001 (the frozen view bytes)";

    // SI-2's verify: the same evidence delivered through all three
    // modes, all publisher-willing — one digest, one verdict.
    #[test]
    fn three_modes_one_verdict() {
        let custodian = KeyPair::seeded(Suite::Ed25519, b"t/weilian").unwrap();
        let hub_key = KeyPair::seeded(Suite::Ed25519, b"t/hub").unwrap();
        let mut set = DeclarationSet::new();
        set.register(declaring("weilian-shenzhen", "de-zoll", &custodian));
        set.register(declaring("de-zoll", "weilian-shenzhen", &custodian));

        let mut digests = Vec::new();
        for mode in [
            TransportMode::Protocol,
            TransportMode::Document,
            TransportMode::Hub,
        ] {
            match deliver(
                &set,
                "weilian-shenzhen",
                "de-zoll",
                "cn-dynamic",
                mode,
                EVIDENCE,
            ) {
                DeliveryOutcome::Delivered {
                    evidence_digest,
                    mode: m,
                } => {
                    assert_eq!(m, mode);
                    digests.push(evidence_digest);
                }
                DeliveryOutcome::Gap { reason } => panic!("unexpected gap: {reason}"),
            }
        }
        digests.dedup();
        assert_eq!(
            digests.len(),
            1,
            "the three modes carry one evidence digest"
        );

        // The hub relay carries the same bytes and verifies.
        let graph = graph_with(&[("hub-1", &hub_key)]);
        let hub = Hub {
            hub_id: "hub-1".into(),
        };
        let relayed = hub
            .relay(
                EVIDENCE,
                "weilian-shenzhen",
                "de-zoll",
                "cn-dynamic",
                &set,
                &hub_key,
            )
            .unwrap();
        assert_eq!(relayed.evidence_digest, digests[0]);
        relayed.verify(EVIDENCE, &graph).unwrap();
    }

    // The refusal case: a posture that does not offer hub transport
    // yields a STATED gap at delivery, and the hub refuses the relay
    // (never brokered around).
    #[test]
    fn refusal_surfaces_as_a_stated_gap() {
        let custodian = KeyPair::seeded(Suite::Ed25519, b"t/weilian").unwrap();
        let mut set = DeclarationSet::new();
        let mut declaration = declaring("weilian-shenzhen", "de-zoll", &custodian);
        declaration.postures[0]
            .transports
            .retain(|t| *t != TransportMode::Hub);
        set.register(declaration);

        match deliver(
            &set,
            "weilian-shenzhen",
            "de-zoll",
            "cn-dynamic",
            TransportMode::Hub,
            EVIDENCE,
        ) {
            DeliveryOutcome::Gap { reason } => {
                assert!(reason.contains("not `hub`"), "{reason}")
            }
            other => panic!("expected a stated gap, got {other:?}"),
        }

        // The hub refuses on the same consultation.
        let hub_key = KeyPair::seeded(Suite::Ed25519, b"t/hub").unwrap();
        let hub = Hub {
            hub_id: "hub-1".into(),
        };
        let err = hub.relay(
            EVIDENCE,
            "weilian-shenzhen",
            "de-zoll",
            "cn-dynamic",
            &set,
            &hub_key,
        );
        assert!(err.is_err());

        // Absence of a declaration is equally stated at delivery.
        match deliver(
            &set,
            "weilian-shenzhen",
            "random-party",
            "cn-dynamic",
            TransportMode::Document,
            EVIDENCE,
        ) {
            DeliveryOutcome::Gap { reason } => {
                assert!(reason.contains("no interop declaration"), "{reason}")
            }
            other => panic!("expected a stated gap, got {other:?}"),
        }
    }

    // A hub with no declaration on the RECIPIENT side refuses too:
    // both ends must be willing.
    #[test]
    fn the_hub_checks_both_sides() {
        let custodian = KeyPair::seeded(Suite::Ed25519, b"t/weilian").unwrap();
        let hub_key = KeyPair::seeded(Suite::Ed25519, b"t/hub").unwrap();
        let mut set = DeclarationSet::new();
        // Only the custodian declares; the verifier does not.
        set.register(declaring("weilian-shenzhen", "de-zoll", &custodian));
        let hub = Hub {
            hub_id: "hub-1".into(),
        };
        let err = hub.relay(
            EVIDENCE,
            "weilian-shenzhen",
            "de-zoll",
            "cn-dynamic",
            &set,
            &hub_key,
        );
        let message = err.unwrap_err().to_string();
        assert!(
            message.contains("no interop declaration") && message.contains("de-zoll"),
            "{message}"
        );
    }

    // Tampering with the relayed bytes fails verification (the hub
    // attested a different digest); so does a forged hub signature.
    #[test]
    fn relays_are_tamper_evident() {
        let custodian = KeyPair::seeded(Suite::Ed25519, b"t/weilian").unwrap();
        let hub_key = KeyPair::seeded(Suite::Ed25519, b"t/hub").unwrap();
        let impostor = KeyPair::seeded(Suite::Ed25519, b"t/impostor").unwrap();
        let graph = graph_with(&[("hub-1", &hub_key)]);
        let mut set = DeclarationSet::new();
        set.register(declaring("weilian-shenzhen", "de-zoll", &custodian));
        set.register(declaring("de-zoll", "weilian-shenzhen", &custodian));
        let hub = Hub {
            hub_id: "hub-1".into(),
        };

        let relayed = hub
            .relay(
                EVIDENCE,
                "weilian-shenzhen",
                "de-zoll",
                "cn-dynamic",
                &set,
                &hub_key,
            )
            .unwrap();
        // Different bytes beside the attestation: fails.
        assert!(relayed.verify(b"different bytes", &graph).is_err());
        // An impostor signing as the hub: fails.
        let forged = hub
            .relay(
                EVIDENCE,
                "weilian-shenzhen",
                "de-zoll",
                "cn-dynamic",
                &set,
                &impostor,
            )
            .unwrap();
        assert!(forged.verify(EVIDENCE, &graph).is_err());
        // The genuine relay verifies.
        relayed.verify(EVIDENCE, &graph).unwrap();
    }
}
