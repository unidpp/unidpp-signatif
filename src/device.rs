//! The device as a cryptographic principal (ID-5, RC-2's device
//! half): manufacture-time certificates, per-segment operational
//! slot keys, and edge commitments — commit now, reveal later.
//!
//! The device signs. At manufacture, the maker's certificate binds
//! the device's identity key to the static segment's commitment.
//! In service, the segment authority certifies per-segment
//! operational slot keys — the device signs its dynamic-state
//! commitments with the slot key, and the attestation path-finds
//! to the authority (device key → slot credential → authority).
//! Revoking one slot-key chain kills only that segment's
//! attestations.
//!
//! The edge publishes commitments over local log prefixes: commit
//! first, reveal later, and never contradict — a reveal
//! inconsistent with a prior commitment is rejected.

use crate::graph::{NodeId, TrustGraph};
use crate::keyring::KeyPair;
use crate::sign::{SignatureSlot, SigningDomain};
use crate::SignatifError;
use unidpp_model::{sha256, CanonicalWriter};

/// A new signing domain for device-side signatures.
pub const DEVICE_DOMAIN_TAG: &str = "UNIDPP-SIGNATIF/DEVICE";

/// The manufacture-time certificate: the maker binds the device's
/// identity key to the static segment's state commitment.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DeviceCertificate {
    /// The device (subject id).
    pub device: String,
    /// The device's identity public key (hex).
    pub device_key: String,
    /// The static segment this certificate covers.
    pub segment: String,
    /// The static state commitment bound at manufacture.
    pub static_commitment: [u8; 32],
    /// The manufacturer (trust-graph node).
    pub manufacturer: String,
    /// The manufacturer's signature.
    pub signature: SignatureSlot,
}

impl DeviceCertificate {
    /// What the manufacturer signs.
    fn payload(
        device: &str,
        device_key: &str,
        segment: &str,
        static_commitment: &[u8; 32],
    ) -> Vec<u8> {
        let mut w = CanonicalWriter::new();
        w.write_bytes(device.as_bytes());
        w.write_bytes(device_key.as_bytes());
        w.write_bytes(segment.as_bytes());
        w.write_bytes(static_commitment);
        w.into_bytes()
    }

    /// Issue: the manufacturer signs at manufacture time.
    pub fn issue(
        device: &str,
        device_key_hex: &str,
        segment: &str,
        static_commitment: [u8; 32],
        manufacturer: &str,
        maker_key: &KeyPair,
    ) -> Result<DeviceCertificate, SignatifError> {
        let payload = Self::payload(device, device_key_hex, segment, &static_commitment);
        let signature = SignatureSlot::sign(maker_key, SigningDomain::Delegation, &payload)?;
        Ok(DeviceCertificate {
            device: device.into(),
            device_key: device_key_hex.into(),
            segment: segment.into(),
            static_commitment,
            manufacturer: manufacturer.into(),
            signature,
        })
    }

    /// Verify under the graph (the manufacturer's key).
    pub fn verify(&self, graph: &TrustGraph) -> Result<(), SignatifError> {
        let node = NodeId::new(&self.manufacturer)
            .map_err(|e| SignatifError::crypto(format!("device manufacturer: {e}")))?;
        let public = graph
            .node(&node)
            .and_then(|n| n.key(&self.signature.key_id))
            .ok_or_else(|| {
                SignatifError::crypto(format!(
                    "manufacturer `{}` has no such key",
                    self.manufacturer
                ))
            })?;
        let payload = Self::payload(
            &self.device,
            &self.device_key,
            &self.segment,
            &self.static_commitment,
        );
        self.signature
            .verify(SigningDomain::Delegation, &payload, public)
    }
}

/// A segment authority's credential certifying a device's
/// operational slot key for ITS segment (the per-segment binding
/// whose revocation is scoped).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SlotCredential {
    /// The device holding the slot.
    pub device: String,
    /// The slot's public key (hex).
    pub slot_key: String,
    /// The segment the slot may sign for.
    pub segment: String,
    /// The certifying segment authority (trust-graph node).
    pub authority: String,
    /// Effective window start (RFC 3339).
    pub valid_from: String,
    /// Effective window end (absent: open).
    pub valid_to: Option<String>,
    /// The authority's signature.
    pub signature: SignatureSlot,
}

impl SlotCredential {
    fn payload(
        device: &str,
        slot_key: &str,
        segment: &str,
        valid_from: &str,
        valid_to: Option<&str>,
    ) -> Vec<u8> {
        let mut w = CanonicalWriter::new();
        w.write_bytes(device.as_bytes());
        w.write_bytes(slot_key.as_bytes());
        w.write_bytes(segment.as_bytes());
        w.write_bytes(valid_from.as_bytes());
        w.write_bytes(valid_to.unwrap_or("").as_bytes());
        w.into_bytes()
    }

    /// Issue: the segment authority certifies the slot key.
    pub fn issue(
        device: &str,
        slot_key_hex: &str,
        segment: &str,
        authority: &str,
        valid_from: &str,
        valid_to: Option<&str>,
        authority_key: &KeyPair,
    ) -> Result<SlotCredential, SignatifError> {
        let payload = Self::payload(device, slot_key_hex, segment, valid_from, valid_to);
        let signature = SignatureSlot::sign(authority_key, SigningDomain::Delegation, &payload)?;
        Ok(SlotCredential {
            device: device.into(),
            slot_key: slot_key_hex.into(),
            segment: segment.into(),
            authority: authority.into(),
            valid_from: valid_from.into(),
            valid_to: valid_to.map(Into::into),
            signature,
        })
    }

    /// Verify under the graph (the authority's key).
    pub fn verify(&self, graph: &TrustGraph) -> Result<(), SignatifError> {
        let node = NodeId::new(&self.authority)
            .map_err(|e| SignatifError::crypto(format!("slot authority: {e}")))?;
        let public = graph
            .node(&node)
            .and_then(|n| n.key(&self.signature.key_id))
            .ok_or_else(|| {
                SignatifError::crypto(format!(
                    "slot authority `{}` has no such key",
                    self.authority
                ))
            })?;
        let payload = Self::payload(
            &self.device,
            &self.slot_key,
            &self.segment,
            &self.valid_from,
            self.valid_to.as_deref(),
        );
        self.signature
            .verify(SigningDomain::Delegation, &payload, public)
    }
}

/// What a slot attestation concluded under a trust graph with the
/// held credentials.
#[derive(Debug, Clone, PartialEq)]
pub enum SlotStanding {
    /// Path-finds: the slot key is certified for the claimed
    /// segment by a live authority credential.
    Certified {
        /// The certifying authority.
        authority: String,
    },
    /// The credential verifies but has been revoked (the chain
    /// named) — only THIS segment's attestations die.
    Revoked {
        /// The revoked chain's segment.
        segment: String,
        /// The revoked slot key.
        slot_key: String,
    },
    /// No admissible credential — stated.
    NoChain {
        /// Why.
        reason: String,
    },
}

/// Verify a slot attestation's chain (ID-5's verify: path-finding
/// to the authority; revoking one slot-key chain kills only that
/// segment's attestations).
pub fn slot_standing(
    credentials: &[SlotCredential],
    device: &str,
    slot_key_hex: &str,
    claimed_segment: &str,
    graph: &TrustGraph,
    revoked_slot_keys: &[String],
) -> SlotStanding {
    let credential = credentials
        .iter()
        .find(|c| c.device == device && c.slot_key == slot_key_hex);
    let Some(credential) = credential else {
        return SlotStanding::NoChain {
            reason: format!("no slot credential held for `{device}`/`{slot_key_hex}`"),
        };
    };
    if let Err(e) = credential.verify(graph) {
        return SlotStanding::NoChain {
            reason: format!("the slot credential does not verify: {e}"),
        };
    }
    if credential.segment != claimed_segment {
        return SlotStanding::NoChain {
            reason: format!(
                "the slot is certified for segment `{}`, not the claimed `{claimed_segment}`",
                credential.segment
            ),
        };
    }
    if revoked_slot_keys.iter().any(|k| k == slot_key_hex) {
        return SlotStanding::Revoked {
            segment: credential.segment.clone(),
            slot_key: slot_key_hex.into(),
        };
    }
    SlotStanding::Certified {
        authority: credential.authority.clone(),
    }
}

// ---------------------------------------------------------------------------
// RC-2 (device half) — edge commitments: commit now, reveal later
// ---------------------------------------------------------------------------

/// An edge commitment over a local log prefix (RC-2): the device
/// commits to its state BEFORE revealing, and any later reveal must
/// be consistent with (contain) that commitment.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EdgeCommitment {
    /// The device.
    pub device: String,
    /// The segment the prefix belongs to.
    pub segment: String,
    /// The prefix length committed (event count).
    pub prefix_len: u64,
    /// The prefix commitment (hash over the local log prefix).
    pub prefix_commitment: [u8; 32],
}

impl EdgeCommitment {
    /// Commit over a local log prefix.
    pub fn commit(
        device: &str,
        segment: &str,
        prefix_len: u64,
        prefix_state: &[u8],
    ) -> EdgeCommitment {
        let mut w = CanonicalWriter::new();
        w.write_bytes(&prefix_len.to_le_bytes());
        w.write_bytes(prefix_state);
        EdgeCommitment {
            device: device.into(),
            segment: segment.into(),
            prefix_len,
            prefix_commitment: sha256(&[&w.into_bytes()]).0,
        }
    }
}

/// What a reveal concluded against a prior commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevealVerdict {
    /// Consistent: the revealed prefix's commitment recomputes.
    Consistent,
    /// The reveal contradicts the prior commitment — REJECTED.
    Contradicted {
        /// The reason.
        reason: String,
    },
}

/// Verify a reveal against a prior edge commitment (RC-2's verify:
/// a reveal inconsistent with a prior commitment is rejected).
pub fn verify_reveal(
    commitment: &EdgeCommitment,
    revealed_prefix_len: u64,
    revealed_state: &[u8],
) -> RevealVerdict {
    let mut w = CanonicalWriter::new();
    w.write_bytes(&revealed_prefix_len.to_le_bytes());
    w.write_bytes(revealed_state);
    let revealed = sha256(&[&w.into_bytes()]).0;
    if revealed == commitment.prefix_commitment {
        RevealVerdict::Consistent
    } else {
        RevealVerdict::Contradicted {
            reason: format!(
                "the reveal (prefix {revealed_prefix_len}) does not recompute the prior \
                 commitment over prefix {} — commit now, reveal later, never contradict",
                commitment.prefix_len
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn cast() -> (TrustGraph, KeyPair, KeyPair) {
        let maker = KeyPair::seeded(Suite::Ed25519, b"dev/maker").unwrap();
        let authority = KeyPair::seeded(Suite::Ed25519, b"dev/samr").unwrap();
        let graph = graph_with(&[("momiji", &maker), ("cn-samr", &authority)]);
        (graph, maker, authority)
    }

    fn slot_key() -> KeyPair {
        KeyPair::seeded(Suite::Ed25519, b"dev/slot-bms").unwrap()
    }

    // ID-5's verify: a segment attestation path-finds to its
    // authority; revoking one slot-key chain kills only that
    // segment's attestations.
    #[test]
    fn attestations_path_find_and_revocation_is_scoped() {
        let (graph, maker, authority) = cast();
        let slot = slot_key();

        // The manufacture-time certificate binds the device key to
        // the static segment's commitment.
        let static_commitment = [7u8; 32];
        let certificate = DeviceCertificate::issue(
            "urn:unidpp:device:pack-0001",
            &hex(slot.public().as_bytes()),
            "static",
            static_commitment,
            "momiji",
            &maker,
        )
        .unwrap();
        certificate.verify(&graph).unwrap();

        // The segment authority certifies the operational slot key
        // for ITS segment.
        let credential = SlotCredential::issue(
            "urn:unidpp:device:pack-0001",
            &hex(slot.public().as_bytes()),
            "cn-dynamic",
            "cn-samr",
            "2027-01-01T00:00:00Z",
            None,
            &authority,
        )
        .unwrap();

        // Path-finding: the attestation stands on the chain
        // (slot key → credential → authority).
        let mut credentials = vec![credential.clone()];
        match slot_standing(
            &credentials,
            "urn:unidpp:device:pack-0001",
            &hex(slot.public().as_bytes()),
            "cn-dynamic",
            &graph,
            &[],
        ) {
            SlotStanding::Certified { authority: a } => assert_eq!(a, "cn-samr"),
            other => panic!("expected certification, got {other:?}"),
        }

        // A slot claiming the WRONG segment is refused.
        match slot_standing(
            &credentials,
            "urn:unidpp:device:pack-0001",
            &hex(slot.public().as_bytes()),
            "eu-static",
            &graph,
            &[],
        ) {
            SlotStanding::NoChain { reason } => {
                assert!(reason.contains("not the claimed"), "{reason}")
            }
            other => panic!("expected refusal, got {other:?}"),
        }

        // Revoking the slot-key chain: only that segment dies — a
        // second slot (a different chain, same device) still
        // certifies its own segment.
        let other_slot = KeyPair::seeded(Suite::Ed25519, b"dev/slot-tpms").unwrap();
        let other_credential = SlotCredential::issue(
            "urn:unidpp:device:pack-0001",
            &hex(other_slot.public().as_bytes()),
            "eu-static",
            "cn-samr",
            "2027-01-01T00:00:00Z",
            None,
            &authority,
        )
        .unwrap();
        credentials.push(other_credential);
        let revoked = vec![hex(slot.public().as_bytes())];
        match slot_standing(
            &credentials,
            "urn:unidpp:device:pack-0001",
            &hex(slot.public().as_bytes()),
            "cn-dynamic",
            &graph,
            &revoked,
        ) {
            SlotStanding::Revoked { segment, slot_key } => {
                assert_eq!(segment, "cn-dynamic");
                assert_eq!(slot_key, hex(slot.public().as_bytes()));
            }
            other => panic!("expected revocation, got {other:?}"),
        }
        // The other chain is untouched.
        assert!(matches!(
            slot_standing(
                &credentials,
                "urn:unidpp:device:pack-0001",
                &hex(other_slot.public().as_bytes()),
                "eu-static",
                &graph,
                &revoked,
            ),
            SlotStanding::Certified { .. }
        ));

        // A forged credential fails the graph.
        let impostor = KeyPair::seeded(Suite::Ed25519, b"dev/impostor").unwrap();
        let forged = SlotCredential::issue(
            "urn:unidpp:device:pack-0001",
            &hex(slot.public().as_bytes()),
            "cn-dynamic",
            "cn-samr",
            "2027-01-01T00:00:00Z",
            None,
            &impostor,
        )
        .unwrap();
        match slot_standing(
            &[forged],
            "urn:unidpp:device:pack-0001",
            &hex(slot.public().as_bytes()),
            "cn-dynamic",
            &graph,
            &[],
        ) {
            SlotStanding::NoChain { reason } => {
                assert!(reason.contains("does not verify"), "{reason}")
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    // RC-2's verify: a reveal inconsistent with a prior commitment
    // is rejected — commit now, reveal later, never contradict.
    #[test]
    fn contradictory_reveals_are_rejected() {
        let commitment = EdgeCommitment::commit(
            "urn:unidpp:device:pack-0001",
            "cn-dynamic",
            42,
            b"events 0..42 canonical bytes",
        );
        // The consistent reveal: same prefix, same bytes.
        assert_eq!(
            verify_reveal(&commitment, 42, b"events 0..42 canonical bytes"),
            RevealVerdict::Consistent
        );
        // A different state at the same length contradicts.
        match verify_reveal(&commitment, 42, b"events 0..42 edited bytes") {
            RevealVerdict::Contradicted { reason } => {
                assert!(reason.contains("never contradict"), "{reason}")
            }
            other => panic!("expected contradiction, got {other:?}"),
        }
        // A different length contradicts.
        assert!(matches!(
            verify_reveal(&commitment, 41, b"events 0..42 canonical bytes"),
            RevealVerdict::Contradicted { .. }
        ));
    }
}
