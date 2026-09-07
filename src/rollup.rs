//! Roll-up attestation signing — the cryptographic half of
//! `unidpp-transform::rollup`.
//!
//! The transform crate owns the data model: the traversal set's Merkle
//! root, the aggregates, and the canonical body a signature covers.
//! This module supplies the real signing and slot verification, the
//! same way every other artifact is signed here: a domain-separated
//! [`SignatureSlot`] over the canonical body, installed into the
//! attestation's core slot.

use unidpp_model::SigSlot;
use unidpp_transform::rollup::RollupAttestation;

use crate::keyring::{KeyPair, PublicKey};
use crate::sign::{SignatureSlot, SigningDomain};
use crate::SignatifError;

/// Sign an attestation's canonical body with `key` and install the
/// resulting slot. The key's suite must map onto the core carrier
/// table (the attestation carries a core [`SigSlot`]).
pub fn sign_rollup(
    key: &KeyPair,
    attestation: &mut RollupAttestation,
) -> Result<(), SignatifError> {
    let slot = SignatureSlot::sign(
        key,
        SigningDomain::RollupAttestation,
        &attestation.canonical_body(),
    )?;
    let slot: SigSlot = slot.to_sig_slot().ok_or_else(|| {
        SignatifError::crypto(format!("suite {} has no core carrier slot", key.suite()))
    })?;
    attestation.install_signature(slot);
    Ok(())
}

/// The signature predicate for
/// [`unidpp_transform::rollup::verify_rollup`]: real verification of
/// the attestation's slot against a pinned anchor. Returns the
/// check's failure reason verbatim (the verdict reports it).
pub fn check_rollup_signature(
    slot: &SigSlot,
    body: &[u8],
    anchor: &PublicKey,
) -> Result<(), String> {
    let slot = SignatureSlot::from_sig_slot(slot).map_err(|e| e.to_string())?;
    slot.verify(SigningDomain::RollupAttestation, body, anchor)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Suite;
    use unidpp_model::sha256;
    use unidpp_transform::quantity::{Quantity, UnitRegistry};
    use unidpp_transform::rollup::{verify_rollup, RollupVerdict, TraversalMember, TraversalSet};

    fn set() -> TraversalSet {
        let mut quantities = std::collections::BTreeMap::new();
        quantities.insert(
            "recycled-content-mass".to_string(),
            Quantity::parse("120", "g", &UnitRegistry::iso80000()).unwrap(),
        );
        TraversalSet::new(vec![TraversalMember {
            passport: unidpp_model::PassportId::new("urn:unidpp:passport:cell-a").unwrap(),
            version: 1,
            state_hash: sha256(&[b"cell-a"]),
            quantities,
        }])
        .unwrap()
    }

    #[test]
    fn signed_rollup_round_trips_and_tampering_breaks_it() {
        let mut attestation = RollupAttestation::build(
            unidpp_model::PassportId::new("urn:unidpp:passport:pack").unwrap(),
            &set(),
            "urn:unidpp:transform:recycled-content-sum",
            "urn:unidpp:passport:recycler",
            &UnitRegistry::iso80000(),
        )
        .unwrap()
        .0;
        let key = KeyPair::seeded(Suite::EcdsaP256, b"rollup-attester").unwrap();
        sign_rollup(&key, &mut attestation).unwrap();
        assert!(attestation.signature.signature.is_some());

        // Verified against the pinned anchor.
        let registry = UnitRegistry::iso80000();
        let verdict = verify_rollup(&attestation, &set(), &registry, |slot, body| {
            check_rollup_signature(slot, body, key.public())
        });
        assert_eq!(verdict, RollupVerdict::Verified);

        // A different anchor: the slot is rejected, reported by reason.
        let stranger = KeyPair::seeded(Suite::EcdsaP256, b"stranger").unwrap();
        let verdict = verify_rollup(&attestation, &set(), &registry, |slot, body| {
            check_rollup_signature(slot, body, stranger.public())
        });
        assert!(matches!(verdict, RollupVerdict::SignatureRejected(_)));

        // A tampered body no longer matches the installed signature.
        let mut tampered = attestation.clone();
        tampered.method_ref = "urn:unidpp:transform:someone-elses-method".to_string();
        let verdict = verify_rollup(&tampered, &set(), &registry, |slot, body| {
            check_rollup_signature(slot, body, key.public())
        });
        assert!(matches!(verdict, RollupVerdict::SignatureRejected(_)));
    }
}
