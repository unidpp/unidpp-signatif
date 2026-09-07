//! The signature layer: real multi-suite signing and verification over
//! the core's canonical payloads, co-signature aggregation, and
//! policy-scoped acceptance.
//!
//! The core (`unidpp-model::trust`) frames signature slots and their
//! byte budgets; this layer computes and verifies actual signatures for
//! **Ed25519** (ed25519-dalek) and **ECDSA-P256** (deterministic RFC
//! 6979 via the `p256` crate). **SM2 and ML-DSA remain framing-only**:
//! their suites parse, frame, and budget exactly as the core specifies,
//! but computing them is deferred to binding crates (a GM-SM2
//! implementation and a FIPS 204 module) — see [`Suite::deferral`].
//!
//! Policy-scoped acceptance: a co-signature passes if **any** suite the
//! verifier's [`AcceptancePolicy`] allows verifies under a registered
//! key; a stricter policy can require `min_verified_suites` distinct
//! verified suites (the the UniDPP design framework multi-suite co-signature model: every
//! jurisdiction verifies under its own crypto policy, and a lens
//! registry is multi-suite co-signed for exactly that reason).

use std::collections::BTreeSet;
use std::fmt;

use unidpp_model::{CanonicalReader, CanonicalWriter, SigSlot};

use crate::keyring::{KeyId, KeyPair, PublicKey};
use crate::SignatifError;

/// The suites SIGNATIF knows, extending the core's carrier-framing
/// [`unidpp_model::SignatureSuite`] table.
///
/// **Deviation (documented):** the core's multi-suite table for carrier
/// framing is ECDSA-P256 / SM2 / ML-DSA-{44,65,87}; it has no Ed25519
/// slot. SIGNATIF adds Ed25519 as an *infrastructure* suite for objects
/// that do not ride the Tier-A carrier budget (delegation credentials,
/// witness attestations, signed tree heads, notary stamps): it converts
/// to a core [`SigSlot`] only where [`Suite::to_core`] maps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Suite {
    /// Ed25519 (real crypto, ed25519-dalek). SIGNATIF extension suite.
    Ed25519,
    /// ECDSA-P256, r||s (real crypto, p256/RFC 6979).
    EcdsaP256,
    /// SM2 (framing only — deferred to a GM-SM2 binding).
    Sm2,
    /// ML-DSA-44 (framing only — deferred to a FIPS 204 binding).
    MlDsa44,
    /// ML-DSA-65 (framing only — deferred to a FIPS 204 binding).
    MlDsa65,
    /// ML-DSA-87 (framing only — deferred to a FIPS 204 binding).
    MlDsa87,
}

impl Suite {
    /// All suites, canonical order (infrastructure suites first, then
    /// the core's table order).
    pub const ALL: &'static [Suite] = &[
        Suite::Ed25519,
        Suite::EcdsaP256,
        Suite::Sm2,
        Suite::MlDsa44,
        Suite::MlDsa65,
        Suite::MlDsa87,
    ];

    /// Canonical token.
    pub fn as_str(self) -> &'static str {
        match self {
            Suite::Ed25519 => "ed25519",
            Suite::EcdsaP256 => "ecdsa-p256",
            Suite::Sm2 => "sm2",
            Suite::MlDsa44 => "ml-dsa-44",
            Suite::MlDsa65 => "ml-dsa-65",
            Suite::MlDsa87 => "ml-dsa-87",
        }
    }

    /// Parse a suite token (case-insensitive).
    pub fn parse_token(s: &str) -> Result<Suite, SignatifError> {
        let squashed = s.trim().to_ascii_lowercase().replace(['-', '_'], "");
        Suite::ALL
            .iter()
            .copied()
            .find(|suite| suite.as_str().replace('-', "") == squashed)
            .ok_or_else(|| SignatifError::invalid(format!("unknown suite `{s}`")))
    }

    /// Map to the core carrier-framing suite; `None` for Ed25519 (the
    /// extension suite has no core carrier slot).
    pub fn to_core(self) -> Option<unidpp_model::SignatureSuite> {
        match self {
            Suite::EcdsaP256 => Some(unidpp_model::SignatureSuite::EcdsaP256),
            Suite::Sm2 => Some(unidpp_model::SignatureSuite::Sm2),
            Suite::MlDsa44 => Some(unidpp_model::SignatureSuite::MlDsa44),
            Suite::MlDsa65 => Some(unidpp_model::SignatureSuite::MlDsa65),
            Suite::MlDsa87 => Some(unidpp_model::SignatureSuite::MlDsa87),
            Suite::Ed25519 => None,
        }
    }

    /// Map a core carrier suite to a SIGNATIF suite (total).
    pub fn from_core(core: unidpp_model::SignatureSuite) -> Suite {
        match core {
            unidpp_model::SignatureSuite::EcdsaP256 => Suite::EcdsaP256,
            unidpp_model::SignatureSuite::Sm2 => Suite::Sm2,
            unidpp_model::SignatureSuite::MlDsa44 => Suite::MlDsa44,
            unidpp_model::SignatureSuite::MlDsa65 => Suite::MlDsa65,
            unidpp_model::SignatureSuite::MlDsa87 => Suite::MlDsa87,
        }
    }

    /// Whether this suite has real computation in this crate.
    pub fn is_computed(self) -> bool {
        matches!(self, Suite::Ed25519 | Suite::EcdsaP256)
    }

    /// Canonical signature length in bytes (mirrors the core's framing
    /// budget table; Ed25519 is 64).
    pub fn signature_len(self) -> usize {
        match self {
            Suite::Ed25519 => 64,
            other => other.to_core().map(|c| c.signature_len()).unwrap_or(64),
        }
    }

    /// One-byte suite code (`to_core` where defined; Ed25519 takes 6).
    pub fn code(self) -> u8 {
        match self {
            Suite::Ed25519 => 6,
            other => other.to_core().map(|c| c.code()).unwrap_or(6),
        }
    }

    /// The documented deferral for framing-only suites.
    pub fn deferral(self) -> Option<&'static str> {
        match self {
            Suite::Sm2 => Some(
                "SM2 computation requires a GM/T 0003 binding crate; SIGNATIF carries the \
                 core's framing (64-byte r||s slots) and refuses to fake verification",
            ),
            Suite::MlDsa44 | Suite::MlDsa65 | Suite::MlDsa87 => Some(
                "ML-DSA (FIPS 204) computation requires a PQ binding crate; SIGNATIF \
                 carries the core's framing and budget math only",
            ),
            _ => None,
        }
    }
}

impl fmt::Display for Suite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Suite {
    type Err = SignatifError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Suite::parse_token(s)
    }
}

impl serde::Serialize for Suite {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for Suite {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        Suite::parse_token(&s).map_err(serde::de::Error::custom)
    }
}

/// Domain separation for every signed SIGNATIF object. A signature over
/// domain D never verifies in domain D' — an STH cannot be replayed as a
/// delegation credential, and so on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SigningDomain {
    /// A core canonical event/payload body (the artifact layer).
    ArtifactEvent,
    /// A delegation credential in the trust graph.
    Delegation,
    /// A witness attestation in a master list.
    MasterListWitness,
    /// A signed tree head of a transparency log.
    TreeHead,
    /// A notarized historical verification stamp.
    HistoricalStamp,
    /// A quorum attestation (threshold ceremony output).
    Quorum,
}

impl SigningDomain {
    /// The domain-separation tag prepended to the payload before signing.
    pub fn tag(self) -> &'static str {
        match self {
            SigningDomain::ArtifactEvent => "UNIDPP-SIGNATIF/ARTIFACT-EVENT",
            SigningDomain::Delegation => "UNIDPP-SIGNATIF/DELEGATION",
            SigningDomain::MasterListWitness => "UNIDPP-SIGNATIF/MASTER-LIST-WITNESS",
            SigningDomain::TreeHead => "UNIDPP-SIGNATIF/TREE-HEAD",
            SigningDomain::HistoricalStamp => "UNIDPP-SIGNATIF/HISTORICAL-STAMP",
            SigningDomain::Quorum => "UNIDPP-SIGNATIF/QUORUM",
        }
    }
}

/// The bytes actually signed for a domain payload: `tag || 0x00 ||
/// payload`.
pub fn domain_framed(domain: SigningDomain, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.tag().len() + 1 + payload.len());
    out.extend_from_slice(domain.tag().as_bytes());
    out.push(0);
    out.extend_from_slice(payload);
    out
}

/// A SIGNATIF signature slot: like the core's [`SigSlot`] but carrying
/// the full suite table (including Ed25519) and real signature values.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignatureSlot {
    /// Signing suite.
    pub suite: Suite,
    /// Content-derived key id of the signer.
    pub key_id: KeyId,
    /// Signature value (`None` = framed-only placeholder).
    pub signature: Option<Vec<u8>>,
}

impl SignatureSlot {
    /// Sign `payload` in `domain` with `key`, producing a filled slot.
    pub fn sign(
        key: &KeyPair,
        domain: SigningDomain,
        payload: &[u8],
    ) -> Result<SignatureSlot, SignatifError> {
        let value = key.sign_raw(&domain_framed(domain, payload))?;
        Ok(SignatureSlot {
            suite: key.suite(),
            key_id: key.key_id().clone(),
            signature: Some(value),
        })
    }

    /// A framed-only placeholder (no signature value) — the same
    /// discipline as the core's `SigSlot::placeholder`.
    pub fn placeholder(suite: Suite, key_id: &KeyId) -> SignatureSlot {
        SignatureSlot {
            suite,
            key_id: key_id.clone(),
            signature: None,
        }
    }

    /// Whether this slot is framing-only.
    pub fn is_framed_only(&self) -> bool {
        self.signature.is_none()
    }

    /// Verify this slot's signature value against a public key.
    ///
    /// Framed-only slots are rejected (they carry nothing verifiable);
    /// deferred suites return [`SignatifError::SuiteDeferred`]; a suite
    /// that does not match the key's suite is a cryptographic error.
    pub fn verify(
        &self,
        domain: SigningDomain,
        payload: &[u8],
        public: &PublicKey,
    ) -> Result<(), SignatifError> {
        if let Some(detail) = self.suite.deferral() {
            return Err(SignatifError::SuiteDeferred {
                suite: self.suite.to_string(),
                detail: detail.to_string(),
            });
        }
        if self.suite != public.suite() {
            return Err(SignatifError::crypto(format!(
                "slot suite `{}` does not match key suite `{}`",
                self.suite,
                public.suite()
            )));
        }
        let sig = self
            .signature
            .as_ref()
            .ok_or_else(|| SignatifError::crypto("slot is framed-only (nothing to verify)"))?;
        if sig.len() != self.suite.signature_len() {
            return Err(SignatifError::crypto(format!(
                "signature length {} does not match the {} framing budget {}",
                sig.len(),
                self.suite,
                self.suite.signature_len()
            )));
        }
        KeyPair::verify_raw(public, &domain_framed(domain, payload), sig)
    }

    /// Convert to a core [`SigSlot`] (filled or placeholder); `None`
    /// when the suite has no core carrier mapping (Ed25519).
    pub fn to_sig_slot(&self) -> Option<SigSlot> {
        Some(SigSlot {
            suite: self.suite.to_core()?,
            key_id: self.key_id.to_string(),
            signature: self.signature.clone(),
        })
    }

    /// Convert from a core [`SigSlot`].
    pub fn from_sig_slot(slot: &SigSlot) -> Result<SignatureSlot, SignatifError> {
        Ok(SignatureSlot {
            suite: Suite::from_core(slot.suite),
            key_id: KeyId::new(&slot.key_id)?,
            signature: slot.signature.clone(),
        })
    }
}

/// A co-signature: multiple suites' slots over one canonical payload.
///
/// Aggregation is by *collection*, not by cryptographic compression:
/// each slot is a full signature over the same payload under its own
/// suite and key. Acceptance is policy-scoped (see
/// [`AcceptancePolicy`]) — the point of co-signing is that a verifier
/// restricted to one jurisdiction's crypto policy still finds a suite
/// it can check.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CoSignature {
    /// Domain all slots were signed in.
    pub domain: SigningDomain,
    /// The canonical payload (core canonical bytes for artifact events).
    pub payload: Vec<u8>,
    /// The slots.
    pub slots: Vec<SignatureSlot>,
}

impl CoSignature {
    /// Start a co-signature over a canonical payload.
    pub fn new(domain: SigningDomain, payload: &[u8]) -> CoSignature {
        CoSignature {
            domain,
            payload: payload.to_vec(),
            slots: Vec::new(),
        }
    }

    /// Append a slot signed by `key`.
    pub fn sign_by(&mut self, key: &KeyPair) -> Result<&mut CoSignature, SignatifError> {
        let slot = SignatureSlot::sign(key, self.domain, &self.payload)?;
        self.slots.push(slot);
        Ok(self)
    }

    /// Append a framed-only placeholder slot.
    pub fn frame_by(&mut self, suite: Suite, key_id: &KeyId) -> &mut CoSignature {
        self.slots.push(SignatureSlot::placeholder(suite, key_id));
        self
    }

    /// Cryptographically verify every computed slot against a key
    /// directory; deferred and framed-only slots are reported, not
    /// fatal.
    pub fn verify(&self, keys: &crate::graph::KeyDirectory) -> CoSignatureReport {
        let mut slots = Vec::with_capacity(self.slots.len());
        let mut verified_suites = BTreeSet::new();
        for slot in &self.slots {
            let verdict = match keys.resolve(&slot.key_id) {
                None => SlotVerdict::UnknownKey {
                    suite: slot.suite,
                    key_id: slot.key_id.clone(),
                },
                Some(public) => match slot.verify(self.domain, &self.payload, public) {
                    Ok(()) => {
                        verified_suites.insert(slot.suite);
                        SlotVerdict::Verified {
                            suite: slot.suite,
                            key_id: slot.key_id.clone(),
                        }
                    }
                    Err(SignatifError::SuiteDeferred { suite, detail }) => SlotVerdict::Deferred {
                        suite,
                        key_id: slot.key_id.clone(),
                        detail,
                    },
                    Err(e) => SlotVerdict::Invalid {
                        suite: slot.suite,
                        key_id: slot.key_id.clone(),
                        why: e.to_string(),
                    },
                },
            };
            slots.push(verdict);
        }
        CoSignatureReport {
            slots,
            verified_suites,
        }
    }
}

/// Per-slot cryptographic verdict of a co-signature check.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SlotVerdict {
    /// The signature verified under the registered public key.
    Verified {
        /// Suite of the slot.
        suite: Suite,
        /// Key that verified.
        key_id: KeyId,
    },
    /// The signature failed verification (bad value, wrong key, or
    /// framed-only).
    Invalid {
        /// Suite of the slot.
        suite: Suite,
        /// Key that was tried.
        key_id: KeyId,
        /// Why it failed.
        why: String,
    },
    /// The suite is framing-only in this crate.
    Deferred {
        /// Suite of the slot.
        suite: String,
        /// Key the slot names.
        key_id: KeyId,
        /// Documented deferral detail.
        detail: String,
    },
    /// The key is not registered in the directory.
    UnknownKey {
        /// Suite of the slot.
        suite: Suite,
        /// Key that was not found.
        key_id: KeyId,
    },
}

/// Result of a co-signature verification pass.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CoSignatureReport {
    /// Per-slot verdicts, in slot order.
    pub slots: Vec<SlotVerdict>,
    /// Distinct suites with at least one verified slot.
    pub verified_suites: BTreeSet<Suite>,
}

impl CoSignatureReport {
    /// Number of slots that verified.
    pub fn verified_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| matches!(s, SlotVerdict::Verified { .. }))
            .count()
    }

    /// Whether at least one slot verified.
    pub fn any_verified(&self) -> bool {
        !self.verified_suites.is_empty()
    }

    /// Distinct verified-suite count.
    pub fn distinct_verified_suites(&self) -> usize {
        self.verified_suites.len()
    }
}

/// Policy-scoped acceptance: which suites this verifier accepts, and how
/// many distinct verified suites it demands.
///
/// The default reading of the UniDPP design framework's multi-suite model is *any-allowed*:
/// acceptance if ANY registered suite the policy allows verifies. A
/// `min_verified_suites` of 2 or more encodes the stricter
/// multi-signed / lens-registry co-signature requirement.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptancePolicy {
    /// Suites whose verification counts toward acceptance.
    pub allowed_suites: BTreeSet<Suite>,
    /// Minimum count of *distinct verified* allowed suites (default 1 =
    /// the any-allowed rule).
    pub min_verified_suites: usize,
}

impl AcceptancePolicy {
    /// Any-allowed policy over the computed suites.
    pub fn any_computed() -> AcceptancePolicy {
        AcceptancePolicy {
            allowed_suites: [Suite::Ed25519, Suite::EcdsaP256].into(),
            min_verified_suites: 1,
        }
    }

    /// Only the suite(s) a jurisdiction's crypto policy admits
    /// (e.g. SM2-only jurisdictions consume binding-backed verification
    /// once available; here this policy frames that scoping).
    pub fn only(suites: &[Suite]) -> AcceptancePolicy {
        AcceptancePolicy {
            allowed_suites: suites.iter().copied().collect(),
            min_verified_suites: 1,
        }
    }

    /// Multi-suite co-signature requirement (lens-registry grade).
    pub fn multi_signed() -> AcceptancePolicy {
        AcceptancePolicy {
            allowed_suites: [Suite::Ed25519, Suite::EcdsaP256].into(),
            min_verified_suites: 2,
        }
    }

    /// Evaluate a report against this policy.
    pub fn evaluate(&self, report: &CoSignatureReport) -> Acceptance {
        let verified_allowed: BTreeSet<Suite> = report
            .verified_suites
            .intersection(&self.allowed_suites)
            .copied()
            .collect();
        if verified_allowed.is_empty() {
            return Acceptance::Rejected {
                reason: format!(
                    "no slot verified under an allowed suite (allowed: {:?})",
                    self.allowed_suites
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                ),
            };
        }
        if verified_allowed.len() < self.min_verified_suites {
            return Acceptance::Rejected {
                reason: format!(
                    "policy requires {} distinct verified suites, got {}",
                    self.min_verified_suites,
                    verified_allowed.len()
                ),
            };
        }
        Acceptance::Accepted {
            suites: verified_allowed,
        }
    }
}

/// Outcome of acceptance evaluation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Acceptance {
    /// Accepted — these allowed suites verified.
    Accepted {
        /// The suites that carried the acceptance.
        suites: BTreeSet<Suite>,
    },
    /// Rejected, with the policy's reason.
    Rejected {
        /// Why the policy rejected.
        reason: String,
    },
}

impl Acceptance {
    /// Whether this is [`Acceptance::Accepted`].
    pub fn is_accepted(&self) -> bool {
        matches!(self, Acceptance::Accepted { .. })
    }
}

/// Deterministic canonical bytes for SIGNATIF-signed composite objects
/// (delegation credentials, attestations, tree heads): a length-prefixed
/// field stream via the core's [`CanonicalWriter`], so signature inputs
/// are byte-unambiguous.
pub fn canonical_fields(fields: &[&[u8]]) -> Vec<u8> {
    let mut w = CanonicalWriter::new();
    for f in fields {
        w.write_bytes(f);
    }
    w.into_bytes()
}

/// Read back fields written by [`canonical_fields`].
pub fn canonical_field_reader(bytes: &[u8]) -> Result<Vec<Vec<u8>>, SignatifError> {
    let mut r = CanonicalReader::new(bytes);
    let mut out = Vec::new();
    while r.remaining() > 0 {
        out.push(
            r.read_bytes()
                .map_err(|e| SignatifError::invalid(e.to_string()))?,
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::KeyDirectory;

    #[test]
    fn suite_table_round_trips() {
        for suite in Suite::ALL {
            assert_eq!(Suite::parse_token(suite.as_str()).unwrap(), *suite);
            let mangled = suite.as_str().to_ascii_uppercase().replace('-', "_");
            assert_eq!(Suite::parse_token(&mangled).unwrap(), *suite);
        }
        assert!(Suite::parse_token("rsa-2048").is_err());
        // Core mapping: total except Ed25519.
        for core in unidpp_model::SignatureSuite::ALL {
            let s = Suite::from_core(*core);
            assert_eq!(s.to_core(), Some(*core));
        }
        assert_eq!(Suite::Ed25519.to_core(), None);
        assert_eq!(Suite::Ed25519.signature_len(), 64);
        assert_eq!(Suite::Sm2.signature_len(), 64);
        assert_eq!(Suite::MlDsa87.signature_len(), 4627);
    }

    #[test]
    fn domain_separation_blocks_cross_replay() {
        let k = KeyPair::seeded(Suite::Ed25519, b"d").unwrap();
        let slot = SignatureSlot::sign(&k, SigningDomain::TreeHead, b"sth").unwrap();
        assert!(slot
            .verify(SigningDomain::TreeHead, b"sth", k.public())
            .is_ok());
        assert!(slot
            .verify(SigningDomain::Delegation, b"sth", k.public())
            .is_err());
        assert!(slot
            .verify(SigningDomain::TreeHead, b"other", k.public())
            .is_err());
    }

    #[test]
    fn slot_interop_with_core_framing() {
        let k = KeyPair::seeded(Suite::EcdsaP256, b"d").unwrap();
        let slot = SignatureSlot::sign(&k, SigningDomain::ArtifactEvent, b"body").unwrap();
        let core_slot = slot.to_sig_slot().unwrap();
        assert_eq!(core_slot.suite, unidpp_model::SignatureSuite::EcdsaP256);
        assert_eq!(core_slot.signature.as_ref().unwrap().len(), 64);
        let back = SignatureSlot::from_sig_slot(&core_slot).unwrap();
        assert_eq!(back, slot);
        // Ed25519 does not map onto the core carrier table.
        let k2 = KeyPair::seeded(Suite::Ed25519, b"d").unwrap();
        let slot2 = SignatureSlot::sign(&k2, SigningDomain::ArtifactEvent, b"body").unwrap();
        assert!(slot2.to_sig_slot().is_none());
        // Core placeholder converts to a framed-only SIGNATIF slot.
        let ph = SigSlot::placeholder(unidpp_model::SignatureSuite::Sm2, "k-sm2x");
        let conv = SignatureSlot::from_sig_slot(&ph).unwrap();
        assert!(conv.is_framed_only());
        assert_eq!(conv.suite, Suite::Sm2);
        assert!(conv
            .verify(SigningDomain::ArtifactEvent, b"body", k.public())
            .is_err());
    }

    #[test]
    fn cosignature_acceptance_is_policy_scoped() {
        let ed = KeyPair::seeded(Suite::Ed25519, b"co-1").unwrap();
        let p256 = KeyPair::seeded(Suite::EcdsaP256, b"co-2").unwrap();
        let mut dir = KeyDirectory::new();
        dir.register(ed.public());
        dir.register(p256.public());

        let payload = b"canonical artifact body";
        let mut co = CoSignature::new(SigningDomain::ArtifactEvent, payload);
        co.sign_by(&ed).unwrap();
        co.sign_by(&p256).unwrap();

        let report = co.verify(&dir);
        assert_eq!(report.verified_count(), 2);
        assert_eq!(report.distinct_verified_suites(), 2);
        assert!(AcceptancePolicy::any_computed()
            .evaluate(&report)
            .is_accepted());
        assert!(AcceptancePolicy::multi_signed()
            .evaluate(&report)
            .is_accepted());

        // An SM2-only jurisdiction policy rejects: no computed suite allowed.
        let sm2_only = AcceptancePolicy::only(&[Suite::Sm2]);
        assert!(!sm2_only.evaluate(&report).is_accepted());

        // One broken slot: any-allowed still accepts via the other suite.
        let mut tampered = co.clone();
        tampered.slots[0].signature.as_mut().unwrap()[0] ^= 0x01;
        let rep2 = tampered.verify(&dir);
        assert_eq!(rep2.verified_count(), 1);
        assert!(AcceptancePolicy::any_computed()
            .evaluate(&rep2)
            .is_accepted());
        // ...but the multi-suite policy no longer does.
        assert!(!AcceptancePolicy::multi_signed()
            .evaluate(&rep2)
            .is_accepted());
    }

    #[test]
    fn deferred_slots_are_reported_not_faked() {
        let ed = KeyPair::seeded(Suite::Ed25519, b"co-3").unwrap();
        let mut dir = KeyDirectory::new();
        dir.register(ed.public());
        // A fake SM2 slot value: must NOT verify and must NOT be
        // reported Invalid — it is Deferred (framing-only).
        let mut co = CoSignature::new(SigningDomain::ArtifactEvent, b"payload");
        co.frame_by(Suite::Sm2, ed.key_id());
        co.slots[0].signature = Some(vec![0u8; 64]);
        let report = co.verify(&dir);
        assert!(matches!(
            &report.slots[0],
            SlotVerdict::Deferred { suite, .. } if suite == "sm2"
        ));
        assert!(!report.any_verified());
        assert!(!AcceptancePolicy::any_computed()
            .evaluate(&report)
            .is_accepted());
    }

    #[test]
    fn canonical_fields_round_trip() {
        let fields: Vec<Vec<u8>> = vec![b"a".to_vec(), vec![], b"longer-field".to_vec()];
        let refs: Vec<&[u8]> = fields.iter().map(|f| f.as_slice()).collect();
        let bytes = canonical_fields(&refs);
        assert_eq!(canonical_field_reader(&bytes).unwrap(), fields);
    }
}
