//! The signature layer: real multi-suite signing and verification over
//! the core's canonical payloads, co-signature aggregation, composite
//! (AND-composition) signatures, and policy-scoped acceptance.
//!
//! The core (`unidpp-model::trust`) frames signature slots and their
//! byte budgets; this layer computes and verifies actual signatures for
//! **Ed25519** (ed25519-dalek) and **ECDSA-P256** (deterministic RFC
//! 6979 via the `p256` crate). **SM2 and ML-DSA remain framing-only**:
//! their suites parse, frame, and budget exactly as the core specifies,
//! but computing them is deferred to binding crates (a GM-SM2
//! implementation and a FIPS 204 module) — see [`Suite::deferral`].
//! **SLH-DSA (128s/192s) is framed and explicitly unsupported** pending
//! its binding: the `slh-dsa` crate feature is a stub seam, and every
//! path refuses with [`SignatifError::Unsupported`] — see
//! [`Suite::unsupported`].
//!
//! Two aggregation forms coexist (CC/SIGNATIF §3.7.3 vs §3.7.4):
//!
//! - the **collection** form ([`CoSignature::slots`]): independent
//!   slots over one payload, acceptance policy-scoped (any-allowed by
//!   default) — the multi-jurisdiction co-signature model;
//! - the **composite** form ([`CoSignature::composites`]):
//!   [`CompositeSignature`], a cryptographic AND-composition — one
//!   logical signature from two or more member suites, valid only when
//!   *every* member verifies — the hybrid classical/PQ migration form.
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
    /// SLH-DSA-SHA2-128s (FIPS 205; framed, computation gated behind
    /// the `slh-dsa` crate feature — see [`Suite::unsupported`]).
    SlhDsa128s,
    /// SLH-DSA-SHA2-192s (FIPS 205; framed, computation gated behind
    /// the `slh-dsa` crate feature — see [`Suite::unsupported`]).
    SlhDsa192s,
}

impl Suite {
    /// All suites, canonical order (infrastructure suites first, then
    /// the core's table order, then the PQ stateless-hash extensions).
    pub const ALL: &'static [Suite] = &[
        Suite::Ed25519,
        Suite::EcdsaP256,
        Suite::Sm2,
        Suite::MlDsa44,
        Suite::MlDsa65,
        Suite::MlDsa87,
        Suite::SlhDsa128s,
        Suite::SlhDsa192s,
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
            Suite::SlhDsa128s => "slh-dsa-128s",
            Suite::SlhDsa192s => "slh-dsa-192s",
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

    /// Map to the core carrier-framing suite; `None` for Ed25519 and
    /// the SLH-DSA extensions (they have no core carrier slot).
    pub fn to_core(self) -> Option<unidpp_model::SignatureSuite> {
        match self {
            Suite::EcdsaP256 => Some(unidpp_model::SignatureSuite::EcdsaP256),
            Suite::Sm2 => Some(unidpp_model::SignatureSuite::Sm2),
            Suite::MlDsa44 => Some(unidpp_model::SignatureSuite::MlDsa44),
            Suite::MlDsa65 => Some(unidpp_model::SignatureSuite::MlDsa65),
            Suite::MlDsa87 => Some(unidpp_model::SignatureSuite::MlDsa87),
            Suite::Ed25519 | Suite::SlhDsa128s | Suite::SlhDsa192s => None,
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
    ///
    /// SM2 and ML-DSA-65 compute when their binding features (`sm2`,
    /// `ml-dsa`) are enabled; without them the suites stay framing-only
    /// ([`Suite::deferral`]) — never silently faked.
    pub fn is_computed(self) -> bool {
        match self {
            Suite::Ed25519 | Suite::EcdsaP256 => true,
            #[cfg(feature = "sm2")]
            Suite::Sm2 => true,
            #[cfg(feature = "ml-dsa")]
            Suite::MlDsa65 => true,
            _ => false,
        }
    }

    /// Whether this suite is a post-quantum algorithm (ML-DSA per
    /// FIPS 204, SLH-DSA per FIPS 205) — the migration-phase input of
    /// the deployment manifest (CC/SIGNATIF §18/§20).
    pub fn is_post_quantum(self) -> bool {
        matches!(
            self,
            Suite::MlDsa44
                | Suite::MlDsa65
                | Suite::MlDsa87
                | Suite::SlhDsa128s
                | Suite::SlhDsa192s
        )
    }

    /// Canonical signature length in bytes (mirrors the core's framing
    /// budget table; Ed25519 is 64; SLH-DSA per FIPS 205: 128s = 7856,
    /// 192s = 16224).
    pub fn signature_len(self) -> usize {
        match self {
            Suite::Ed25519 => 64,
            Suite::SlhDsa128s => 7856,
            Suite::SlhDsa192s => 16224,
            other => other.to_core().map(|c| c.signature_len()).unwrap_or(64),
        }
    }

    /// One-byte suite code (`to_core` where defined; Ed25519 takes 6,
    /// SLH-DSA-128s 7, SLH-DSA-192s 8 — the extension codes after the
    /// core's 1–5).
    pub fn code(self) -> u8 {
        match self {
            Suite::Ed25519 => 6,
            Suite::SlhDsa128s => 7,
            Suite::SlhDsa192s => 8,
            other => other.to_core().map(|c| c.code()).unwrap_or(6),
        }
    }

    /// The documented deferral for framing-only suites.
    pub fn deferral(self) -> Option<&'static str> {
        let m = self;
        #[cfg(feature = "sm2")]
        {
            if matches!(m, Suite::Sm2) {
                return None;
            }
        }
        #[cfg(feature = "ml-dsa")]
        {
            if matches!(m, Suite::MlDsa65) {
                return None;
            }
        }
        match m {
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

    /// Why this suite is **explicitly unsupported** here (as opposed to
    /// [`Suite::deferral`], which names a deliberate binding seam).
    ///
    /// SLH-DSA (FIPS 205) is in the standard's post-quantum algorithm
    /// table, so the suites are framed (token, budget, wire code) — but
    /// no computation exists under the default feature set. The
    /// `slh-dsa` crate feature is the integration seam: it is
    /// deliberately a **stub** (no PQ crate dependency yet — pending
    /// build-size and supply-chain review of the FIPS 205 candidates),
    /// so even with the feature enabled the suites refuse with this
    /// error until the binding lands in `keyring`. Every path returns
    /// an explicit [`SignatifError::Unsupported`]; nothing panics and
    /// nothing fakes a verification.
    pub fn unsupported(self) -> Option<&'static str> {
        match self {
            Suite::SlhDsa128s | Suite::SlhDsa192s => {
                if cfg!(feature = "slh-dsa") {
                    Some(
                        "the `slh-dsa` feature is enabled but is a stub: the FIPS 205 \
                         binding crate is deliberately not a dependency yet (build-size and \
                         supply-chain review pending); wire it into `keyring` to activate \
                         computation",
                    )
                } else {
                    Some(
                        "SLH-DSA (FIPS 205) computation requires the `slh-dsa` crate \
                         feature; enable it to activate the (currently stubbed) SLH-DSA path",
                    )
                }
            }
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
    /// A signed roll-up attestation over a committed traversal set.
    RollupAttestation,
    /// A grid segment policy object (its constitution) — the
    /// authority's signature over the policy's canonical bytes.
    SegmentPolicy,
    /// A grid commitment spine root — the custodian's signature
    /// binding the spine (what anchors and logs consume).
    SpineRoot,
    /// A signed profile — the issuer's signature over the profile
    /// manifest (PR-1: the issuer class grades what it may claim).
    Profile,
    /// An S13 cross-border message (request, response, offer,
    /// escalation) — the choreography's signed objects (XB-6).
    S13Message,
    /// A sovereign attestation service's signature over an
    /// attestation statement (XB-2) — distinct from the quorum
    /// co-signature it may carry.
    SovereignAttestation,
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
            SigningDomain::SegmentPolicy => "UNIDPP-SIGNATIF/SEGMENT-POLICY",
            SigningDomain::SpineRoot => "UNIDPP-SIGNATIF/SPINE-ROOT",
            SigningDomain::Profile => "UNIDPP-SIGNATIF/PROFILE",
            SigningDomain::S13Message => "UNIDPP-SIGNATIF/S13-MESSAGE",
            SigningDomain::SovereignAttestation => "UNIDPP-SIGNATIF/SOVEREIGN-ATTESTATION",
            SigningDomain::RollupAttestation => "UNIDPP-SIGNATIF/ROLLUP-ATTESTATION",
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
    /// explicitly-unsupported suites (SLH-DSA without its binding)
    /// return [`SignatifError::Unsupported`]; deferred suites return
    /// [`SignatifError::SuiteDeferred`]; a suite that does not match
    /// the key's suite is a cryptographic error.
    pub fn verify(
        &self,
        domain: SigningDomain,
        payload: &[u8],
        public: &PublicKey,
    ) -> Result<(), SignatifError> {
        if let Some(detail) = self.suite.unsupported() {
            return Err(SignatifError::Unsupported {
                suite: self.suite.to_string(),
                detail: detail.to_string(),
            });
        }
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

/// A **composite signature** (CC/SIGNATIF §3.7.4, §9
/// `algorithms-composite`): one logical signature produced by the
/// cryptographic **AND-composition** of two or more member suites over
/// the same domain-framed payload.
///
/// Unlike a [`CoSignature`] (a *collection* of independent slots, where
/// acceptance is policy-scoped — any-allowed by default), a composite
/// is **all-or-nothing**: [`CompositeSignature::verify`] succeeds only
/// when *every* member slot verifies; a single failing member fails
/// the composite. This is the hybrid classical/post-quantum migration
/// form (e.g. Ed25519 AND ML-DSA over one payload during the
/// transition window): the verifier gains security only if both
/// algorithms hold, so both must hold.
///
/// The composite is carried on a [`CoSignature`] as an *alternative
/// slot form* alongside the plain multi-suite collection
/// ([`CoSignature::composites`]): a verified composite contributes all
/// its member suites to the report's `verified_suites`; a composite
/// with any failing member contributes none.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CompositeSignature {
    /// Domain all members signed in.
    pub domain: SigningDomain,
    /// The canonical payload every member signed (same bytes for all).
    pub payload: Vec<u8>,
    /// The member slots, one per composing suite.
    pub members: Vec<SignatureSlot>,
}

impl CompositeSignature {
    /// Start a composite over a canonical payload.
    pub fn new(domain: SigningDomain, payload: &[u8]) -> CompositeSignature {
        CompositeSignature {
            domain,
            payload: payload.to_vec(),
            members: Vec::new(),
        }
    }

    /// Add a member: every member signs the *same* domain-framed
    /// payload bytes — the AND-composition is over identical inputs.
    pub fn sign_member(&mut self, key: &KeyPair) -> Result<&mut CompositeSignature, SignatifError> {
        self.members
            .push(SignatureSlot::sign(key, self.domain, &self.payload)?);
        Ok(self)
    }

    /// Add a framed-only placeholder member (no signature value).
    pub fn frame_member(&mut self, suite: Suite, key_id: &KeyId) -> &mut CompositeSignature {
        self.members.push(SignatureSlot::placeholder(suite, key_id));
        self
    }

    /// The AND-composition verification: every member must verify
    /// against its registered key; one failure fails the composite.
    ///
    /// Explicitly-unsupported and deferred member suites (and
    /// unregistered member keys) fail the composite — a composite is
    /// only as strong as its weakest member.
    pub fn verify(&self, keys: &crate::graph::KeyDirectory) -> CompositeVerdict {
        let mut members = Vec::with_capacity(self.members.len());
        for slot in &self.members {
            let verdict = match keys.resolve(&slot.key_id) {
                None => SlotVerdict::UnknownKey {
                    suite: slot.suite,
                    key_id: slot.key_id.clone(),
                },
                Some(public) => match slot.verify(self.domain, &self.payload, public) {
                    Ok(()) => SlotVerdict::Verified {
                        suite: slot.suite,
                        key_id: slot.key_id.clone(),
                    },
                    Err(SignatifError::SuiteDeferred { suite, detail })
                    | Err(SignatifError::Unsupported { suite, detail }) => SlotVerdict::Deferred {
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
            members.push(verdict);
        }
        let verified = !members.is_empty()
            && members
                .iter()
                .all(|m| matches!(m, SlotVerdict::Verified { .. }));
        CompositeVerdict { members, verified }
    }

    /// Distinct member suites (the composition's coverage when it
    /// verifies).
    pub fn member_suites(&self) -> BTreeSet<Suite> {
        self.members.iter().map(|m| m.suite).collect()
    }
}

/// Verification outcome of a composite: per-member verdicts plus the
/// AND-composition result.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CompositeVerdict {
    /// Per-member verdicts, in member order.
    pub members: Vec<SlotVerdict>,
    /// Whether the composite as a whole verified (every member
    /// verified; an empty composite never verifies).
    pub verified: bool,
}

impl CompositeVerdict {
    /// The first non-verifying member verdict, for diagnostics (`None`
    /// when the composite verified or is empty).
    pub fn first_failing_member(&self) -> Option<&SlotVerdict> {
        self.members
            .iter()
            .find(|m| !matches!(m, SlotVerdict::Verified { .. }))
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
///
/// A co-signature may additionally carry **composite signatures**
/// ([`CompositeSignature`], cryptographic AND-composition) as an
/// alternative slot form alongside the plain collection: composites
/// live in [`CoSignature::composites`], verify under their own
/// all-or-nothing semantics, and contribute their member suites to
/// `verified_suites` only when the whole composite verifies.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CoSignature {
    /// Domain all slots were signed in.
    pub domain: SigningDomain,
    /// The canonical payload (core canonical bytes for artifact events).
    pub payload: Vec<u8>,
    /// The plain (collection-form) slots.
    pub slots: Vec<SignatureSlot>,
    /// The composite (AND-composition-form) signatures carried
    /// alongside the plain slots.
    #[serde(default)]
    pub composites: Vec<CompositeSignature>,
}

impl CoSignature {
    /// Start a co-signature over a canonical payload.
    pub fn new(domain: SigningDomain, payload: &[u8]) -> CoSignature {
        CoSignature {
            domain,
            payload: payload.to_vec(),
            slots: Vec::new(),
            composites: Vec::new(),
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

    /// Append a composite signature (the AND-composition slot form).
    /// The composite's domain and payload must match the co-signature's
    /// own — a composite over different bytes is a structural error.
    pub fn attach_composite(
        &mut self,
        composite: CompositeSignature,
    ) -> Result<&mut CoSignature, SignatifError> {
        if composite.domain != self.domain || composite.payload != self.payload {
            return Err(SignatifError::invalid(
                "composite signature must cover the co-signature's domain and payload",
            ));
        }
        self.composites.push(composite);
        Ok(self)
    }

    /// Build and attach a composite over this co-signature's own
    /// domain and payload, signing with each of `keys` (the
    /// AND-composition member set).
    pub fn sign_composite_by(
        &mut self,
        keys: &[&KeyPair],
    ) -> Result<&mut CoSignature, SignatifError> {
        let mut composite = CompositeSignature::new(self.domain, &self.payload);
        for key in keys {
            composite.sign_member(key)?;
        }
        self.attach_composite(composite)
    }

    /// Cryptographically verify every computed slot and composite
    /// against a key directory; deferred and framed-only slots are
    /// reported, not fatal.
    ///
    /// Composites verify under AND-composition: a verifying composite
    /// contributes *all* its member suites to `verified_suites`; a
    /// composite with any failing member contributes none.
    pub fn verify(&self, keys: &crate::graph::KeyDirectory) -> CoSignatureReport {
        let mut slots = Vec::with_capacity(self.slots.len());
        let mut verified_suites = BTreeSet::new();
        for slot in &self.slots {
            let verdict = Self::slot_verdict(slot, self.domain, &self.payload, keys);
            if let SlotVerdict::Verified { suite, .. } = &verdict {
                verified_suites.insert(*suite);
            }
            slots.push(verdict);
        }
        let mut composites = Vec::with_capacity(self.composites.len());
        for composite in &self.composites {
            let verdict = composite.verify(keys);
            if verdict.verified {
                verified_suites.extend(composite.member_suites());
            }
            composites.push(verdict);
        }
        CoSignatureReport {
            slots,
            verified_suites,
            composites,
        }
    }

    fn slot_verdict(
        slot: &SignatureSlot,
        domain: SigningDomain,
        payload: &[u8],
        keys: &crate::graph::KeyDirectory,
    ) -> SlotVerdict {
        match keys.resolve(&slot.key_id) {
            None => SlotVerdict::UnknownKey {
                suite: slot.suite,
                key_id: slot.key_id.clone(),
            },
            Some(public) => match slot.verify(domain, payload, public) {
                Ok(()) => SlotVerdict::Verified {
                    suite: slot.suite,
                    key_id: slot.key_id.clone(),
                },
                Err(SignatifError::SuiteDeferred { suite, detail })
                | Err(SignatifError::Unsupported { suite, detail }) => SlotVerdict::Deferred {
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
    /// Distinct suites with at least one verified slot (a verifying
    /// composite contributes all its member suites).
    pub verified_suites: BTreeSet<Suite>,
    /// Per-composite verdicts (the AND-composition slot form), in
    /// composite order.
    #[serde(default)]
    pub composites: Vec<CompositeVerdict>,
}

impl CoSignatureReport {
    /// Number of slots that verified.
    pub fn verified_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| matches!(s, SlotVerdict::Verified { .. }))
            .count()
    }

    /// Whether at least one slot or composite verified.
    pub fn any_verified(&self) -> bool {
        !self.verified_suites.is_empty()
    }

    /// Distinct verified-suite count.
    pub fn distinct_verified_suites(&self) -> usize {
        self.verified_suites.len()
    }

    /// Whether every carried composite verified (vacuously true when
    /// none are carried).
    pub fn all_composites_verified(&self) -> bool {
        self.composites.iter().all(|c| c.verified)
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
        // A fake value in a framing-only suite (ML-DSA-44 never
        // computes here): must NOT verify and must NOT be reported
        // Invalid — it is Deferred.
        let mut co = CoSignature::new(SigningDomain::ArtifactEvent, b"payload");
        co.frame_by(Suite::MlDsa44, ed.key_id());
        co.slots[0].signature = Some(vec![0u8; 2420]);
        let report = co.verify(&dir);
        assert!(matches!(
            &report.slots[0],
            SlotVerdict::Deferred { suite, .. } if suite == "ml-dsa-44"
        ));
        // The same fake value in SM2: with the binding feature the
        // suite computes, so the junk value is Invalid (real
        // verification refused it); without the feature it is Deferred.
        let mut sm2 = CoSignature::new(SigningDomain::ArtifactEvent, b"payload");
        sm2.frame_by(Suite::Sm2, ed.key_id());
        sm2.slots[0].signature = Some(vec![0u8; 64]);
        let report2 = sm2.verify(&dir);
        #[cfg(feature = "sm2")]
        assert!(matches!(&report2.slots[0], SlotVerdict::Invalid { .. }));
        #[cfg(not(feature = "sm2"))]
        assert!(matches!(&report2.slots[0], SlotVerdict::Deferred { .. }));
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

    #[test]
    fn composite_signatures_verify_under_and_composition() {
        let ed = KeyPair::seeded(Suite::Ed25519, b"comp-1").unwrap();
        let p256 = KeyPair::seeded(Suite::EcdsaP256, b"comp-2").unwrap();
        let mut dir = KeyDirectory::new();
        dir.register(ed.public());
        dir.register(p256.public());

        let mut composite =
            CompositeSignature::new(SigningDomain::ArtifactEvent, b"canonical body");
        composite.sign_member(&ed).unwrap();
        composite.sign_member(&p256).unwrap();
        let verdict = composite.verify(&dir);
        assert!(verdict.verified, "all members verify: composite holds");
        assert_eq!(verdict.members.len(), 2);
        assert!(verdict.first_failing_member().is_none());
        assert_eq!(composite.member_suites().len(), 2);

        // AND-composition: tamper ONE member — the composite fails even
        // though the other member still verifies.
        let mut broken = composite.clone();
        broken.members[0].signature.as_mut().unwrap()[0] ^= 0x01;
        let verdict = broken.verify(&dir);
        assert!(!verdict.verified);
        assert!(verdict.first_failing_member().is_some());

        // An unregistered member key fails the composite (fails closed).
        let stranger = KeyPair::seeded(Suite::Ed25519, b"comp-3").unwrap();
        let mut unknown = composite.clone();
        unknown.sign_member(&stranger).unwrap();
        assert!(!unknown.verify(&dir).verified);

        // A framed-only member fails the composite.
        let mut framed = CompositeSignature::new(SigningDomain::ArtifactEvent, b"canonical body");
        framed.sign_member(&ed).unwrap();
        framed.frame_member(Suite::MlDsa87, p256.key_id());
        let verdict = framed.verify(&dir);
        assert!(!verdict.verified);
        assert!(matches!(
            verdict.first_failing_member(),
            Some(SlotVerdict::Deferred { .. })
        ));

        // An empty composite never verifies.
        let empty = CompositeSignature::new(SigningDomain::ArtifactEvent, b"x");
        assert!(!empty.verify(&dir).verified);
    }

    #[test]
    fn composite_slot_form_counts_toward_acceptance() {
        let ed = KeyPair::seeded(Suite::Ed25519, b"cs-1").unwrap();
        let p256 = KeyPair::seeded(Suite::EcdsaP256, b"cs-2").unwrap();
        let mut dir = KeyDirectory::new();
        dir.register(ed.public());
        dir.register(p256.public());

        // A co-signature carrying ONLY a composite (no plain slots).
        let mut co = CoSignature::new(SigningDomain::ArtifactEvent, b"body");
        co.sign_composite_by(&[&ed, &p256]).unwrap();
        assert!(co.slots.is_empty());
        assert_eq!(co.composites.len(), 1);
        let report = co.verify(&dir);
        assert!(report.all_composites_verified());
        // The verifying composite contributes both member suites.
        assert_eq!(report.distinct_verified_suites(), 2);
        // One composite satisfies the two-distinct-suite policy.
        assert!(AcceptancePolicy::multi_signed()
            .evaluate(&report)
            .is_accepted());

        // Tampering one member drops BOTH suites: the composite
        // contributes nothing when it fails as a whole.
        let mut tampered = co.clone();
        tampered.composites[0].members[1]
            .signature
            .as_mut()
            .unwrap()[0] ^= 0x01;
        let report = tampered.verify(&dir);
        assert!(!report.all_composites_verified());
        assert!(!report.any_verified());
        assert!(!AcceptancePolicy::any_computed()
            .evaluate(&report)
            .is_accepted());

        // A composite over different bytes cannot be attached.
        let mut foreign = CompositeSignature::new(SigningDomain::TreeHead, b"body");
        foreign.sign_member(&ed).unwrap();
        let mut co2 = CoSignature::new(SigningDomain::ArtifactEvent, b"body");
        assert!(co2.attach_composite(foreign).is_err());
    }

    #[test]
    fn slh_dsa_suites_frame_refusing_computation() {
        // Tokens parse and round-trip; the suites are in the table.
        for (suite, token, len, code) in [
            (Suite::SlhDsa128s, "slh-dsa-128s", 7856usize, 7u8),
            (Suite::SlhDsa192s, "slh-dsa-192s", 16224, 8),
        ] {
            assert!(Suite::ALL.contains(&suite));
            assert_eq!(suite.as_str(), token);
            assert_eq!(Suite::parse_token(token).unwrap(), suite);
            assert_eq!(Suite::parse_token(&token.to_uppercase()).unwrap(), suite);
            assert_eq!(suite.signature_len(), len);
            assert_eq!(suite.code(), code);
            assert_eq!(suite.to_core(), None, "no core carrier slot");
            assert!(suite.is_post_quantum());
            assert!(!suite.is_computed());
            // Deferral vs unsupported: SLH-DSA is unsupported (feature
            // seam), not deferred (binding seam).
            assert!(suite.unsupported().is_some());
            assert_eq!(suite.deferral(), None);
            // Keygen refuses with the explicit Unsupported error.
            let err = KeyPair::seeded(suite, b"seed").unwrap_err();
            assert!(matches!(err, SignatifError::Unsupported { .. }), "{err}");
            assert!(err.to_string().contains("slh-dsa"), "{err}");
        }
        // Framing-only slots in a co-signature report as Deferred with
        // the unsupported detail — never faked, never fatal.
        let ed = KeyPair::seeded(Suite::Ed25519, b"slh").unwrap();
        let mut dir = KeyDirectory::new();
        dir.register(ed.public());
        let mut co = CoSignature::new(SigningDomain::ArtifactEvent, b"body");
        co.frame_by(Suite::SlhDsa128s, ed.key_id());
        let report = co.verify(&dir);
        match &report.slots[0] {
            SlotVerdict::Deferred { suite, detail, .. } => {
                assert_eq!(suite, "slh-dsa-128s");
                assert!(detail.contains("slh-dsa"), "{detail}");
            }
            other => panic!("expected Deferred, got {other:?}"),
        }
    }
}
