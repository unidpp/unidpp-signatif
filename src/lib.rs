//! UniDPP trust integration (SIGNATIF): the trust layer that turns the
//! core's *framing* types into *operations*.
//!
//! `unidpp-core` (`crates/model/src/trust.rs`) frames multi-suite
//! signature slots ([`unidpp_model::SigSlot`]) and defers actual trust
//! computation to this crate. SIGNATIF supplies:
//!
//! - a **delegation trust graph** ([`graph`]): root / threshold-group /
//!   delegated / end nodes, scoped delegation edges under the four-layer
//!   scope (authority × profile-version × product-group × time window,
//!   [`scope`]), jurisdiction trust lists, M-of-K multi-witness
//!   master-list entries, and path-finding from an artifact signature up
//!   to a verifier's anchor bundle;
//! - a **signature layer** ([`sign`]) with real Ed25519 (ed25519-dalek)
//!   and ECDSA-P256 (RFC 6979 deterministic, p256) cryptography over the
//!   core's canonical payloads, plus co-signature aggregation under
//!   policy-scoped acceptance (pass if ANY suite the acceptance policy
//!   allows verifies). SM2 and ML-DSA remain framing-only — see
//!   [`sign::Suite`] for the documented deferral;
//! - **revocation** ([`revoke`]) with a prospective/retroactive reason
//!   taxonomy, distrust windows `[start, end]` with cascading voiding
//!   inside the window and re-validation outside it, and propagation to
//!   transitively bound artifacts through the core's taint/provenance
//!   crates;
//! - **transparency anchoring** ([`anchor`]): an append-only Merkle log
//!   with inclusion and consistency proofs, signed tree heads, salted
//!   commitment leaves (logs anchor commitments, never facts), and a
//!   log-of-logs M-of-K master list;
//! - a **verification pipeline** ([`verify`]) producing the core's
//!   [`unidpp_verdict::Verdict`] types: the three readings, coverage
//!   reports, and time-stamped historical verification valid as-of its
//!   anchors;
//! - a **Confium seam** (module `confium`, feature `confium`): interface-only
//!   trait shapes for threshold ceremonies, mirroring the Confium
//!   session/coordinator API. The real binding is a documented
//!   deviation: it is deferred.
//!
//! Crate conventions follow `unidpp-core`: serde-only extra dependencies
//! where possible (the two real-crypto crates are the deliberate
//! exception), rustdoc on every public item, and hand-rolled seeded
//! property tests (no proptest dependency).

#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]

pub mod anchor;
pub mod graph;
pub mod keyring;
pub mod revoke;
pub mod scope;
pub mod sign;
pub mod verify;

#[cfg(feature = "confium")]
pub mod confium;

pub use anchor::{
    verify_consistency, verify_inclusion, ConsistencyProof, InclusionProof, LogEntry, LogOfLogs,
    ProofNode, Side, SignedTreeHead, TransparencyLog,
};
pub use graph::{
    AnchorBundle, DelegationCredential, DelegationNode, KeyDirectory, MasterList, MasterListEntry,
    NodeId, NodeKind, RegisteredKey, TrustGraph, TrustList, TrustListEntry, TrustPath,
    WitnessAttestation,
};
pub use keyring::{KeyId, KeyPair, PublicKey};
pub use revoke::{
    IssuanceIndex, QuorumAttestation, Revocation, RevocationLedger, RevocationReason,
    RevokedSubject, Standing,
};
pub use scope::{DelegationScope, LayerConstraint, ScopeRequest, WindowConstraint};
pub use sign::{
    Acceptance, AcceptancePolicy, CoSignature, CoSignatureReport, SignatureSlot, SigningDomain,
    SlotVerdict, Suite,
};
pub use verify::{HistoricalStanding, HistoricalVerification, SignatifVerdict, TrustReport};

use std::fmt;

/// Errors of the SIGNATIF crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatifError {
    /// Malformed input (bad lengths, bad encodings).
    Validation(String),
    /// A scope constraint is unsatisfiable or a widening was attempted.
    ScopeViolation(String),
    /// Real cryptographic verification failed (wrong key, bad signature,
    /// suite/key-type mismatch, bad point encodings).
    Crypto(String),
    /// The suite is framing-only in this crate; computation is deferred
    /// to a binding crate (`detail` names the binding seam).
    SuiteDeferred {
        /// The deferred suite's token.
        suite: String,
        /// Where the computation is deferred to.
        detail: String,
    },
    /// No delegation path connects the key to a root of the anchor bundle.
    NoTrustPath {
        /// The key that could not be reached.
        key_id: String,
    },
    /// A path existed but its effective scope excludes the request.
    ScopeExcluded {
        /// The key whose path was out of scope.
        key_id: String,
        /// Which layer (or detail) excluded the request.
        detail: String,
    },
    /// A delegation credential failed signature verification.
    CredentialSignatureInvalid {
        /// Delegating node.
        parent: String,
        /// Receiving node.
        child: String,
    },
    /// Unknown node or key referenced by an operation.
    Unknown {
        /// What kind of thing was not found.
        kind: &'static str,
        /// Its id.
        id: String,
    },
    /// A trust-anchoring precondition failed (root not listed, master
    /// list quorum not met).
    Trust(String),
    /// Transparency-log proof verification failed.
    Transparency(String),
    /// A retroactive (void-ab-initio) declaration lacked the required
    /// quorum attestation — authority-over-authority needs a quorate body.
    QuorumRequired {
        /// The subject of the retroactive declaration.
        subject: String,
    },
}

impl SignatifError {
    /// Convenience constructor for [`SignatifError::Validation`].
    pub fn invalid(msg: impl Into<String>) -> SignatifError {
        SignatifError::Validation(msg.into())
    }

    /// Convenience constructor for [`SignatifError::Crypto`].
    pub fn crypto(msg: impl Into<String>) -> SignatifError {
        SignatifError::Crypto(msg.into())
    }
}

impl fmt::Display for SignatifError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatifError::Validation(m) => write!(f, "validation error: {m}"),
            SignatifError::ScopeViolation(m) => write!(f, "scope violation: {m}"),
            SignatifError::Crypto(m) => write!(f, "cryptographic error: {m}"),
            SignatifError::SuiteDeferred { suite, detail } => {
                write!(f, "suite `{suite}` is framing-only here: {detail}")
            }
            SignatifError::NoTrustPath { key_id } => write!(
                f,
                "no delegation path from any anchored root to key `{key_id}`"
            ),
            SignatifError::ScopeExcluded { key_id, detail } => {
                write!(f, "path to key `{key_id}` exists but scope excludes the request: {detail}")
            }
            SignatifError::CredentialSignatureInvalid { parent, child } => write!(
                f,
                "delegation credential {parent} -> {child} failed signature verification"
            ),
            SignatifError::Unknown { kind, id } => write!(f, "unknown {kind} `{id}`"),
            SignatifError::Trust(m) => write!(f, "trust anchoring failed: {m}"),
            SignatifError::Transparency(m) => write!(f, "transparency error: {m}"),
            SignatifError::QuorumRequired { subject } => write!(
                f,
                "retroactive distrust of `{subject}` requires a quorum attestation \
                 (authority-over-authority is a threshold decision)"
            ),
        }
    }
}

impl std::error::Error for SignatifError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_display() {
        let e = SignatifError::SuiteDeferred {
            suite: "sm2".into(),
            detail: "binding deferred".into(),
        };
        assert!(e.to_string().contains("framing-only"));
        assert_eq!(
            SignatifError::invalid("bad").to_string(),
            "validation error: bad"
        );
    }
}
