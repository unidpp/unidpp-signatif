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
//!   allows verifies), and **composite signatures** (cryptographic
//!   AND-composition of member suites over one payload, CC/SIGNATIF
//!   §3.7.4) carried as an alternative slot form alongside the
//!   multi-suite collection. SM2 and ML-DSA remain framing-only — see
//!   [`sign::Suite`] for the documented deferral; SLH-DSA is framed and
//!   gated behind the (stubbed) `slh-dsa` crate feature, refusing with
//!   an explicit [`SignatifError::Unsupported`] rather than panicking;
//! - **revocation** ([`revoke`]) with a prospective/retroactive reason
//!   taxonomy, distrust windows `[start, end]` with cascading voiding
//!   inside the window and re-validation outside it, and propagation to
//!   transitively bound artifacts through the core's taint/provenance
//!   crates;
//! - **transparency anchoring** ([`anchor`]): an append-only Merkle log
//!   with inclusion and consistency proofs, signed tree heads, salted
//!   commitment leaves (logs anchor commitments, never facts), a
//!   log-of-logs M-of-K master list, and **external time anchoring**
//!   (CC/SIGNATIF §13): an OpenTimestamps-style commitment payload
//!   (RFC 3161 timestamp request bytes or an OTS-lite digest +
//!   rendezvous point) produced by
//!   [`anchor::external_anchor_payload`] for the operator to submit —
//!   the library never performs network calls;
//! - a **verification pipeline** ([`verify`]) producing the core's
//!   [`unidpp_verdict::Verdict`] types: the three readings, coverage
//!   reports, and time-stamped historical verification valid as-of its
//!   anchors;
//! - a **Confium seam** (module `confium`, feature `confium`): trait
//!   shapes for threshold ceremonies mirroring the Confium
//!   session/coordinator API, with two implementations — the
//!   interface-only mock for lifecycle tests, and a real bridge
//!   ([`confium::real::RealCeremony`]) onto the crate's own threshold
//!   cryptography. The binding to Confium itself remains a documented,
//!   deferred deviation;
//! - a **deployment manifest** ([`manifest`], CC/SIGNATIF §18): the
//!   serializable declaration of a deployment's active and deprecated
//!   algorithms, migration phase, topology profile, and scope
//!   extensions, with a validation function.
//!
//! Crate conventions follow `unidpp-core`: serde-only extra dependencies
//! where possible (the two real-crypto crates are the deliberate
//! exception), rustdoc on every public item, and hand-rolled seeded
//! property tests (no proptest dependency).

#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]

pub mod acceptance;
pub mod anchor;
pub mod dossier;
pub mod envelope;
pub mod frozen;
pub mod graph;
pub mod grid;
pub mod keyring;
pub mod manifest;
pub mod revoke;
pub mod rollup;
pub mod s13;
pub mod scope;
pub mod sign;
pub mod signed_profile;
pub mod sovereign;
pub mod spine_anchor;
pub mod threshold;
pub mod verify;

#[cfg(feature = "confium")]
pub mod confium;

pub use anchor::{
    external_anchor_payload, verify_consistency, verify_external_anchor, verify_inclusion,
    ConsistencyProof, ExternalAnchor, ExternalAnchorMethod, InclusionProof, LogEntry, LogOfLogs,
    ProofNode, Side, SignedTreeHead, TransparencyLog,
};
pub use graph::{
    AnchorBundle, DelegationCredential, DelegationNode, KeyDirectory, MasterList, MasterListEntry,
    NodeId, NodeKind, RegisteredKey, TrustGraph, TrustList, TrustListEntry, TrustPath,
    WitnessAttestation,
};
pub use keyring::{KeyId, KeyPair, PublicKey};
pub use manifest::{AlgorithmStatus, DeploymentManifest, MigrationPhase, TopologyProfile};
pub use revoke::{
    IssuanceIndex, QuorumAttestation, Revocation, RevocationLedger, RevocationReason,
    RevokedSubject, Standing,
};
pub use scope::{DelegationScope, LayerConstraint, ScopeCondition, ScopeRequest, WindowConstraint};
pub use sign::{
    Acceptance, AcceptancePolicy, CoSignature, CoSignatureReport, CompositeSignature,
    CompositeVerdict, SignatureSlot, SigningDomain, SlotVerdict, Suite,
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
    /// A path's effective scope carried a condition the request does
    /// not satisfy (CC/SIGNATIF §14 `tab-failure-reasons`
    /// `scope_condition_failed`): the pipeline's hard scope-condition
    /// check failed at verification time.
    ScopeConditionFailed {
        /// The condition that was not met.
        condition: crate::scope::ScopeCondition,
    },
    /// The operation is explicitly unsupported under the current
    /// feature set — distinct from [`SignatifError::SuiteDeferred`]
    /// (a binding exists by design) in that no computation path exists
    /// here at all; the `detail` names the feature or binding that
    /// would activate it (currently the SLH-DSA stub).
    Unsupported {
        /// The suite or operation that is unsupported.
        suite: String,
        /// What would activate support.
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
                write!(
                    f,
                    "path to key `{key_id}` exists but scope excludes the request: {detail}"
                )
            }
            SignatifError::ScopeConditionFailed { condition } => {
                write!(
                    f,
                    "scope condition `{condition}` ({}-form) failed at verification time",
                    condition.label()
                )
            }
            SignatifError::Unsupported { suite, detail } => {
                write!(f, "suite `{suite}` is unsupported here: {detail}")
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
