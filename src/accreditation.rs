//! Accreditation objects (TR-9): the A→C grant as a first-class
//! verifiable object whose LIVENESS is checked at use time.
//!
//! The accreditation pyramid is first-class: a conformity body's
//! evidence stands on the accreditation authority's grant — scope,
//! window, schemes — signed by the authority. Liveness is a use-time
//! property: a C-class signature whose accreditation has expired
//! DEGRADES the verdict, naming the chain; a missing accreditation
//! is stated, never silent. Trust markers are graded, never boolean.

use crate::graph::{NodeId, TrustGraph};
use crate::keyring::KeyPair;
use crate::party::{intake_permits, ObjectClass, PartyClass};
use crate::sign::{SignatureSlot, SigningDomain};
use crate::SignatifError;
use unidpp_model::time::Timestamp;
use unidpp_model::{sha256, CanonicalWriter};

/// The accreditation grant: the A→C edge of the pyramid.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AccreditationObject {
    /// The accredited party (trust-graph node — expected class:
    /// conformity body).
    pub accredited: String,
    /// The accrediting authority (expected class: accreditation
    /// authority or government).
    pub authority: String,
    /// Version (supersession is detectable).
    pub version: u64,
    /// The accredited scope (what the C may attest: classes,
    /// schemes, programs).
    pub scope: Vec<String>,
    /// The accepted cryptographic suites.
    pub schemes: Vec<String>,
    /// Effective window start (RFC 3339).
    pub valid_from: String,
    /// Effective window end (RFC 3339; absent: open-ended).
    pub valid_to: Option<String>,
    /// The authority's signature in the ACCREDITATION domain.
    pub signature: SignatureSlot,
}

impl AccreditationObject {
    /// The canonical, signable form (CN-1): accredited, authority,
    /// version, sorted-joined scope, sorted-joined schemes, window.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let join = |values: &[String]| {
            let mut sorted: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
            sorted.sort();
            sorted.join("\u{1f}").into_bytes()
        };
        let mut w = CanonicalWriter::new();
        w.write_bytes(self.accredited.as_bytes());
        w.write_bytes(self.authority.as_bytes());
        w.write_bytes(&self.version.to_le_bytes());
        w.write_bytes(&join(&self.scope));
        w.write_bytes(&join(&self.schemes));
        w.write_bytes(self.valid_from.as_bytes());
        w.write_bytes(self.valid_to.as_deref().unwrap_or("").as_bytes());
        w.into_bytes()
    }

    /// The object's digest.
    pub fn digest(&self) -> [u8; 32] {
        sha256(&[&self.canonical_bytes()]).0
    }

    /// Issue: the authority signs the canonical bytes. The signing
    /// matrix is consulted — only an accreditation authority (or a
    /// government) may grant an accreditation.
    #[allow(clippy::too_many_arguments)] // the grant's fields are the pyramid's edge
    pub fn issue(
        accredited: &str,
        authority: &str,
        version: u64,
        scope: Vec<String>,
        schemes: Vec<String>,
        valid_from: &str,
        valid_to: Option<&str>,
        key: &KeyPair,
    ) -> Result<AccreditationObject, SignatifError> {
        let mut w = CanonicalWriter::new();
        w.write_bytes(accredited.as_bytes());
        w.write_bytes(authority.as_bytes());
        w.write_bytes(&version.to_le_bytes());
        let join = |values: &[String]| {
            let mut sorted: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
            sorted.sort();
            sorted.join("\u{1f}").into_bytes()
        };
        let scope_joined = join(&scope);
        let schemes_joined = join(&schemes);
        w.write_bytes(&scope_joined);
        w.write_bytes(&schemes_joined);
        w.write_bytes(valid_from.as_bytes());
        w.write_bytes(valid_to.unwrap_or("").as_bytes());
        let payload = w.into_bytes();
        let signature = SignatureSlot::sign(key, SigningDomain::Accreditation, &payload)?;
        Ok(AccreditationObject {
            accredited: accredited.into(),
            authority: authority.into(),
            version,
            scope,
            schemes,
            valid_from: valid_from.into(),
            valid_to: valid_to.map(Into::into),
            signature,
        })
    }

    /// Verify under the graph: the signature must resolve to the
    /// DECLARED authority's key.
    pub fn verify(&self, graph: &TrustGraph) -> Result<(), SignatifError> {
        let node = NodeId::new(&self.authority)
            .map_err(|e| SignatifError::crypto(format!("accreditation authority: {e}")))?;
        let public = graph
            .node(&node)
            .and_then(|n| n.key(&self.signature.key_id))
            .ok_or_else(|| {
                SignatifError::crypto(format!(
                    "accreditation authority `{}` has no such key",
                    self.authority
                ))
            })?;
        self.signature.verify(
            SigningDomain::Accreditation,
            &self.canonical_bytes(),
            public,
        )
    }

    /// Liveness at `at`: inside the effective window (absent end =
    /// open-ended). A malformed instant is a stated failure.
    pub fn live_at(&self, at: &str) -> Result<bool, SignatifError> {
        let now = Timestamp::parse(at)
            .map_err(|e| SignatifError::Validation(format!("liveness instant: {e}")))?;
        let from = Timestamp::parse(&self.valid_from)
            .map_err(|e| SignatifError::Validation(format!("window start: {e}")))?;
        if let Some(to) = &self.valid_to {
            let to = Timestamp::parse(to)
                .map_err(|e| SignatifError::Validation(format!("window end: {e}")))?;
            return Ok(now >= from && now <= to);
        }
        Ok(now >= from)
    }

    /// Whether the accredited scope covers `what` (exact scope
    /// entry or the wildcard `*`).
    pub fn covers(&self, what: &str) -> bool {
        self.scope.iter().any(|s| s == what || s == "*")
    }
}

/// The graded standing of a C-class signature's accreditation
/// chain, at use time.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccreditationStanding {
    /// Live: the chain verifies and the window holds.
    Live,
    /// Expired: the chain verifies but the window has passed —
    /// graded degradation, the chain named.
    Expired {
        /// The authority whose grant lapsed.
        authority: String,
        /// The grant's window end.
        valid_to: String,
    },
    /// No admissible accreditation at all — stated, never silent.
    Missing {
        /// Why (not found, wrong class, failed verification).
        reason: String,
    },
}

/// The use-time liveness check (TR-9's verify clause): given the
/// grants the verifier holds and a C-class signer, grade the
/// standing of its accreditation at `at`, naming the chain. The
/// degradation is graded, never boolean.
pub fn standing_at(
    grants: &[AccreditationObject],
    accredited: &str,
    at: &str,
    graph: &TrustGraph,
) -> AccreditationStanding {
    let candidates: Vec<&AccreditationObject> = grants
        .iter()
        .filter(|g| g.accredited == accredited)
        .collect();
    if candidates.is_empty() {
        return AccreditationStanding::Missing {
            reason: format!("no accreditation grant held for `{accredited}`"),
        };
    }
    // The latest version whose signature verifies under the graph.
    let mut admissible: Vec<&AccreditationObject> = Vec::new();
    for grant in &candidates {
        if grant.verify(graph).is_ok() {
            admissible.push(grant);
        }
    }
    if admissible.is_empty() {
        return AccreditationStanding::Missing {
            reason: format!(
                "every held grant for `{accredited}` fails verification under this \
                 verifier's anchors"
            ),
        };
    }
    admissible.sort_by_key(|g| g.version);
    let latest = admissible.last().expect("non-empty");
    match latest.live_at(at) {
        Ok(true) => AccreditationStanding::Live,
        Ok(false) => AccreditationStanding::Expired {
            authority: latest.authority.clone(),
            valid_to: latest
                .valid_to
                .clone()
                .unwrap_or_else(|| "open-ended".into()),
        },
        Err(e) => AccreditationStanding::Missing {
            reason: e.to_string(),
        },
    }
}

/// The pyramid edge at issue time: the grant itself must be signed
/// by a party whose class may accredit (the matrix's A→C edge).
pub fn check_grant_class(authority_party: PartyClass) -> Result<(), SignatifError> {
    intake_permits(authority_party, ObjectClass::Accreditation)
}

/// New signing domain for accreditation grants — carried by the
/// domain registry of Annex B (the Accreditation row).
pub const ACCREDITATION_DOMAIN_TAG: &str = "UNIDPP-SIGNATIF/ACCREDITATION";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{DelegationNode, NodeKind, RegisteredKey};
    use crate::keyring::KeyId;
    use crate::sign::Suite;

    fn cast() -> (TrustGraph, KeyPair) {
        let authority = KeyPair::seeded(Suite::Ed25519, b"accred/cnas").unwrap();
        let lab = KeyPair::seeded(Suite::Ed25519, b"accred/lab").unwrap();
        let mut graph = TrustGraph::new();
        for (id, key, party) in [
            ("cnas", &authority, Some(PartyClass::AccreditationAuthority)),
            ("cn-bms-lab", &lab, Some(PartyClass::ConformityBody)),
        ] {
            let mut node = DelegationNode::new(NodeId::new(id).unwrap(), NodeKind::Delegated);
            node.party = party;
            node.register(RegisteredKey {
                key_id: KeyId::of(key.public()),
                public: *key.public(),
            });
            graph.add_node(node);
        }
        (graph, authority)
    }

    fn grant(key: &KeyPair, valid_to: Option<&str>) -> AccreditationObject {
        AccreditationObject::issue(
            "cn-bms-lab",
            "cnas",
            1,
            vec!["battery-bms".into(), "cell-safety".into()],
            vec!["sm2".into(), "ed25519".into()],
            "2027-01-01T00:00:00Z",
            valid_to,
            key,
        )
        .unwrap()
    }

    // TR-9's verify: a live chain passes; an expired accreditation
    // DEGRADES the verdict naming the chain; absence is stated.
    #[test]
    fn liveness_degrades_expired_chains_naming_them() {
        let (graph, key) = cast();
        let live = grant(&key, Some("2030-12-31T23:59:59Z"));
        assert_eq!(
            standing_at(
                &[live.clone()],
                "cn-bms-lab",
                "2030-06-01T00:00:00Z",
                &graph
            ),
            AccreditationStanding::Live
        );

        let expired = grant(&key, Some("2030-01-01T00:00:00Z"));
        match standing_at(&[expired], "cn-bms-lab", "2030-06-01T00:00:00Z", &graph) {
            AccreditationStanding::Expired {
                authority,
                valid_to,
            } => {
                assert_eq!(authority, "cnas");
                assert_eq!(valid_to, "2030-01-01T00:00:00Z");
            }
            other => panic!("expected expired, got {other:?}"),
        }

        match standing_at(&[], "cn-bms-lab", "2030-06-01T00:00:00Z", &graph) {
            AccreditationStanding::Missing { reason } => {
                assert!(reason.contains("cn-bms-lab"), "{reason}")
            }
            other => panic!("expected missing, got {other:?}"),
        }
    }

    // The grant's class gate: an A (or G) may accredit; a C may
    // not; scope coverage is exact-or-wildcard; supersession takes
    // the latest admissible version; canonical bytes are
    // order-insensitive over scope and schemes.
    #[test]
    fn grants_are_class_bound_scope_checked_and_superseding() {
        let (graph, key) = cast();
        assert!(check_grant_class(PartyClass::AccreditationAuthority).is_ok());
        assert!(check_grant_class(PartyClass::Government).is_ok());
        assert!(check_grant_class(PartyClass::ConformityBody).is_err());

        let g = grant(&key, None);
        assert!(g.covers("battery-bms"));
        assert!(!g.covers("medical-devices"));
        assert!(g.verify(&graph).is_ok());

        // Wrong key: stated missing.
        let impostor = KeyPair::seeded(Suite::Ed25519, b"accred/impostor").unwrap();
        let forged = grant(&impostor, None);
        match standing_at(&[forged], "cn-bms-lab", "2030-06-01T00:00:00Z", &graph) {
            AccreditationStanding::Missing { reason } => {
                assert!(reason.contains("fails verification"), "{reason}")
            }
            other => panic!("expected missing, got {other:?}"),
        }

        // v2 supersedes v1: the latest admissible version governs.
        let v1 = AccreditationObject::issue(
            "cn-bms-lab",
            "cnas",
            1,
            vec!["battery-bms".into()],
            vec!["ed25519".into()],
            "2027-01-01T00:00:00Z",
            Some("2031-01-01T00:00:00Z"),
            &key,
        )
        .unwrap();
        let v2 = AccreditationObject::issue(
            "cn-bms-lab",
            "cnas",
            2,
            vec!["battery-bms".into()],
            vec!["ed25519".into()],
            "2027-01-01T00:00:00Z",
            Some("2029-01-01T00:00:00Z"),
            &key,
        )
        .unwrap();
        assert_eq!(
            standing_at(&[v1, v2], "cn-bms-lab", "2030-06-01T00:00:00Z", &graph),
            AccreditationStanding::Expired {
                authority: "cnas".into(),
                valid_to: "2029-01-01T00:00:00Z".into(),
            }
        );

        // Canonical bytes: scope/scheme order does not matter.
        let a = AccreditationObject::issue(
            "c",
            "a",
            1,
            vec!["x".into(), "y".into()],
            vec!["s1".into(), "s2".into()],
            "2027-01-01T00:00:00Z",
            None,
            &key,
        )
        .unwrap();
        let mut b = AccreditationObject::issue(
            "c",
            "a",
            1,
            vec!["y".into(), "x".into()],
            vec!["s2".into(), "s1".into()],
            "2027-01-01T00:00:00Z",
            None,
            &key,
        )
        .unwrap();
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
        assert_eq!(a.digest(), b.digest());
        b.scope.clear();
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
    }
}
