//! The party model (TR-1, ARCHITECTURE §2): nine party classes with
//! signer-class semantics, and the signing matrix — which party
//! class may sign which object class — as a first-class table
//! consulted at intake.
//!
//! Party class is orthogonal to node kind (a Root or a Delegated
//! node may equally be a regulator or a manufacturer): the class
//! states the node's ROLE in the world; the signing matrix states
//! what that role may put its key behind. An out-of-class signature
//! is refused at intake with both classes named — a perfectly valid
//! signature from the wrong role is not the object it claims to be.

use crate::graph::{DelegationNode, NodeId, TrustGraph};
use crate::SignatifError;

/// The nine party classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PartyClass {
    /// Government / regulator: legal duty, accreditation,
    /// market surveillance.
    Government,
    /// International standardization or treaty body: harmonized
    /// profiles, master-list witnessing.
    InternationalBody,
    /// Accreditation authority: accredits conformity bodies (the
    /// A of the A→C→B pyramid).
    AccreditationAuthority,
    /// Conformity-assessment body: issues conformity evidence (the
    /// C of the pyramid).
    ConformityBody,
    /// Product manufacturer: self-declarations, custody of the
    /// product's spine.
    Manufacturer,
    /// Verifier / market-surveillance reader: requests, reports.
    Verifier,
    /// Bearer / owner: owner-push data (no signed object class
    /// yet — stated, not silent).
    Bearer,
    /// Operator: runs infrastructure (custody, relays, declarations
    /// of serving posture).
    Operator,
    /// Update actor: dynamic-data attestations at the edge (S2/S3
    /// origins).
    UpdateActor,
}

impl PartyClass {
    /// The stable token.
    pub fn token(self) -> &'static str {
        match self {
            PartyClass::Government => "government",
            PartyClass::InternationalBody => "international-body",
            PartyClass::AccreditationAuthority => "accreditation-authority",
            PartyClass::ConformityBody => "conformity-body",
            PartyClass::Manufacturer => "manufacturer",
            PartyClass::Verifier => "verifier",
            PartyClass::Bearer => "bearer",
            PartyClass::Operator => "operator",
            PartyClass::UpdateActor => "update-actor",
        }
    }
}

/// The object classes a signature can attest (the typed objects of
/// the seam; each maps to a signing domain of Annex B, Table B.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObjectClass {
    /// A segment policy object (the segment's constitution).
    SegmentPolicy,
    /// A commitment spine root.
    SpineRoot,
    /// A profile manifest (requirement set / self-declaration).
    Profile,
    /// An S13 message (request or response).
    S13Message,
    /// A sovereign attestation (substitution evidence).
    SovereignAttestation,
    /// A master-list witness attestation.
    MasterListWitness,
    /// An accreditation grant (the A→C edge of the pyramid).
    Accreditation,
    /// An interop declaration (published posture).
    InteropDeclaration,
    /// A hub's faithful-relay attestation.
    HubRelay,
}

impl ObjectClass {
    /// The stable token.
    pub fn token(self) -> &'static str {
        match self {
            ObjectClass::SegmentPolicy => "segment-policy",
            ObjectClass::SpineRoot => "spine-root",
            ObjectClass::Profile => "profile",
            ObjectClass::S13Message => "s13-message",
            ObjectClass::SovereignAttestation => "sovereign-attestation",
            ObjectClass::MasterListWitness => "master-list-witness",
            ObjectClass::Accreditation => "accreditation",
            ObjectClass::InteropDeclaration => "interop-declaration",
            ObjectClass::HubRelay => "hub-relay",
        }
    }
}

/// The signing matrix: the object classes each party class may
/// sign. First-class data — adding an object class extends the
/// table, never the checking code.
pub fn signing_matrix() -> &'static [(PartyClass, &'static [ObjectClass])] {
    &[
        // A regulator legislates: constitutions of segments,
        // accreditations, and the witnessing of master lists.
        (
            PartyClass::Government,
            &[
                ObjectClass::SegmentPolicy,
                ObjectClass::Accreditation,
                ObjectClass::MasterListWitness,
            ],
        ),
        // An international body harmonizes: profiles and the
        // witnessing of master lists.
        (
            PartyClass::InternationalBody,
            &[ObjectClass::Profile, ObjectClass::MasterListWitness],
        ),
        // An accreditation authority accredits (and witnesses the
        // lists its accredited bodies appear on).
        (
            PartyClass::AccreditationAuthority,
            &[ObjectClass::Accreditation, ObjectClass::MasterListWitness],
        ),
        // A conformity body issues conformity evidence.
        (
            PartyClass::ConformityBody,
            &[ObjectClass::SovereignAttestation],
        ),
        // A manufacturer self-declares, custodies the spine, and
        // answers S13 as custodian.
        (
            PartyClass::Manufacturer,
            &[
                ObjectClass::Profile,
                ObjectClass::SpineRoot,
                ObjectClass::S13Message,
            ],
        ),
        // A verifier asks (signs requests) and files reports.
        (PartyClass::Verifier, &[ObjectClass::S13Message]),
        // A bearer pushes owner data; no bearer-signed object class
        // is defined yet — the matrix states this by absence.
        (PartyClass::Bearer, &[]),
        // An operator custodies infrastructure: spines it holds,
        // relays it runs, serving postures it publishes.
        (
            PartyClass::Operator,
            &[
                ObjectClass::SpineRoot,
                ObjectClass::S13Message,
                ObjectClass::InteropDeclaration,
                ObjectClass::HubRelay,
            ],
        ),
        // An update actor attests dynamic data at the edge.
        (
            PartyClass::UpdateActor,
            &[ObjectClass::SovereignAttestation],
        ),
    ]
}

/// The intake check (TR-2): may a signer of `party` class sign an
/// object of `object` class? Refusals name both classes.
pub fn intake_permits(party: PartyClass, object: ObjectClass) -> Result<(), SignatifError> {
    let row = signing_matrix()
        .iter()
        .find(|(class, _)| *class == party)
        .expect("the matrix covers every party class");
    if row.1.contains(&object) {
        Ok(())
    } else {
        Err(SignatifError::Validation(format!(
            "signing matrix: a `{}` may not sign a `{}` — out-of-class signature \
             refused at intake",
            party.token(),
            object.token()
        )))
    }
}

/// The declared party class of a graph node (None: undeclared —
/// the caller decides whether undeclared signers are admissible).
pub fn party_of(graph: &TrustGraph, node: &NodeId) -> Option<PartyClass> {
    graph.node(node).and_then(|n| n.party)
}

/// Declare a node's party class (the model hook the intake check
/// and the pyramid checks consult).
pub fn declare_party(node: &mut DelegationNode, party: PartyClass) {
    node.party = Some(party);
}

#[cfg(test)]
mod tests {
    use super::*;

    // TR-2's verify: out-of-class signature refused at intake with
    // the class named; in-class passes for every row.
    #[test]
    fn the_matrix_admits_and_refuses_by_class() {
        // Every matrix row's allowance passes.
        for (party, objects) in signing_matrix() {
            for object in *objects {
                intake_permits(*party, *object)
                    .unwrap_or_else(|e| panic!("{party:?} → {object:?}: {e}"));
            }
        }
        // Out-of-class refusals name both sides.
        let err = intake_permits(PartyClass::Manufacturer, ObjectClass::SegmentPolicy)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("manufacturer") && err.contains("segment-policy"),
            "{err}"
        );
        let err = intake_permits(PartyClass::ConformityBody, ObjectClass::InteropDeclaration)
            .unwrap_err()
            .to_string();
        assert!(err.contains("conformity-body"), "{err}");
        // The bearer signs nothing yet — stated by the matrix.
        assert!(intake_permits(PartyClass::Bearer, ObjectClass::S13Message).is_err());
        // The pyramid's edges are class-bound: only A (or G, I)
        // accredits; only C attests conformity evidence.
        assert!(intake_permits(
            PartyClass::AccreditationAuthority,
            ObjectClass::Accreditation
        )
        .is_ok());
        assert!(intake_permits(PartyClass::Manufacturer, ObjectClass::Accreditation).is_err());
        assert!(intake_permits(
            PartyClass::ConformityBody,
            ObjectClass::SovereignAttestation
        )
        .is_ok());
        assert!(intake_permits(PartyClass::Verifier, ObjectClass::SovereignAttestation).is_err());
    }

    // The class is carried on the node and orthogonal to kind.
    #[test]
    fn party_class_rides_the_node() {
        use crate::graph::{NodeKind, RegisteredKey};
        use crate::keyring::{KeyId, KeyPair};
        use crate::sign::Suite;
        let key = KeyPair::seeded(Suite::Ed25519, b"party/lab").unwrap();
        let mut node = DelegationNode::new(NodeId::new("cn-bms-lab").unwrap(), NodeKind::Delegated);
        declare_party(&mut node, PartyClass::ConformityBody);
        node.register(RegisteredKey {
            key_id: KeyId::of(key.public()),
            public: *key.public(),
        });
        let mut graph = TrustGraph::new();
        graph.add_node(node);
        assert_eq!(
            party_of(&graph, &NodeId::new("cn-bms-lab").unwrap()),
            Some(PartyClass::ConformityBody)
        );
        // An undeclared node is stated as such.
        let other = DelegationNode::new(NodeId::new("stranger").unwrap(), NodeKind::End);
        let mut g2 = TrustGraph::new();
        g2.add_node(other);
        assert_eq!(party_of(&g2, &NodeId::new("stranger").unwrap()), None);
    }
}
