//! Provenance coverage (SI-6): chain traversal renders
//! verified-direct / attested / gap coverage over the ANCESTRY.
//!
//! The subject's data classes are graded per element (XB-8); the
//! ancestry is graded per EDGE: walking the relationship graph
//! upstream, each edge renders verified-direct (open evidence seen),
//! attested-by-authority (sealed upstream, substitution accepted) or
//! a stated gap (missing or unresolvable edge) — the correct
//! three-way report over a mixed chain. The traversal is a pure
//! function of the edge graph and the evidence the verifier holds
//! (open/closed: evidence SOURCING is the caller's concern; this
//! module grades what arrived).

use crate::graph::TrustGraph;
use crate::sovereign::SovereignAttestation;
use unidpp_s13::coverage::EvidenceKind;

/// One edge of the ancestry graph (an R1–R7 relationship, upstream
/// direction: ancestor → descendant).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AncestryEdge {
    /// The upstream passport.
    pub ancestor: String,
    /// The downstream passport.
    pub descendant: String,
    /// The relationship token (derivation, installation, membership…).
    pub relationship: String,
}

/// The evidence the verifier holds for one upstream edge.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)] // a one-shot traversal input, not a hot path
pub enum EdgeEvidence {
    /// Open-class evidence: the ancestor's contents were served.
    Open {
        /// The ancestor's open state bytes.
        bytes: Vec<u8>,
    },
    /// Sealed upstream: a sovereign attestation ABOUT the ancestor.
    Sealed {
        /// The attestation substituting for the sealed ancestor.
        attestation: SovereignAttestation,
    },
    /// No admissible evidence: the edge is a stated gap.
    Missing {
        /// Why (unresolvable, refused, outage…).
        reason: String,
    },
}

/// One graded edge of the traversal.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GradedEdge {
    /// The edge as traversed.
    pub edge: AncestryEdge,
    /// The edge's coverage.
    pub coverage: EvidenceKind,
    /// The reading: what was seen, who attested, or why the gap is
    /// stated.
    pub reading: String,
}

/// The provenance coverage report: every upstream edge, graded —
/// the three-way report over the ancestry.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProvenanceCoverage {
    /// The subject whose ancestry was traversed.
    pub subject: String,
    /// The graded edges, breadth-first from the subject.
    pub edges: Vec<GradedEdge>,
}

impl ProvenanceCoverage {
    /// The one-line rendering (the same summary shape as the
    /// data-class coverage report).
    pub fn summary(&self) -> String {
        let parts: Vec<String> = self
            .edges
            .iter()
            .map(|g| {
                format!(
                    "{}→{} ({}): {}",
                    short_id(&g.edge.ancestor),
                    short_id(&g.edge.descendant),
                    g.edge.relationship,
                    g.coverage.token()
                )
            })
            .collect();
        format!("ancestry of {}: {}", self.subject, parts.join(" | "))
    }
}

fn short_id(id: &str) -> String {
    id.rsplit('/').next().unwrap_or(id).to_string()
}

/// Traverse the ancestry upstream from `subject`, grading each edge
/// by the evidence the caller holds for it. Pure and visited-safe
/// (cycles in the edge graph cannot loop the traversal); edges
/// reachable through a graded gap are still traversed (a gap in the
/// chain does not hide the rest — it is stated, and the walk
/// continues with what else is reachable).
pub fn traverse(
    subject: &str,
    graph: &[AncestryEdge],
    evidence_for: impl Fn(&AncestryEdge) -> EdgeEvidence,
    trust: &TrustGraph,
) -> ProvenanceCoverage {
    let mut edges = Vec::new();
    let mut visited: Vec<String> = vec![subject.into()];
    let mut frontier: Vec<String> = vec![subject.into()];
    while let Some(current) = frontier.pop() {
        for edge in graph.iter().filter(|e| e.descendant == current) {
            if visited.contains(&edge.ancestor) {
                continue;
            }
            visited.push(edge.ancestor.clone());
            frontier.push(edge.ancestor.clone());
            let graded = match evidence_for(edge) {
                EdgeEvidence::Open { bytes } => GradedEdge {
                    edge: edge.clone(),
                    coverage: EvidenceKind::VerifiedDirect,
                    reading: format!("open evidence ({} bytes) seen", bytes.len()),
                },
                EdgeEvidence::Sealed { attestation } => match attestation.verify(trust) {
                    Ok(_) => GradedEdge {
                        edge: edge.clone(),
                        coverage: EvidenceKind::AttestedByAuthority,
                        reading: format!(
                            "sealed upstream; attested by `{}` (as of {})",
                            attestation.service, attestation.statement.as_of
                        ),
                    },
                    Err(e) => GradedEdge {
                        edge: edge.clone(),
                        coverage: EvidenceKind::ExplicitlyUnavailable,
                        reading: format!("attestation does not verify: {e}"),
                    },
                },
                EdgeEvidence::Missing { reason } => GradedEdge {
                    edge: edge.clone(),
                    coverage: EvidenceKind::ExplicitlyUnavailable,
                    reading: reason,
                },
            };
            edges.push(graded);
        }
    }
    ProvenanceCoverage {
        subject: subject.into(),
        edges,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{DelegationNode, NodeId, NodeKind, RegisteredKey};
    use crate::keyring::{KeyId, KeyPair};
    use crate::sign::Suite;
    use crate::sovereign::{AttestationStatement, ClaimClass};

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

    fn service_key() -> KeyPair {
        KeyPair::seeded(Suite::Ed25519, b"prov/cn-attest").unwrap()
    }

    fn attestation(service: &KeyPair) -> SovereignAttestation {
        SovereignAttestation::issue(
            AttestationStatement {
                segment: "supplier-dynamic".into(),
                state_commitment: [3u8; 32],
                claim: ClaimClass::Freshness,
                value: "within-window".into(),
                as_of: "2030-06-01T08:00:00Z".into(),
                governing_policy: "supplier-sealed".into(),
                governing_policy_version: 1,
                subject: "urn:unidpp:passport:supplier-module".into(),
            },
            "cn-attestation-service",
            service,
            None,
        )
        .unwrap()
    }

    fn battery_ancestry() -> Vec<AncestryEdge> {
        vec![
            AncestryEdge {
                ancestor: "urn:unidpp:passport:cell-lot-h2231".into(),
                descendant: "urn:unidpp:passport:pack-0001".into(),
                relationship: "derivation".into(),
            },
            AncestryEdge {
                ancestor: "urn:unidpp:passport:supplier-module".into(),
                descendant: "urn:unidpp:passport:pack-0001".into(),
                relationship: "installation".into(),
            },
            AncestryEdge {
                ancestor: "urn:unidpp:passport:recycled-input".into(),
                descendant: "urn:unidpp:passport:supplier-module".into(),
                relationship: "derivation".into(),
            },
        ]
    }

    // SI-6's verify: a mixed chain — open edge, sealed edge, missing
    // edge — produces exactly the three-way report.
    #[test]
    fn a_mixed_chain_produces_the_three_way_report() {
        let service = service_key();
        let trust = graph_with(&[("cn-attestation-service", &service)]);
        let attestation = attestation(&service);
        let edges = battery_ancestry();
        let coverage = traverse(
            "urn:unidpp:passport:pack-0001",
            &edges,
            |edge| {
                if edge.ancestor.contains("cell-lot") {
                    EdgeEvidence::Open {
                        bytes: b"lot=H-2231,chemistry=LFP".to_vec(),
                    }
                } else if edge.ancestor.contains("supplier-module") {
                    EdgeEvidence::Sealed {
                        attestation: attestation.clone(),
                    }
                } else {
                    EdgeEvidence::Missing {
                        reason: "no admissible evidence: the recycled-input edge is \
                                 unresolvable from this verifier"
                            .into(),
                    }
                }
            },
            &trust,
        );

        assert_eq!(coverage.edges.len(), 3);
        let by_ancestor = |frag: &str| {
            coverage
                .edges
                .iter()
                .find(|g| g.edge.ancestor.contains(frag))
                .unwrap_or_else(|| panic!("edge for {frag} missing"))
        };
        assert_eq!(
            by_ancestor("cell-lot").coverage,
            EvidenceKind::VerifiedDirect
        );
        assert_eq!(
            by_ancestor("supplier-module").coverage,
            EvidenceKind::AttestedByAuthority
        );
        assert_eq!(
            by_ancestor("recycled-input").coverage,
            EvidenceKind::ExplicitlyUnavailable
        );
        assert!(coverage.summary().contains("verified-direct"));
        assert!(coverage.summary().contains("attested-by-authority"));
        assert!(coverage.summary().contains("explicitly-unavailable"));
    }

    // A sealed edge whose attestation does not verify is a stated
    // gap, never a pass.
    #[test]
    fn unverified_attestations_are_stated_gaps() {
        let service = service_key();
        let wrong_graph = graph_with(&[(
            "unrelated",
            &KeyPair::seeded(Suite::Ed25519, b"prov/none").unwrap(),
        )]);
        let attestation = attestation(&service);
        let edges = battery_ancestry();
        let coverage = traverse(
            "urn:unidpp:passport:pack-0001",
            &edges,
            |edge| {
                if edge.ancestor.contains("supplier-module") {
                    EdgeEvidence::Sealed {
                        attestation: attestation.clone(),
                    }
                } else {
                    EdgeEvidence::Missing {
                        reason: "not held".into(),
                    }
                }
            },
            &wrong_graph,
        );
        let supplier = coverage
            .edges
            .iter()
            .find(|g| g.edge.ancestor.contains("supplier-module"))
            .unwrap();
        assert_eq!(supplier.coverage, EvidenceKind::ExplicitlyUnavailable);
        assert!(supplier.reading.contains("does not verify"));
    }

    // The walk is visited-safe: a cycle in the edge graph cannot
    // loop the traversal.
    #[test]
    fn cycles_cannot_loop_the_traversal() {
        let cyclic = vec![
            AncestryEdge {
                ancestor: "urn:unidpp:passport:a".into(),
                descendant: "urn:unidpp:passport:b".into(),
                relationship: "derivation".into(),
            },
            AncestryEdge {
                ancestor: "urn:unidpp:passport:b".into(),
                descendant: "urn:unidpp:passport:a".into(),
                relationship: "derivation".into(),
            },
        ];
        let trust = graph_with(&[]);
        let coverage = traverse(
            "urn:unidpp:passport:a",
            &cyclic,
            |_| EdgeEvidence::Missing {
                reason: "gap".into(),
            },
            &trust,
        );
        assert_eq!(coverage.edges.len(), 1, "each edge graded once");
    }
}
