//! The scheme-calculus surface (SI-4/5/7/13): recognition modes,
//! declared harmonization levels, algebra portability, and bridge
//! freshness.
//!
//! MECE with the rest: declarations (declaration.rs) own the
//! published posture; transport (transport.rs) owns delivery; this
//! module owns the RECOGNITION question (by what mode is a
//! counterpart's object class recognized here), the LEVEL question
//! (what the pair's declared levels imply per class — direct versus
//! substituted behaviour), the PORTABILITY question (a foreign
//! scheme resolving a composite event's structure through bridged
//! identities without the origin's semantics), and the FRESHNESS
//! question (a stale bridge degrades exactly its covered classes).

use crate::declaration::{DeclarationSet, HarmonizationLevel, RecognitionMode, TransportMode};
use crate::graph::{NodeId, TrustGraph};
use crate::keyring::KeyPair;
use crate::party::ObjectClass;
use crate::sign::{SignatureSlot, SigningDomain};
use crate::SignatifError;
use unidpp_model::time::Timestamp;
use unidpp_model::{sha256, CanonicalWriter};

// ---------------------------------------------------------------------------
// SI-4 — recognition modes, per object class
// ---------------------------------------------------------------------------

/// What a recognition check concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recognition {
    /// Recognized under the named mode.
    Recognized(RecognitionMode),
    /// Not recognized — the reason is stated.
    Refused {
        /// Why (not pinned, not on the list, out of class).
        reason: String,
    },
}

/// A club list: a signed roster of recognized anchors, operated by
/// a club operator (SI-4's third mode).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ClubList {
    /// The club's name.
    pub club: String,
    /// The object classes the list covers.
    pub object_classes: Vec<ObjectClass>,
    /// The recognized counterpart anchors (node ids).
    pub members: Vec<String>,
    /// The operator's signature.
    pub signature: SignatureSlot,
}

impl ClubList {
    /// What the operator signs.
    fn payload(club: &str, object_classes: &[ObjectClass], members: &[String]) -> Vec<u8> {
        let mut w = CanonicalWriter::new();
        w.write_bytes(club.as_bytes());
        let mut classes: Vec<&str> = object_classes.iter().map(|c| c.token()).collect();
        classes.sort();
        for c in classes {
            w.write_bytes(c.as_bytes());
        }
        let mut members = members.to_vec();
        members.sort();
        for m in &members {
            w.write_bytes(m.as_bytes());
        }
        w.into_bytes()
    }

    /// Issue (the club operator signs).
    pub fn issue(
        club: &str,
        object_classes: Vec<ObjectClass>,
        members: Vec<String>,
        operator_key: &KeyPair,
    ) -> Result<ClubList, SignatifError> {
        let payload = Self::payload(club, &object_classes, &members);
        let signature =
            SignatureSlot::sign(operator_key, SigningDomain::MasterListWitness, &payload)?;
        Ok(ClubList {
            club: club.into(),
            object_classes,
            members,
            signature,
        })
    }

    /// Verify the operator's signature under the graph.
    pub fn verify(&self, operator: &str, graph: &TrustGraph) -> Result<(), SignatifError> {
        let node = NodeId::new(operator)
            .map_err(|e| SignatifError::crypto(format!("club operator: {e}")))?;
        let public = graph
            .node(&node)
            .and_then(|n| n.key(&self.signature.key_id))
            .ok_or_else(|| {
                SignatifError::crypto(format!("club operator `{operator}` has no such key"))
            })?;
        let payload = Self::payload(&self.club, &self.object_classes, &self.members);
        self.signature
            .verify(SigningDomain::MasterListWitness, &payload, public)
    }

    /// Membership, class-scoped.
    pub fn recognizes(&self, object: ObjectClass, counterpart: &str) -> bool {
        self.object_classes.contains(&object) && self.members.iter().any(|m| m == counterpart)
    }
}

/// The recognition check (SI-4): is `counterpart`'s object of
/// `object` class recognized here, under the declared mode? The
/// inputs are the declared mode and the mode's machinery (pinned
/// anchors, club list, master-list membership).
pub fn recognize(
    mode: RecognitionMode,
    object: ObjectClass,
    counterpart: &str,
    counterpart_pinned_here: bool,
    here_pinned_there: bool,
    club: Option<&ClubList>,
    on_master_list: bool,
) -> Recognition {
    match mode {
        RecognitionMode::UnilateralPinning => {
            if counterpart_pinned_here {
                Recognition::Recognized(mode)
            } else {
                Recognition::Refused {
                    reason: format!(
                        "unilateral pinning: `{counterpart}`'s anchor is not pinned by this \
                         verifier"
                    ),
                }
            }
        }
        RecognitionMode::BilateralAnchors => {
            if counterpart_pinned_here && here_pinned_there {
                Recognition::Recognized(mode)
            } else {
                Recognition::Refused {
                    reason: format!(
                        "bilateral anchors: the exchange is incomplete (`{counterpart}` \
                         pinned here: {counterpart_pinned_here}; this verifier pinned \
                         there: {here_pinned_there})"
                    ),
                }
            }
        }
        RecognitionMode::ClubList => match club {
            Some(list) if list.recognizes(object, counterpart) => Recognition::Recognized(mode),
            Some(_) => Recognition::Refused {
                reason: format!(
                    "club list: `{counterpart}` or object class `{}` is not on the list",
                    object.token()
                ),
            },
            None => Recognition::Refused {
                reason: "club list: no list held".into(),
            },
        },
        RecognitionMode::MasterListMesh => {
            if on_master_list {
                Recognition::Recognized(mode)
            } else {
                Recognition::Refused {
                    reason: format!(
                        "master-list mesh: `{counterpart}` is not on the multi-witnessed \
                         master list"
                    ),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SI-5 — declared harmonization levels, machine-queryable
// ---------------------------------------------------------------------------

/// The declared level for one class of one pair (the minimum of the
/// two sides' declarations; None: undeclared — stated).
pub fn declared_level(
    declarations: &DeclarationSet,
    here: &str,
    counterpart: &str,
    data_class: &str,
) -> Option<HarmonizationLevel> {
    let here_declared = declarations
        .latest_for(here, counterpart)
        .and_then(|d| d.posture_for(data_class))
        .map(|p| p.level);
    let there_declared = declarations
        .latest_for(counterpart, here)
        .and_then(|d| d.posture_for(data_class))
        .map(|p| p.level);
    match (here_declared, there_declared) {
        (Some(a), Some(b)) => Some(if a.ordinal() < b.ordinal() { a } else { b }),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// What the declared level implies for behaviour on that class:
/// L3+ structural mapping means DIRECT evidence may flow; L1–L2
/// means DOCUMENT substitution; L0 or undeclared means a stated gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassBehaviour {
    /// Structures map: direct evidence.
    Direct,
    /// Documents (frozen views) substitute: no structural mapping.
    Substituted,
    /// A stated gap.
    Gap,
}

/// The machine-queryable behaviour per class (SI-5's verify: a
/// mixed-level relationship drives different behaviour per class).
pub fn behaviour_for_level(level: Option<HarmonizationLevel>) -> ClassBehaviour {
    match level {
        Some(l) if l.ordinal() >= 3 => ClassBehaviour::Direct,
        Some(l) if l.ordinal() >= 1 => ClassBehaviour::Substituted,
        _ => ClassBehaviour::Gap,
    }
}

// ---------------------------------------------------------------------------
// SI-7 — algebra portability
// ---------------------------------------------------------------------------

/// A bridged identity: the same subject in a foreign scheme's
/// identifier space, through a registered bridge.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BridgedIdentity {
    /// The origin scheme's identifier.
    pub origin: String,
    /// The foreign scheme's identifier.
    pub foreign: String,
    /// The registered bridge item (the mapping reference).
    pub bridge: String,
}

/// A portable composite statement: what a transformation or
/// installation asserts, expressed so a foreign scheme can resolve
/// its structure WITHOUT the origin's semantics — every input is
/// either an origin identifier (resolvable through the bridge
/// table) or already a bridged identity, and the transformation is
/// a REGISTERED transform reference.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PortableStatement {
    /// The statement kind (combine / split / install…).
    pub kind: String,
    /// The registered transform reference (versioned, cited).
    pub transform: String,
    /// The inputs, as origin identifiers.
    pub inputs: Vec<String>,
    /// The output identity (bridged for the foreign scheme).
    pub output: BridgedIdentity,
}

impl PortableStatement {
    /// Resolve the statement's structure for a foreign verifier:
    /// each input is mapped through the bridge table; the transform
    /// reference is carried verbatim. The foreign scheme needs no
    /// origin semantics — only the bridge table and the transform
    /// registry entry.
    pub fn resolve(&self, bridges: &[BridgedIdentity]) -> Result<ResolvedStatement, SignatifError> {
        let mut inputs = Vec::with_capacity(self.inputs.len());
        for input in &self.inputs {
            let bridged = bridges.iter().find(|b| &b.origin == input).ok_or_else(|| {
                SignatifError::Validation(format!(
                    "portability: input `{input}` has no bridge entry — the foreign \
                         scheme cannot resolve the structure"
                ))
            })?;
            inputs.push(bridged.foreign.clone());
        }
        Ok(ResolvedStatement {
            kind: self.kind.clone(),
            transform: self.transform.clone(),
            inputs,
            output: self.output.foreign.clone(),
        })
    }
}

/// The structure as a foreign scheme sees it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResolvedStatement {
    /// The statement kind.
    pub kind: String,
    /// The registered transform reference.
    pub transform: String,
    /// The inputs in the foreign identifier space.
    pub inputs: Vec<String>,
    /// The output in the foreign identifier space.
    pub output: String,
}

// ---------------------------------------------------------------------------
// SI-13 — bridge freshness
// ---------------------------------------------------------------------------

/// A bridge descriptor: what a bridge maps, at which version, and
/// when it was last refreshed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BridgeDescriptor {
    /// The registered mapping item this bridge serves.
    pub mapping_ref: String,
    /// The bridge's version (a schema bump on either endpoint bumps
    /// the bridge).
    pub version: u64,
    /// The data classes the bridge covers.
    pub covered_classes: Vec<String>,
    /// The refresh instant (RFC 3339).
    pub refreshed_at: String,
}

/// The bridge-health report (SI-13): per bridge, per class — fresh
/// or degraded, with versions named.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BridgeHealth {
    /// Per bridge: the entry's verdict.
    pub bridges: Vec<BridgeEntry>,
}

/// One bridge's health entry.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BridgeEntry {
    /// The bridge's mapping reference.
    pub mapping_ref: String,
    /// The version at the time of the report.
    pub version: u64,
    /// The covered classes with their freshness.
    pub classes: Vec<(String, bool)>,
}

/// A bridge is fresh if it was refreshed within `max_age_secs` of
/// `at`; a stale bridge degrades EXACTLY its covered classes.
pub fn bridge_fresh(
    bridge: &BridgeDescriptor,
    at: &str,
    max_age_secs: i64,
) -> Result<bool, SignatifError> {
    let now = Timestamp::parse(at)
        .map_err(|e| SignatifError::Validation(format!("health instant: {e}")))?;
    let refreshed = Timestamp::parse(&bridge.refreshed_at)
        .map_err(|e| SignatifError::Validation(format!("bridge refresh: {e}")))?;
    Ok(now.signed_secs_since(refreshed) <= max_age_secs && now.signed_secs_since(refreshed) >= 0)
}

/// The health report over the held bridges (names versions, marks
/// classes).
pub fn bridge_health(bridges: &[BridgeDescriptor], at: &str, max_age_secs: i64) -> BridgeHealth {
    BridgeHealth {
        bridges: bridges
            .iter()
            .map(|b| {
                let fresh = bridge_fresh(b, at, max_age_secs).unwrap_or(false);
                BridgeEntry {
                    mapping_ref: b.mapping_ref.clone(),
                    version: b.version,
                    classes: b
                        .covered_classes
                        .iter()
                        .map(|c| (c.clone(), fresh))
                        .collect(),
                }
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::declaration::{ClassPosture, InteropDeclaration};
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

    // SI-4's verify: all four modes exercised; class-scoped
    // recognition refuses out-of-class objects.
    #[test]
    fn all_four_recognition_modes_and_class_scoping() {
        // Unilateral: pinned here → recognized.
        assert!(matches!(
            recognize(
                RecognitionMode::UnilateralPinning,
                ObjectClass::SovereignAttestation,
                "cn-attestation-service",
                true,
                false,
                None,
                false
            ),
            Recognition::Recognized(_)
        ));
        // Unilateral: not pinned → refused, stated.
        assert!(matches!(
            recognize(
                RecognitionMode::UnilateralPinning,
                ObjectClass::SovereignAttestation,
                "cn-attestation-service",
                false,
                false,
                None,
                false
            ),
            Recognition::Refused { .. }
        ));
        // Bilateral: both pins required.
        assert!(matches!(
            recognize(
                RecognitionMode::BilateralAnchors,
                ObjectClass::S13Message,
                "weilian-shenzhen",
                true,
                true,
                None,
                false
            ),
            Recognition::Recognized(_)
        ));
        assert!(matches!(
            recognize(
                RecognitionMode::BilateralAnchors,
                ObjectClass::S13Message,
                "weilian-shenzhen",
                true,
                false,
                None,
                false
            ),
            Recognition::Refused { .. }
        ));
        // Club list: membership is class-scoped.
        let operator = KeyPair::seeded(Suite::Ed25519, b"club/op").unwrap();
        let club = ClubList::issue(
            "the-club",
            vec![ObjectClass::Profile, ObjectClass::SovereignAttestation],
            vec!["cn-attestation-service".into()],
            &operator,
        )
        .unwrap();
        assert!(matches!(
            recognize(
                RecognitionMode::ClubList,
                ObjectClass::SovereignAttestation,
                "cn-attestation-service",
                false,
                false,
                Some(&club),
                false
            ),
            Recognition::Recognized(_)
        ));
        // Out-of-class object: refused even for a member.
        let out = recognize(
            RecognitionMode::ClubList,
            ObjectClass::InteropDeclaration,
            "cn-attestation-service",
            false,
            false,
            Some(&club),
            false,
        );
        assert!(matches!(out, Recognition::Refused { .. }));
        // The operator's signature verifies; a forged list fails.
        let graph = graph_with(&[("club-op", &operator)]);
        club.verify("club-op", &graph).unwrap();
        let impostor = KeyPair::seeded(Suite::Ed25519, b"club/impostor").unwrap();
        let forged = ClubList::issue(
            "the-club",
            vec![ObjectClass::Profile],
            vec!["anyone".into()],
            &impostor,
        )
        .unwrap();
        assert!(forged.verify("club-op", &graph).is_err());
        // Master-list mesh: on-list recognized; off-list refused.
        assert!(matches!(
            recognize(
                RecognitionMode::MasterListMesh,
                ObjectClass::SegmentPolicy,
                "cn-samr",
                false,
                false,
                None,
                true
            ),
            Recognition::Recognized(_)
        ));
        assert!(matches!(
            recognize(
                RecognitionMode::MasterListMesh,
                ObjectClass::SegmentPolicy,
                "unknown",
                false,
                false,
                None,
                false
            ),
            Recognition::Refused { .. }
        ));
    }

    fn posture(class: &str, level: HarmonizationLevel) -> ClassPosture {
        ClassPosture {
            data_class: class.into(),
            level,
            recognition: RecognitionMode::UnilateralPinning,
            transports: vec![TransportMode::Document, TransportMode::Protocol],
            escalation: None,
            reciprocity: None,
        }
    }

    // SI-5's verify: a mixed-level relationship drives different
    // behaviour per class — direct vs substituted vs gap.
    #[test]
    fn mixed_levels_drive_per_class_behaviour() {
        let here = KeyPair::seeded(Suite::Ed25519, b"lvl/eu").unwrap();
        let there = KeyPair::seeded(Suite::Ed25519, b"lvl/cn").unwrap();
        let mut set = DeclarationSet::new();
        set.register(
            InteropDeclaration::issue(
                "eu-registry",
                "cn-scheme",
                1,
                vec![
                    posture("eu-static", HarmonizationLevel::L4),
                    posture("cn-dynamic", HarmonizationLevel::L2),
                ],
                "2027-01-01T00:00:00Z",
                None,
                &here,
            )
            .unwrap(),
        );
        set.register(
            InteropDeclaration::issue(
                "cn-scheme",
                "eu-registry",
                1,
                vec![
                    posture("eu-static", HarmonizationLevel::L5),
                    posture("cn-dynamic", HarmonizationLevel::L1),
                ],
                "2027-01-01T00:00:00Z",
                None,
                &there,
            )
            .unwrap(),
        );
        // The pair's declared level per class is the minimum of the
        // two sides: eu-static min(4,5)=L4 → direct; cn-dynamic
        // min(2,1)=L1 → substituted; undeclared → gap.
        let eu = declared_level(&set, "eu-registry", "cn-scheme", "eu-static").unwrap();
        let cn = declared_level(&set, "eu-registry", "cn-scheme", "cn-dynamic").unwrap();
        assert_eq!(eu.ordinal(), 4);
        assert_eq!(cn.ordinal(), 1);
        assert_eq!(behaviour_for_level(Some(eu)), ClassBehaviour::Direct);
        assert_eq!(behaviour_for_level(Some(cn)), ClassBehaviour::Substituted);
        assert_eq!(
            declared_level(&set, "eu-registry", "cn-scheme", "unknown"),
            None
        );
        assert_eq!(behaviour_for_level(None), ClassBehaviour::Gap);
        assert_eq!(
            behaviour_for_level(Some(HarmonizationLevel::L0)),
            ClassBehaviour::Gap
        );
    }

    // SI-7's verify: a foreign scheme ingests a composite event and
    // resolves its structure without the origin's semantics.
    #[test]
    fn foreign_schemes_resolve_composites_through_bridges() {
        let bridges = vec![
            BridgedIdentity {
                origin: "urn:unidpp:passport:cell-a".into(),
                foreign: "https://id.gs1.org/01/04006381/cell-a".into(),
                bridge: "urn:unidpp:mapping:unidpp-gs1".into(),
            },
            BridgedIdentity {
                origin: "urn:unidpp:passport:cell-b".into(),
                foreign: "https://id.gs1.org/01/04006381/cell-b".into(),
                bridge: "urn:unidpp:mapping:unidpp-gs1".into(),
            },
        ];
        let statement = PortableStatement {
            kind: "combine".into(),
            transform: "urn:unidpp:transform:pack-combine@1".into(),
            inputs: vec![
                "urn:unidpp:passport:cell-a".into(),
                "urn:unidpp:passport:cell-b".into(),
            ],
            output: BridgedIdentity {
                origin: "urn:unidpp:passport:pack-1".into(),
                foreign: "https://id.gs1.org/01/04006381/pack-1".into(),
                bridge: "urn:unidpp:mapping:unidpp-gs1".into(),
            },
        };
        let resolved = statement.resolve(&bridges).unwrap();
        assert_eq!(resolved.kind, "combine");
        assert_eq!(resolved.transform, "urn:unidpp:transform:pack-combine@1");
        assert_eq!(
            resolved.inputs,
            vec![
                "https://id.gs1.org/01/04006381/cell-a",
                "https://id.gs1.org/01/04006381/cell-b"
            ]
        );
        assert_eq!(resolved.output, "https://id.gs1.org/01/04006381/pack-1");
        // An unbridged input is a stated failure, never a guess.
        let mut partial = statement.clone();
        partial.inputs.push("urn:unidpp:passport:cell-c".into());
        let err = partial.resolve(&bridges).unwrap_err().to_string();
        assert!(
            err.contains("cell-c") && err.contains("no bridge entry"),
            "{err}"
        );
    }

    // SI-13's verify: a stale bridge degrades exactly its covered
    // classes; the health report names versions.
    #[test]
    fn stale_bridges_degrade_exactly_their_classes() {
        let eu_cn = BridgeDescriptor {
            mapping_ref: "urn:unidpp:mapping:eu-cn".into(),
            version: 3,
            covered_classes: vec!["eu-static".into(), "eu-reparability".into()],
            refreshed_at: "2030-06-01T00:00:00Z".into(),
        };
        let other = BridgeDescriptor {
            mapping_ref: "urn:unidpp:mapping:jp-eu".into(),
            version: 7,
            covered_classes: vec!["jp-static".into()],
            refreshed_at: "2030-05-01T00:00:00Z".into(),
        };
        // At 2030-06-02 with a 10-day window: eu-cn fresh, jp-eu
        // stale (refreshed 32 days prior).
        let at = "2030-06-02T00:00:00Z";
        assert!(bridge_fresh(&eu_cn, at, 10 * 24 * 3600).unwrap());
        assert!(!bridge_fresh(&other, at, 10 * 24 * 3600).unwrap());
        let health = bridge_health(&[eu_cn, other], at, 10 * 24 * 3600);
        assert_eq!(health.bridges.len(), 2);
        let eu_entry = &health.bridges[0];
        assert_eq!(eu_entry.version, 3);
        assert!(eu_entry.classes.iter().all(|(_, fresh)| *fresh));
        let jp_entry = &health.bridges[1];
        assert_eq!(jp_entry.version, 7);
        assert!(jp_entry.classes.iter().all(|(_, fresh)| !*fresh));
        // The degradation touches exactly the stale bridge's
        // classes: jp-static degraded, eu classes untouched.
        let degraded: Vec<&str> = health
            .bridges
            .iter()
            .flat_map(|b| {
                b.classes
                    .iter()
                    .filter(|(_, f)| !f)
                    .map(|(c, _)| c.as_str())
            })
            .collect();
        assert_eq!(degraded, ["jp-static"]);
    }
}
