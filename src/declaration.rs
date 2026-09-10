//! Interop declarations (SI-8): each scheme's signed, versioned
//! statement of its interop posture — per counterpart and per data
//! class.
//!
//! Willingness is a precondition, never a variable a transport mode
//! can compensate for: S13 evaluation and hub policy checks consult
//! the PUBLISHER's declaration before anything moves, and a refusal
//! (or a missing declaration) surfaces as a stated coverage gap or
//! escalation — never bypassed, never silent. Declarations are
//! versioned and replayable: the version chain IS the record of the
//! scheme's posture over time; consultation is a pure function of
//! (declarations, counterpart, class, transport).

use crate::graph::{NodeId, TrustGraph};
use crate::keyring::KeyPair;
use crate::sign::{SignatureSlot, SigningDomain};
use crate::SignatifError;
use unidpp_model::{sha256, CanonicalWriter};

/// The harmonization ladder (SI-5): L0 no interop … L5 full core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HarmonizationLevel {
    /// No interop declared.
    L0,
    /// Document recognition (frozen views).
    L1,
    /// Protocol interop (S13).
    L2,
    /// Structural mapping (registered items).
    L3,
    /// Shared structures (shared profiles).
    L4,
    /// Full core.
    L5,
}

impl HarmonizationLevel {
    /// The level's ordinal (0–5).
    pub fn ordinal(self) -> u8 {
        match self {
            HarmonizationLevel::L0 => 0,
            HarmonizationLevel::L1 => 1,
            HarmonizationLevel::L2 => 2,
            HarmonizationLevel::L3 => 3,
            HarmonizationLevel::L4 => 4,
            HarmonizationLevel::L5 => 5,
        }
    }
}

/// How objects from the counterpart are recognized (SI-4's modes,
/// declared per object class — carried per posture here).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecognitionMode {
    /// Unilateral pinning under a declared acceptance policy.
    UnilateralPinning,
    /// Bilateral anchor exchange.
    BilateralAnchors,
    /// A club list.
    ClubList,
    /// The master-list mesh.
    MasterListMesh,
}

/// The transport modes a posture offers (SI-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransportMode {
    /// Connected protocol (S13).
    Protocol,
    /// Document exchange (frozen views, dossiers).
    Document,
    /// Hub relay.
    Hub,
}

/// The posture for one data class toward one counterpart.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClassPosture {
    /// The data class ("*" declares the default posture).
    pub data_class: String,
    /// The declared harmonization level.
    pub level: HarmonizationLevel,
    /// How the counterpart's objects are recognized.
    pub recognition: RecognitionMode,
    /// The transport modes offered.
    pub transports: Vec<TransportMode>,
    /// Escalation reference (the ceremony path), if any.
    pub escalation: Option<String>,
    /// Reciprocity reference, if any.
    pub reciprocity: Option<String>,
}

/// A scheme's signed declaration of its interop posture.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct InteropDeclaration {
    /// The declaring scheme's authority (trust-graph node).
    pub declarer: String,
    /// The counterpart ("*" declares the default posture).
    pub counterpart: String,
    /// Monotone version (a new version supersedes the prior).
    pub version: u64,
    /// Per-class postures (sorted canonically; "*" is the fallback).
    pub postures: Vec<ClassPosture>,
    /// Effective window start (RFC 3339).
    pub valid_from: String,
    /// Effective window end (RFC 3339; absent = open-ended).
    pub valid_to: Option<String>,
    /// The declarer's signature in the INTEROP-DECLARATION domain.
    pub signature: SignatureSlot,
}

impl InteropDeclaration {
    /// The canonical, signable form (CN-1): declarer, counterpart,
    /// version, each posture (class, level ordinal, recognition
    /// token, sorted transport tokens, escalation, reciprocity),
    /// window — postures in sorted class order.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        Self::canonical_bytes_for(
            &self.declarer,
            &self.counterpart,
            self.version,
            &self.postures,
            &self.valid_from,
            self.valid_to.as_deref(),
        )
    }

    /// The canonical bytes of the (unsigned) fields — what the
    /// declarer signs.
    fn canonical_bytes_for(
        declarer: &str,
        counterpart: &str,
        version: u64,
        postures: &[ClassPosture],
        valid_from: &str,
        valid_to: Option<&str>,
    ) -> Vec<u8> {
        let mut postures = postures.to_vec();
        postures.sort_by(|a, b| a.data_class.cmp(&b.data_class));
        let mut w = CanonicalWriter::new();
        w.write_bytes(declarer.as_bytes());
        w.write_bytes(counterpart.as_bytes());
        w.write_bytes(&version.to_le_bytes());
        for p in &postures {
            w.write_bytes(p.data_class.as_bytes());
            w.write_bytes(&[p.level.ordinal()]);
            w.write_bytes(recognition_token(p.recognition).as_bytes());
            let mut transports: Vec<&str> =
                p.transports.iter().map(|t| transport_token(*t)).collect();
            transports.sort();
            for t in transports {
                w.write_bytes(t.as_bytes());
            }
            w.write_bytes(p.escalation.as_deref().unwrap_or("").as_bytes());
            w.write_bytes(p.reciprocity.as_deref().unwrap_or("").as_bytes());
        }
        w.write_bytes(valid_from.as_bytes());
        w.write_bytes(valid_to.unwrap_or("").as_bytes());
        w.into_bytes()
    }

    /// The declaration's digest.
    pub fn digest(&self) -> [u8; 32] {
        sha256(&[&self.canonical_bytes()]).0
    }

    /// Issue: the declarer signs the canonical bytes.
    pub fn issue(
        declarer: &str,
        counterpart: &str,
        version: u64,
        postures: Vec<ClassPosture>,
        valid_from: &str,
        valid_to: Option<&str>,
        key: &KeyPair,
    ) -> Result<InteropDeclaration, SignatifError> {
        let bytes = Self::canonical_bytes_for(
            declarer,
            counterpart,
            version,
            &postures,
            valid_from,
            valid_to,
        );
        let signature = SignatureSlot::sign(key, SigningDomain::InteropDeclaration, &bytes)?;
        Ok(InteropDeclaration {
            declarer: declarer.into(),
            counterpart: counterpart.into(),
            version,
            postures,
            valid_from: valid_from.into(),
            valid_to: valid_to.map(Into::into),
            signature,
        })
    }

    /// Verify under the graph: the signature must resolve to the
    /// DECLARED declarer's key.
    pub fn verify(&self, graph: &TrustGraph) -> Result<(), SignatifError> {
        let node = NodeId::new(&self.declarer)
            .map_err(|e| SignatifError::crypto(format!("declaration declarer: {e}")))?;
        let public = graph
            .node(&node)
            .and_then(|n| n.key(&self.signature.key_id))
            .ok_or_else(|| {
                SignatifError::crypto(format!(
                    "declaration declarer `{}` has no such key",
                    self.declarer
                ))
            })?;
        self.signature.verify(
            SigningDomain::InteropDeclaration,
            &self.canonical_bytes(),
            public,
        )
    }

    /// The posture for one data class (exact match, else the "*"
    /// fallback, else None — stated).
    pub fn posture_for(&self, data_class: &str) -> Option<&ClassPosture> {
        self.postures
            .iter()
            .find(|p| p.data_class == data_class)
            .or_else(|| self.postures.iter().find(|p| p.data_class == "*"))
    }
}

fn recognition_token(mode: RecognitionMode) -> &'static str {
    match mode {
        RecognitionMode::UnilateralPinning => "unilateral-pinning",
        RecognitionMode::BilateralAnchors => "bilateral-anchors",
        RecognitionMode::ClubList => "club-list",
        RecognitionMode::MasterListMesh => "master-list-mesh",
    }
}

fn transport_token(mode: TransportMode) -> &'static str {
    match mode {
        TransportMode::Protocol => "protocol",
        TransportMode::Document => "document",
        TransportMode::Hub => "hub",
    }
}

/// What the consultation concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Permission {
    /// Permitted, at the declared level and recognition mode.
    Permitted {
        /// The declared harmonization level.
        level: HarmonizationLevel,
        /// The declared recognition mode.
        recognition: RecognitionMode,
    },
    /// The declaration refuses (stated reason — the WILL gap).
    Refused {
        /// Why the posture refuses.
        reason: String,
    },
    /// No declaration exists (stated — never silent).
    NoDeclaration,
}

/// The set of live declarations (the discovery registry's
/// declaration face; in-memory here, persisted there with FD-3).
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DeclarationSet {
    /// All declarations, all versions (consultation takes the
    /// latest per (declarer, counterpart)).
    pub declarations: Vec<InteropDeclaration>,
}

impl DeclarationSet {
    /// An empty set.
    pub fn new() -> DeclarationSet {
        DeclarationSet::default()
    }

    /// Register a declaration (the version chain grows; consultation
    /// takes the latest).
    pub fn register(&mut self, declaration: InteropDeclaration) -> usize {
        self.declarations.push(declaration);
        self.declarations.len()
    }

    /// The latest declaration by (declarer, counterpart) — the
    /// version chain's head. "*" declarations are the fallback when
    /// no exact-counterpart declaration exists.
    pub fn latest_for(&self, declarer: &str, counterpart: &str) -> Option<&InteropDeclaration> {
        let pick = |c: &str| {
            self.declarations
                .iter()
                .filter(|d| d.declarer == declarer && d.counterpart == c)
                .max_by_key(|d| d.version)
        };
        pick(counterpart).or_else(|| pick("*"))
    }

    /// The willingness gate (SI-2's precondition): consult the
    /// declarer's latest declaration for (counterpart, class) and
    /// ask whether `transport` is offered. Refusal and absence are
    /// STATED — the caller surfaces them as a coverage gap or
    /// escalation, never as silence.
    #[allow(clippy::needless_pass_by_value)] // mode enums are Copy-cheap; the API reads better by value
    pub fn permits(
        &self,
        declarer: &str,
        counterpart: &str,
        data_class: &str,
        transport: TransportMode,
    ) -> Permission {
        // Consult the exact-counterpart declaration first, then the
        // "*" declaration — per class, so a wildcard posture can
        // cover classes the specific declaration omits.
        let pick = |c: &str| {
            self.declarations
                .iter()
                .filter(|d| d.declarer == declarer && d.counterpart == c)
                .max_by_key(|d| d.version)
        };
        let Some((_declaration, posture)) = [counterpart, "*"]
            .iter()
            .find_map(|c| pick(c).and_then(|d| d.posture_for(data_class).map(|p| (d, p))))
        else {
            return Permission::NoDeclaration;
        };
        if posture.level == HarmonizationLevel::L0 {
            return Permission::Refused {
                reason: format!(
                    "`{}` declares L0 for class `{}` toward `{}` — the WILL gap, \
                     never brokered around",
                    declarer, data_class, counterpart
                ),
            };
        }
        if !posture.transports.contains(&transport) {
            return Permission::Refused {
                reason: format!(
                    "`{}` offers {:?} for class `{}` toward `{}`, not `{}`",
                    declarer,
                    posture.transports,
                    data_class,
                    counterpart,
                    transport_token(transport)
                ),
            };
        }
        Permission::Permitted {
            level: posture.level,
            recognition: posture.recognition,
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

    fn permitting(declarer_key: &KeyPair) -> InteropDeclaration {
        InteropDeclaration::issue(
            "weilian-shenzhen",
            "de-zoll",
            1,
            vec![ClassPosture {
                data_class: "cn-dynamic".into(),
                level: HarmonizationLevel::L2,
                recognition: RecognitionMode::BilateralAnchors,
                transports: vec![TransportMode::Protocol, TransportMode::Document],
                escalation: Some("cn-samr-escrow".into()),
                reciprocity: Some("eu-cn-mutual".into()),
            }],
            "2027-01-01T00:00:00Z",
            None,
            declarer_key,
        )
        .unwrap()
    }

    // SI-8's verify: a declaration change flips a live
    // relationship's behavior — v2 (refusing) supersedes v1.
    #[test]
    fn declaration_changes_flip_live_behavior() {
        let declarer = KeyPair::seeded(Suite::Ed25519, b"decl/weilian").unwrap();
        let graph = graph_with(&[("weilian-shenzhen", &declarer)]);
        let mut set = DeclarationSet::new();

        set.register(permitting(&declarer));
        assert!(set
            .latest_for("weilian-shenzhen", "de-zoll")
            .unwrap()
            .verify(&graph)
            .is_ok());
        assert_eq!(
            set.permits(
                "weilian-shenzhen",
                "de-zoll",
                "cn-dynamic",
                TransportMode::Document
            ),
            Permission::Permitted {
                level: HarmonizationLevel::L2,
                recognition: RecognitionMode::BilateralAnchors
            }
        );

        // v2: the class drops to L0 — the WILL gap.
        let refusing = InteropDeclaration::issue(
            "weilian-shenzhen",
            "de-zoll",
            2,
            vec![ClassPosture {
                data_class: "cn-dynamic".into(),
                level: HarmonizationLevel::L0,
                recognition: RecognitionMode::UnilateralPinning,
                transports: vec![],
                escalation: Some("cn-samr-escrow".into()),
                reciprocity: None,
            }],
            "2030-01-01T00:00:00Z",
            None,
            &declarer,
        )
        .unwrap();
        set.register(refusing);
        match set.permits(
            "weilian-shenzhen",
            "de-zoll",
            "cn-dynamic",
            TransportMode::Document,
        ) {
            Permission::Refused { reason } => assert!(reason.contains("WILL gap"), "{reason}"),
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    // A hub relay without a permitting declaration is refused; no
    // declaration at all is stated, never silent; the wildcard
    // fallback works; the wrong key does not verify.
    #[test]
    fn hub_and_absence_semantics() {
        let declarer = KeyPair::seeded(Suite::Ed25519, b"decl/weilian").unwrap();
        let impostor = KeyPair::seeded(Suite::Ed25519, b"decl/impostor").unwrap();
        let graph = graph_with(&[("weilian-shenzhen", &declarer)]);
        let mut set = DeclarationSet::new();
        set.register(permitting(&declarer));

        // Hub not offered → refused (the CAN gap is for hubs that
        // both sides declared hub transport through).
        match set.permits(
            "weilian-shenzhen",
            "de-zoll",
            "cn-dynamic",
            TransportMode::Hub,
        ) {
            Permission::Refused { reason } => assert!(reason.contains("not `hub`"), "{reason}"),
            other => panic!("expected refusal, got {other:?}"),
        }

        // No declaration for an unknown counterpart → stated.
        assert_eq!(
            set.permits(
                "weilian-shenzhen",
                "random-party",
                "cn-dynamic",
                TransportMode::Document
            ),
            Permission::NoDeclaration
        );

        // The "*" fallback serves unlisted classes of a declared
        // counterpart.
        let wildcard = InteropDeclaration::issue(
            "weilian-shenzhen",
            "*",
            1,
            vec![ClassPosture {
                data_class: "*".into(),
                level: HarmonizationLevel::L1,
                recognition: RecognitionMode::UnilateralPinning,
                transports: vec![TransportMode::Document],
                escalation: None,
                reciprocity: None,
            }],
            "2027-01-01T00:00:00Z",
            None,
            &declarer,
        )
        .unwrap();
        set.register(wildcard);
        assert!(matches!(
            set.permits(
                "weilian-shenzhen",
                "de-zoll",
                "eu-static",
                TransportMode::Document
            ),
            Permission::Permitted { .. }
        ));

        // A declaration signed by the wrong key does not verify.
        let forged = permitting(&impostor);
        assert!(forged.verify(&graph).is_err());
    }

    // The canonical form is order-insensitive over postures and
    // transports (equal postures serialize to equal bytes).
    #[test]
    fn canonical_bytes_are_order_insensitive() {
        let key = KeyPair::seeded(Suite::Ed25519, b"decl/x").unwrap();
        let a = InteropDeclaration::issue(
            "s",
            "c",
            1,
            vec![
                ClassPosture {
                    data_class: "b".into(),
                    level: HarmonizationLevel::L1,
                    recognition: RecognitionMode::ClubList,
                    transports: vec![TransportMode::Hub, TransportMode::Document],
                    escalation: None,
                    reciprocity: None,
                },
                ClassPosture {
                    data_class: "a".into(),
                    level: HarmonizationLevel::L1,
                    recognition: RecognitionMode::ClubList,
                    transports: vec![],
                    escalation: None,
                    reciprocity: None,
                },
            ],
            "2027-01-01T00:00:00Z",
            None,
            &key,
        )
        .unwrap();
        let mut b = a.clone();
        b.postures.reverse();
        b.postures[0].transports.reverse();
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
        assert_eq!(a.digest(), b.digest());
    }
}
