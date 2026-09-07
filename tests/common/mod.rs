//! Shared fixtures for the SIGNATIF integration tests.
//!
//! Everything is seeded and deterministic: same seeds, same keys, same
//! signatures, same hashes, every run.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use unidpp_event::{EventLog, EventPayload, EventType, TypedEvent};
use unidpp_model::{
    Interval, PassportId, SignatureSuite, Timestamp, TrustMarker,
};
use unidpp_transform::ProvenanceGraph;

use unidpp_signatif::graph::{
    AnchorBundle, DelegationCredential, DelegationNode, MasterList, MasterListEntry, NodeId,
    NodeKind, RegisteredKey, TrustGraph, TrustList, WitnessAttestation,
};
use unidpp_signatif::keyring::{KeyPair, PublicKey};
use unidpp_signatif::revoke::{IssuanceIndex, RevocationLedger};
use unidpp_signatif::scope::{DelegationScope, ScopeRequest};
use unidpp_signatif::sign::{Suite, SigningDomain};
use unidpp_signatif::SignatifError;

pub fn t(secs: i64) -> Timestamp {
    Timestamp::from_secs(secs)
}

pub fn pid(n: &str) -> PassportId {
    PassportId::new(&format!("urn:unidpp:passport:{n}")).unwrap()
}

/// The EU-shaped trust topology used by the scenarios:
///
/// ```text
/// eu-root (Root; master-listed 2-of-3 witnesses; EU trust list)
///   └─(authority=eu, groups={batteries,electronics})→ eu-notified (Delegated)
///        └─(narrow: groups={batteries})→ issuer-key-a (End, Ed25519)
/// ```
pub struct Topology {
    pub graph: TrustGraph,
    pub bundle: AnchorBundle,
    pub root: NodeId,
    pub notified: NodeId,
    pub issuer: NodeId,
    pub root_key: KeyPair,
    pub notified_key: KeyPair,
    pub issuer_key: KeyPair,
    /// A second suite registered to the issuer node (the multi-suite
    /// co-signature discipline).
    pub issuer_key_alt: KeyPair,
    pub witness_keys: BTreeMap<NodeId, KeyPair>,
}

pub const T0: i64 = 1_000_000;

pub fn topology() -> Topology {
    let root = NodeId::new("eu-root").unwrap();
    let notified = NodeId::new("eu-notified").unwrap();
    let issuer = NodeId::new("issuer-key-a").unwrap();
    let root_key = KeyPair::seeded(Suite::Ed25519, b"scenario/eu-root").unwrap();
    let notified_key = KeyPair::seeded(Suite::EcdsaP256, b"scenario/eu-notified").unwrap();
    let issuer_key = KeyPair::seeded(Suite::Ed25519, b"scenario/issuer-a").unwrap();
    let issuer_key_alt = KeyPair::seeded(Suite::EcdsaP256, b"scenario/issuer-a-alt").unwrap();

    let mut graph = TrustGraph::new();
    let mut root_node = DelegationNode::new(root.clone(), NodeKind::Root);
    root_node.register(RegisteredKey::of(&root_key));
    graph.add_node(root_node);
    let mut notified_node = DelegationNode::new(notified.clone(), NodeKind::Delegated);
    notified_node.register(RegisteredKey::of(&notified_key));
    graph.add_node(notified_node);
    let mut issuer_node = DelegationNode::new(issuer.clone(), NodeKind::End);
    issuer_node.register(RegisteredKey::of(&issuer_key));
    issuer_node.register(RegisteredKey::of(&issuer_key_alt));
    graph.add_node(issuer_node);

    let wide = DelegationScope::unconstrained()
        .authority(["eu"])
        .profile_version([
            "urn:unidpp:profile:eu-batt@3",
            "urn:unidpp:profile:eu-espr@2",
        ])
        .product_group(["batteries", "electronics"])
        .within(Interval::starting(t(T0)));
    let narrow = DelegationScope::unconstrained()
        .authority(["eu"])
        .profile_version(["urn:unidpp:profile:eu-batt@3"])
        .product_group(["batteries"])
        .within(Interval::starting(t(T0)));

    let mut hop1 =
        DelegationCredential::mint_sign(&root, &notified, wide, &root_key).unwrap();
    // Multi-suite co-signed delegation (the lens-registry discipline).
    hop1.co_sign_by(&root_key).unwrap();
    let hop2 = DelegationCredential::mint_sign(&notified, &issuer, narrow, &notified_key).unwrap();
    graph.add_edge(hop1).unwrap();
    graph.add_edge(hop2).unwrap();

    // Jurisdiction trust list + 2-of-3 multi-witness master list.
    let mut list = TrustList::new("EU");
    list.trust(root.clone(), t(T0));
    let mut witness_keys = BTreeMap::new();
    let mut witnesses = BTreeMap::new();
    let mut attestations = Vec::new();
    for i in 1..=3u8 {
        let id = NodeId::new(&format!("witness-{i}")).unwrap();
        let key = KeyPair::seeded(Suite::Ed25519, format!("scenario/w{i}").as_bytes()).unwrap();
        attestations.push(
            WitnessAttestation::mint_sign(&id, &root, t(T0), &key).unwrap(),
        );
        witnesses.insert(id.clone(), *key.public());
        witness_keys.insert(id, key);
    }
    let mut master = MasterList::new(2, witnesses);
    master.upsert(MasterListEntry {
        node: root.clone(),
        attestations,
    });

    Topology {
        graph,
        bundle: AnchorBundle {
            jurisdiction: "EU".into(),
            trust_lists: vec![list],
            master,
        },
        root,
        notified,
        issuer,
        root_key,
        notified_key,
        issuer_key,
        issuer_key_alt,
        witness_keys,
    }
}

/// The scope request an EU battery verification makes.
pub fn battery_request(at: Timestamp) -> ScopeRequest {
    ScopeRequest::new(
        "eu",
        "urn:unidpp:profile:eu-batt@3",
        "batteries",
        at,
    )
}

/// An event log for one passport: an issuance by `issuer_key` at `at`,
/// then a custody transfer.
pub fn passport_log(subject: &PassportId, at: i64, issuer_actor: &str) -> EventLog {
    let mut log = EventLog::new(subject.clone());
    let issuance = TypedEvent::new(
        0,
        t(at),
        "issuing authority",
        issuer_actor,
        EventType::Issuance,
        EventPayload::Issuance {
            derived: false,
            inputs: vec![],
        },
        TrustMarker::MultiSigned,
    )
    .unwrap();
    log.append(issuance, None, None).unwrap();
    let custody = TypedEvent::new(
        1,
        t(at + 10),
        "custodian",
        "holder-1",
        EventType::CustodyTransfer,
        EventPayload::CustodyTransfer {
            from: "manufacturer".into(),
            to: "distributor".into(),
            counterparty_signed: true,
        },
        TrustMarker::Attested,
    )
    .unwrap();
    log.append(custody, None, None).unwrap();
    log
}

/// The issuance index entry for a passport log signed by `key`.
pub fn record_issuance(
    index: &mut IssuanceIndex,
    subject: &PassportId,
    at: i64,
    key: &KeyPair,
) {
    index.record(subject.clone(), t(at), key.key_id().clone());
}

/// Co-sign a canonical event body with the issuer's keys in both real
/// suites (Ed25519 + ECDSA-P256).
pub fn cosign_issuance(log: &EventLog, issuer_key: &KeyPair) -> unidpp_signatif::sign::CoSignature {
    cosign_issuance_two(log, issuer_key, None)
}

/// Co-sign with an explicit second-suite key (when the topology's
/// `issuer_key_alt` is at hand).
pub fn cosign_issuance_two(
    log: &EventLog,
    issuer_key: &KeyPair,
    alt: Option<&KeyPair>,
) -> unidpp_signatif::sign::CoSignature {
    let issuance = &log.sealed()[0].event;
    let body = issuance.canonical_body().unwrap();
    let mut co = unidpp_signatif::sign::CoSignature::new(SigningDomain::ArtifactEvent, &body);
    co.sign_by(issuer_key).unwrap();
    if let Some(alt) = alt {
        co.sign_by(alt).unwrap();
    }
    co
}

/// Empty ledger + provenance scaffolding.
pub fn empty_state() -> (RevocationLedger, ProvenanceGraph) {
    (RevocationLedger::new(), ProvenanceGraph::new())
}

/// Assert a result is the expected error shape (test helper).
pub fn assert_err_kind(actual: &Result<(), SignatifError>, matches: fn(&SignatifError) -> bool) {
    match actual {
        Ok(()) => panic!("expected an error, got Ok"),
        Err(e) => assert!(matches(e), "unexpected error kind: {e}"),
    }
}

/// Unused-but-stable helpers kept for symmetry with core tests.
pub fn suite_set(suites: &[Suite]) -> BTreeSet<unidpp_model::SignatureSuite> {
    suites
        .iter()
        .filter_map(|s| s.to_core())
        .collect::<BTreeSet<SignatureSuite>>()
}

/// A public key from a seeded pair (witness/operator lookups).
pub fn public_of(key: &KeyPair) -> PublicKey {
    *key.public()
}
