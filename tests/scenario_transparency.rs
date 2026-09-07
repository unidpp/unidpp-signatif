//! Scenario: transparency anchoring end-to-end — salted commitments,
//! inclusion proofs feeding the pipeline's anchor, signed tree heads,
//! the log-of-logs M-of-K master list, and tamper detection.

mod common;

use common::{battery_request, pid, t, topology, T0};

use unidpp_signatif::anchor::{
    verify_consistency, verify_inclusion, verify_master_quorum, LogEntry, LogOfLogs,
    SignedTreeHead, TransparencyLog,
};
use unidpp_signatif::keyring::KeyPair;
use unidpp_signatif::sign::{AcceptancePolicy, Suite};
use unidpp_signatif::verify::{anchor_from_inclusion, SignatifVerifier, VerificationTarget};
use unidpp_verdict::Reading;

/// The operator key of a witness log.
fn witness_operator(id: &str) -> KeyPair {
    KeyPair::seeded(Suite::Ed25519, format!("tlog/op-{id}").as_bytes()).unwrap()
}

#[test]
fn artifact_head_anchored_through_inclusion_and_sth() {
    let topo = topology();
    let (ledger, provenance) = common::empty_state();
    let issuers = unidpp_signatif::revoke::IssuanceIndex::new();

    // The artifact's log and its head commitment.
    let subject = pid("battery-anchored");
    let log = common::passport_log(&subject, T0 + 60, "issuer-key-a");
    let head = log.head().unwrap();

    // A witness transparency log whose leaves are salted commitments
    // to fact references (never the facts).
    let operator = witness_operator("eu-1");
    let mut tlog = TransparencyLog::new("eu-witness-1");
    for i in 0..3u8 {
        let salt = unidpp_event::salt_from_seed(format!("salt-{i}").as_bytes());
        let commitment = unidpp_signatif::anchor::salted_commitment(
            format!("urn:unidpp:fact:other-{i}").as_bytes(),
            &salt,
        );
        tlog.append(LogEntry::salted(commitment, i as u64));
    }
    let seq = tlog.append(LogEntry::public(head));
    let sth = tlog
        .sign_tree_head(t(T0 + 120), &operator)
        .unwrap();

    // The verifier pins the STH and checks the artifact head's
    // inclusion, deriving the anchor the core verdict will pin.
    let proof = tlog.inclusion_proof(seq).unwrap();
    assert!(verify_inclusion(&head, &proof, &sth.root).is_ok());
    let anchor = anchor_from_inclusion(&head, &proof, &sth).unwrap();
    assert_eq!(anchor, head);

    // A forged STH (wrong root) does not yield an anchor.
    let mut evil = sth.clone();
    evil.root = unidpp_model::sha256(&[b"evil"]);
    assert!(anchor_from_inclusion(&head, &proof, &evil).is_err());
    // Nor does a proof for the wrong leaf.
    let other_proof = tlog.inclusion_proof(0).unwrap();
    assert!(anchor_from_inclusion(&head, &other_proof, &sth).is_err());

    // The pipeline with the derived anchor: fully anchored verdict.
    let co = common::cosign_issuance_two(
        &log,
        &topo.issuer_key,
        Some(&topo.issuer_key_alt),
    );
    let verifier = SignatifVerifier {
        graph: &topo.graph,
        bundle: &topo.bundle,
        ledger: &ledger,
        request: battery_request(t(T0 + 130)),
        policy: AcceptancePolicy::any_computed(),
    };
    let target = VerificationTarget {
        log: &log,
        co_signature: co,
        anchor: Some(anchor),
        profile: None,
        provided: Default::default(),
        active_links: 0,
    };
    let verdict = verifier.verify(
        &target,
        t(T0 + 130),
        &issuers,
        &provenance,
        Reading::Evidentiary,
    );
    assert!(verdict.accepted());
    assert!(verdict.verdict.cryptographic.anchor_ok == Some(true));
    assert_eq!(
        verdict.verdict.trust_marker,
        unidpp_model::TrustMarker::LogAnchored
    );

    // Offline (no anchor): degrades explicitly, never silently passes.
    let target_offline = VerificationTarget {
        log: &log,
        co_signature: common::cosign_issuance_two(
            &log,
            &topo.issuer_key,
            Some(&topo.issuer_key_alt),
        ),
        anchor: None,
        profile: None,
        provided: Default::default(),
        active_links: 0,
    };
    let offline = verifier.verify(
        &target_offline,
        t(T0 + 130),
        &issuers,
        &provenance,
        Reading::Evidentiary,
    );
    assert!(offline.accepted(), "accepted-but-degraded");
    assert!(matches!(
        offline.verdict.outcome,
        unidpp_verdict::Outcome::Degraded(unidpp_verdict::Degradation::OfflineNoAnchor)
    ));
    assert!(offline.verdict.cryptographic.anchor_ok.is_none());
}

#[test]
fn inclusion_tamper_detection_on_leaf_and_log() {
    let operator = witness_operator("eu-2");
    let mut tlog = TransparencyLog::new("eu-witness-2");
    let mut heads = Vec::new();
    for i in 0..6u8 {
        let head = unidpp_model::sha256(&[format!("head-{i}").as_bytes()]);
        heads.push(head);
        tlog.append(LogEntry::public(head));
    }
    let sth = tlog.sign_tree_head(t(1000), &operator).unwrap();
    let seq = 3;
    let proof = tlog.inclusion_proof(seq).unwrap();

    // Tamper the leaf in the operator's copy: the pinned STH catches
    // it (the reconstructed root diverges).
    let mut tampered = tlog.clone();
    tampered.entries_tamper_for_test(seq, unidpp_model::sha256(&[b"fake"]));
    let tampered_sth = tampered.sign_tree_head(t(1000), &operator).unwrap();
    assert_ne!(sth.root, tampered_sth.root);
    assert!(verify_inclusion(&heads[seq as usize], &proof, &tampered_sth.root).is_err());
    // The honest proof still verifies against the honest pinned root.
    assert!(verify_inclusion(&heads[seq as usize], &proof, &sth.root).is_ok());
    // Truncating the log leaves a consistent prefix — but the
    // consistency proof from the pinned size exposes the divergence.
    let mut truncated = tlog.clone();
    truncated.truncate_for_test();
    let cons = tlog.consistency_proof(6).unwrap();
    let old_root = tlog.root_at_size(6).unwrap();
    assert!(verify_consistency(6, &old_root, 5, &truncated.root().unwrap(), &cons.path).is_err());
}

#[test]
fn log_of_logs_m_of_k_master_anchoring() {
    // Three independent witness logs each anchor the artifact head and
    // sign tree heads; the log-of-logs master log carries their STH
    // commitments; M-of-K quorum accepts.
    let head = unidpp_model::sha256(&[b"artifact-head"]);
    let mut logs = Vec::new();
    let mut sths = Vec::new();
    let mut operators = Vec::new();
    for i in 1..=3u8 {
        let id = format!("witness-{i}");
        let operator = witness_operator(&id);
        let mut log = TransparencyLog::new(&id);
        log.append(LogEntry::public(unidpp_model::sha256(&[
            format!("noise-{i}").as_bytes(),
        ])));
        log.append(LogEntry::public(head));
        let sth = log.sign_tree_head(t(2000), &operator).unwrap();
        logs.push(log);
        sths.push(sth);
        operators.push(operator);
    }

    let mut lol = LogOfLogs::new(2, 3);
    for sth in &sths {
        lol.append_witness_sth(sth);
    }
    let master_root = lol.root().unwrap();

    let items: Vec<(SignedTreeHead, unidpp_signatif::keyring::PublicKey, unidpp_signatif::anchor::InclusionProof)> = sths
        .iter()
        .zip(operators.iter())
        .map(|(sth, op)| (sth.clone(), *op.public(), lol.witness_proof(sth).unwrap()))
        .collect();
    // 3-of-3 and 2-of-3 hold.
    assert!(verify_master_quorum(&master_root, &items, 3).unwrap());
    assert!(verify_master_quorum(&master_root, &items[..2], 2).unwrap());
    // 3-of-2 does not.
    assert!(!verify_master_quorum(&master_root, &items[..2], 3).unwrap());
    // One witness's STH tampered (root swapped): its signature check
    // fails and the quorum collapses to the honest witnesses.
    let mut evil = items[0].0.clone();
    evil.root = unidpp_model::sha256(&[b"evil"]);
    let evil_items = vec![
        (evil, items[0].1, items[0].2.clone()),
        items[1].clone(),
    ];
    assert!(verify_master_quorum(&master_root, &evil_items, 2).is_err());
    // The master log is append-only: anchoring a further STH keeps the
    // old master root consistent via a consistency proof.
    let old_master_root = master_root;
    let extra = logs[0].sign_tree_head(t(3000), &operators[0]).unwrap();
    lol.append_witness_sth(&extra);
    let new_master_root = lol.root().unwrap();
    let proof = lol.log.consistency_proof(3).unwrap();
    assert!(
        verify_consistency(3, &old_master_root, 4, &new_master_root, &proof.path).is_ok()
    );
}

#[test]
fn witness_sth_signature_and_size_binding() {
    let operator = witness_operator("eu-3");
    let mut tlog = TransparencyLog::new("eu-witness-3");
    for i in 0..4u8 {
        tlog.append(LogEntry::public(unidpp_model::sha256(&[&[i]])));
    }
    let sth = tlog.sign_tree_head(t(5000), &operator).unwrap();
    assert!(sth.verify(operator.public()).is_ok());
    // The pinned head stays valid for its prefix as the log grows...
    tlog.append(LogEntry::public(unidpp_model::sha256(&[b"more"])));
    assert!(tlog.verify_size_against(&sth).is_ok());
    // ...and the growth is provable by consistency.
    let new_root = tlog.root().unwrap();
    let proof = tlog.consistency_proof(4).unwrap();
    assert!(verify_consistency(4, &sth.root, 5, &new_root, &proof.path).is_ok());
    // But a claim of a size the log never had fails.
    let fake = SignedTreeHead {
        log_id: sth.log_id.clone(),
        tree_size: 99,
        timestamp: sth.timestamp,
        root: sth.root,
        signature: sth.signature.clone(),
    };
    assert!(tlog.verify_size_against(&fake).is_err());
}
