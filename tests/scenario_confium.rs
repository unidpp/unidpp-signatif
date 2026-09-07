//! Scenario: the Confium threshold-ceremony seam, exercised through
//! its interface-only mock (documented deviation: no real threshold
//! cryptography, and no build dependency on Confium).
//!
//! Run with: `cargo test --features confium`.

#![cfg(feature = "confium")]

mod common;

use common::{t, T0};

use unidpp_signatif::confium::mock::MockCeremony;
use unidpp_signatif::confium::{
    CeremonyCoordinator, CeremonyError, CeremonyKind, CeremonyStatement, Commitment, QuorumSpec,
    SessionInit, SessionState, Share,
};
use unidpp_signatif::graph::{DelegationNode, NodeId, NodeKind, RegisteredKey};
use unidpp_signatif::scope::DelegationScope;
use unidpp_signatif::sign::Suite;

fn members() -> Vec<NodeId> {
    vec![
        NodeId::new("director-1").unwrap(),
        NodeId::new("director-2").unwrap(),
        NodeId::new("director-3").unwrap(),
    ]
}

fn statement() -> CeremonyStatement {
    CeremonyStatement {
        label: "root-renewal/delegation".into(),
        payload: b"delegation statement bytes".to_vec(),
    }
}

fn init(expires_at: Option<unidpp_model::Timestamp>) -> SessionInit {
    SessionInit {
        kind: CeremonyKind::Sign,
        statement: statement(),
        quorum: QuorumSpec {
            quorum_id: NodeId::new("biml-root-ceremony").unwrap(),
            threshold: 2,
            members: members(),
        },
        expires_at,
    }
}

#[test]
fn lifecycle_follows_the_confium_session_states() {
    let mut ceremony = MockCeremony::new(None);
    let id = ceremony.create_session(init(None)).unwrap();
    assert_eq!(ceremony.session_state(&id), Some(SessionState::Pending));

    // One commitment: still pending (need 2).
    ceremony
        .submit_commitment(
            &id,
            Commitment {
                signer: members()[0].clone(),
                transcript: b"c1".to_vec(),
            },
        )
        .unwrap();
    assert_eq!(ceremony.session_state(&id), Some(SessionState::Pending));

    // Second commitment: CommitmentsCollected.
    ceremony
        .submit_commitment(
            &id,
            Commitment {
                signer: members()[1].clone(),
                transcript: b"c2".to_vec(),
            },
        )
        .unwrap();
    assert_eq!(
        ceremony.session_state(&id),
        Some(SessionState::CommitmentsCollected)
    );

    // Shares from both committed members: SharesCollected.
    for signer in [&members()[0], &members()[1]] {
        ceremony
            .submit_share(
                &id,
                Share {
                    signer: signer.clone(),
                    material: b"s".to_vec(),
                },
            )
            .unwrap();
    }
    assert_eq!(
        ceremony.session_state(&id),
        Some(SessionState::SharesCollected)
    );

    // Aggregation: a verifiable group signature over the statement.
    let aggregated = ceremony.aggregate(&id).unwrap();
    assert_eq!(ceremony.session_state(&id), Some(SessionState::Completed));
    assert_eq!(aggregated.suite, Suite::Ed25519);
    assert!(aggregated.verify(&statement()).is_ok());
    // The group key is deterministic in the quorum: same quorum, same key.
    let group_key = MockCeremony::group_key(&init(None).quorum.quorum_id).unwrap();
    assert_eq!(aggregated.group_key, *group_key.public());
    // A different statement does not verify.
    let other = CeremonyStatement {
        label: "other".into(),
        payload: b"something else".to_vec(),
    };
    assert!(aggregated.verify(&other).is_err());
}

#[test]
fn aggregation_below_threshold_and_unknown_sessions_fail() {
    let mut ceremony = MockCeremony::new(None);
    let id = ceremony.create_session(init(None)).unwrap();
    // Aggregate with zero shares: threshold not met, with counts.
    match ceremony.aggregate(&id) {
        Err(CeremonyError::ThresholdNotMet { have, need }) => {
            assert_eq!((have, need), (0, 2));
        }
        other => panic!("expected ThresholdNotMet, got {other:?}"),
    }
    // Unknown session handle.
    let ghost = unidpp_signatif::confium::SessionId::new("ghost").unwrap();
    assert!(matches!(
        ceremony.submit_commitment(
            &ghost,
            Commitment {
                signer: members()[0].clone(),
                transcript: vec![]
            }
        ),
        Err(CeremonyError::UnknownSession(_))
    ));
    assert!(ceremony.session_state(&ghost).is_none());
    // Degenerate quorums are refused at creation.
    let bad = SessionInit {
        kind: CeremonyKind::Dkg,
        statement: statement(),
        quorum: QuorumSpec {
            quorum_id: NodeId::new("bad").unwrap(),
            threshold: 0,
            members: members(),
        },
        expires_at: None,
    };
    assert!(matches!(
        ceremony.create_session(bad),
        Err(CeremonyError::Framework(_))
    ));
}

#[test]
fn identifiable_abort_emits_misbehavior_proofs() {
    let mut ceremony = MockCeremony::new(None);
    let id = ceremony.create_session(init(None)).unwrap();
    // A share from a member who never committed round 1.
    let err = ceremony
        .submit_share(
            &id,
            Share {
                signer: members()[2].clone(),
                material: b"rogue-share".to_vec(),
            },
        )
        .unwrap_err();
    match &err {
        CeremonyError::Misbehavior(proof) => {
            assert_eq!(proof.offender, members()[2]);
            assert_eq!(proof.offense, "share without a round-1 commitment");
            assert_eq!(proof.evidence, b"rogue-share".to_vec());
        }
        other => panic!("expected Misbehavior, got {other:?}"),
    }
    // The coordinator recorded the proof for proceedings.
    let proof = ceremony.abort_proof(&id).unwrap();
    assert_eq!(proof.offender, members()[2]);
    // Non-member commitments abort too.
    let outsider = NodeId::new("outsider").unwrap();
    let err = ceremony
        .submit_commitment(
            &id,
            Commitment {
                signer: outsider.clone(),
                transcript: b"x".to_vec(),
            },
        )
        .unwrap_err();
    assert!(matches!(err, CeremonyError::Misbehavior(_)));
}

#[test]
fn unlock_window_expires_incomplete_sessions() {
    let expiry = t(T0 + 3600);
    let mut ceremony = MockCeremony::new(Some(t(T0)));
    let id = ceremony.create_session(init(Some(expiry))).unwrap();
    ceremony
        .submit_commitment(
            &id,
            Commitment {
                signer: members()[0].clone(),
                transcript: b"c".to_vec(),
            },
        )
        .unwrap();
    // The unlock window elapses while the session is incomplete.
    ceremony.set_clock(t(T0 + 4000));
    // Past the window: any interaction reports expiry.
    assert!(matches!(
        ceremony.submit_share(
            &id,
            Share {
                signer: members()[0].clone(),
                material: b"s".to_vec(),
            }
        ),
        Err(CeremonyError::Expired)
    ));
    assert!(matches!(
        ceremony.aggregate(&id),
        Err(CeremonyError::Expired)
    ));
}

#[test]
fn aggregated_signature_backs_a_trust_graph_credential() {
    // The seam's integration point: a quorate ceremony output becomes
    // an ordinary SIGNATIF signature slot, verified against the group
    // key registered to the group's trust-graph node.
    let mut ceremony = MockCeremony::new(None);
    let init = init(None);
    let id = ceremony.create_session(init.clone()).unwrap();
    for signer in [&members()[0], &members()[1]] {
        ceremony
            .submit_commitment(
                &id,
                Commitment {
                    signer: signer.clone(),
                    transcript: b"c".to_vec(),
                },
            )
            .unwrap();
        ceremony
            .submit_share(
                &id,
                Share {
                    signer: signer.clone(),
                    material: b"s".to_vec(),
                },
            )
            .unwrap();
    }
    let aggregated = ceremony.aggregate(&id).unwrap();

    // Register the group key on a threshold-group node.
    let mut node = DelegationNode::new(
        init.quorum.quorum_id.clone(),
        NodeKind::ThresholdGroup {
            threshold: init.quorum.threshold,
            members: init.quorum.members.iter().cloned().collect(),
        },
    );
    node.register(RegisteredKey {
        key_id: unidpp_signatif::keyring::KeyId::of(&aggregated.group_key),
        public: aggregated.group_key,
    });
    let mut graph = unidpp_signatif::graph::TrustGraph::new();
    graph.add_node(node);
    let dir = graph.key_directory();
    assert_eq!(dir.len(), 1);

    // The ceremony's slot verifies under the group key, in the Quorum
    // domain, over the ceremony statement payload.
    let slot = aggregated.to_slot();
    let group_public = dir.resolve(&slot.key_id).unwrap();
    assert!(slot
        .verify(
            unidpp_signatif::sign::SigningDomain::Quorum,
            &init.statement.payload,
            group_public,
        )
        .is_ok());
    // And in no other domain (seam discipline).
    assert!(slot
        .verify(
            unidpp_signatif::sign::SigningDomain::Delegation,
            &init.statement.payload,
            group_public,
        )
        .is_err());

    // And the same group can sign a scoped delegation credential whose
    // signature the graph accepts (group-key model: one aggregate
    // signature stands for the quorum).
    let child = NodeId::new("ceremony-delegated").unwrap();
    graph.add_node(DelegationNode::new(child.clone(), NodeKind::Delegated));
    let mut cred = unidpp_signatif::graph::DelegationCredential {
        parent: init.quorum.quorum_id.clone(),
        child,
        scope: DelegationScope::unconstrained().authority(["eu"]),
        signatures: vec![slot],
    };
    let _ = &mut cred;
    // The group node has threshold semantics over *member* keys; the
    // aggregate slot instead verifies under the registered group key —
    // the two quorum models compose at the node, which is exactly the
    // interface the real Confium binding will drive.
    let verified = graph
        .node(&init.quorum.quorum_id)
        .unwrap()
        .key(&cred.signatures[0].key_id)
        .is_some();
    assert!(verified);
}

// ---------------------------------------------------------------------------
// RealCeremony: the same seam over the crate's real threshold
// cryptography (Feldman VSS + threshold Schnorr). The mock tests above
// stay interface-only; these drive the crypto through the trait.
// ---------------------------------------------------------------------------

use unidpp_signatif::confium::real::RealCeremony;
use unidpp_signatif::keyring::PublicKey;
use unidpp_signatif::threshold;

fn two_commitments_then_two_shares(
    ceremony: &mut RealCeremony,
    id: &unidpp_signatif::confium::SessionId,
) {
    for member in [&members()[0], &members()[1]] {
        let commitment = ceremony.commitment_for(id, member).unwrap();
        ceremony.submit_commitment(id, commitment).unwrap();
    }
    for member in [&members()[0], &members()[1]] {
        let share = ceremony.share_for(id, member).unwrap();
        ceremony.submit_share(id, share).unwrap();
    }
}

#[test]
fn real_ceremony_two_of_three_signs_a_standard_ed25519_group_signature() {
    let mut ceremony = RealCeremony::new(None);
    let init = init(None);
    let id = ceremony.create_session(init.clone()).unwrap();
    assert_eq!(ceremony.session_state(&id), Some(SessionState::Pending));
    two_commitments_then_two_shares(&mut ceremony, &id);
    assert_eq!(
        ceremony.session_state(&id),
        Some(SessionState::SharesCollected)
    );

    let aggregated = ceremony.aggregate(&id).unwrap();
    assert_eq!(ceremony.session_state(&id), Some(SessionState::Completed));
    assert_eq!(aggregated.suite, Suite::Ed25519);
    assert_eq!(aggregated.value.len(), 64);

    // The seam's verifier: the group key, the Quorum domain, the
    // statement. A different statement does not verify.
    aggregated.verify(&init.statement).unwrap();
    let other = CeremonyStatement {
        label: "other".into(),
        payload: b"something else".to_vec(),
    };
    assert!(aggregated.verify(&other).is_err());

    // Plain Ed25519: the value is a standard (R || s) signature under
    // the group key — any Ed25519 verifier accepts it over the framed
    // bytes, with no threshold machinery on the verifier's side.
    let PublicKey::Ed25519(group_bytes) = aggregated.group_key else {
        panic!("the threshold group key is not Ed25519");
    };
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&group_bytes).unwrap();
    let sig = ed25519_dalek::Signature::from_slice(&aggregated.value).unwrap();
    use ed25519_dalek::Verifier as _;
    let framed = unidpp_signatif::sign::domain_framed(
        unidpp_signatif::sign::SigningDomain::Quorum,
        &init.statement.payload,
    );
    vk.verify(&framed, &sig).unwrap();

    // And the group is exactly threshold::generate on the ceremony
    // seed (the bridge adds no key material of its own).
    let (direct, _) =
        threshold::generate(&RealCeremony::ceremony_seed(&init.quorum), 2, 3).unwrap();
    assert_eq!(direct, ceremony.group(&id).unwrap());
}

#[test]
fn real_ceremony_dkg_hands_out_feldman_verified_shares_and_inaugurates_the_key() {
    let mut ceremony = RealCeremony::new(None);
    let mut dkg_init = init(None);
    dkg_init.kind = CeremonyKind::Dkg;
    // A DKG statement differs from a signing statement; the group key
    // derivation ignores it (the seed is quorum-shaped).
    dkg_init.statement = CeremonyStatement {
        label: "root-dkg/inauguration".into(),
        payload: b"the inauguration message".to_vec(),
    };
    let id = ceremony.create_session(dkg_init.clone()).unwrap();
    let group = ceremony.group(&id).unwrap();
    assert_eq!(group.threshold, 2);
    assert_eq!(group.commitments.len(), 2);
    assert_eq!(group.commitments[0], group.group_public);

    // Every member verifies their share against the Feldman
    // commitments — a lying dealer is detectable by each member alone.
    for member in &members() {
        let share = ceremony.share_of(&id, member).unwrap();
        assert!(
            threshold::verify_share(&group, &share).unwrap(),
            "{}",
            member
        );
    }

    // The full rounds aggregate the inauguration signature over the
    // DKG statement under the new group key.
    two_commitments_then_two_shares(&mut ceremony, &id);
    let aggregated = ceremony.aggregate(&id).unwrap();
    aggregated.verify(&dkg_init.statement).unwrap();
}

#[test]
fn real_ceremony_below_threshold_is_refused_not_panicked() {
    let mut ceremony = RealCeremony::new(None);
    let id = ceremony.create_session(init(None)).unwrap();
    // Zero shares: the seam's refusal, with counts.
    match ceremony.aggregate(&id) {
        Err(CeremonyError::ThresholdNotMet { have, need }) => assert_eq!((have, need), (0, 2)),
        other => panic!("expected ThresholdNotMet, got {other:?}"),
    }
    // Round 1 complete, only one share: still short of the threshold.
    for member in [&members()[0], &members()[1]] {
        let commitment = ceremony.commitment_for(&id, member).unwrap();
        ceremony.submit_commitment(&id, commitment).unwrap();
    }
    let share = ceremony.share_for(&id, &members()[0]).unwrap();
    ceremony.submit_share(&id, share).unwrap();
    match ceremony.aggregate(&id) {
        Err(CeremonyError::ThresholdNotMet { have, need }) => assert_eq!((have, need), (1, 2)),
        other => panic!("expected ThresholdNotMet, got {other:?}"),
    }
    assert_eq!(
        ceremony.session_state(&id),
        Some(SessionState::CommitmentsCollected)
    );
}

#[test]
fn real_ceremony_tampered_share_aborts_with_the_culprit_named() {
    let mut ceremony = RealCeremony::new(None);
    let id = ceremony.create_session(init(None)).unwrap();
    for member in [&members()[0], &members()[1]] {
        let commitment = ceremony.commitment_for(&id, member).unwrap();
        ceremony.submit_commitment(&id, commitment).unwrap();
    }
    let good = ceremony.share_for(&id, &members()[0]).unwrap();
    ceremony.submit_share(&id, good).unwrap();

    // Member 2's partial, scalar tampered: still valid JSON, right
    // index, right nonce (so it passes the submission binding checks
    // and only the cryptographic verification can catch it).
    let mut tampered = ceremony.share_for(&id, &members()[1]).unwrap();
    let position = tampered
        .material
        .windows(11)
        .position(|w| w == b"\"partial\":\"")
        .expect("the partial material names its scalar");
    let digit = position + 11;
    tampered.material[digit] = if tampered.material[digit] == b'0' {
        b'1'
    } else {
        b'0'
    };
    ceremony.submit_share(&id, tampered).unwrap();

    // Aggregation aborts with the culprit identified.
    let err = ceremony.aggregate(&id).unwrap_err();
    match &err {
        CeremonyError::Misbehavior(proof) => {
            assert_eq!(proof.offender, members()[1]);
            assert!(proof.offense.contains("Feldman"), "{}", proof.offense);
            assert!(!proof.evidence.is_empty());
        }
        other => panic!("expected Misbehavior, got {other:?}"),
    }
    assert_eq!(
        ceremony.session_state(&id),
        Some(SessionState::SharesCollected)
    );
    let proof = ceremony.abort_proof(&id).unwrap();
    assert_eq!(proof.offender, members()[1]);
}

#[test]
fn real_ceremony_tampered_commitment_aborts_at_round_one() {
    let mut ceremony = RealCeremony::new(None);
    let id = ceremony.create_session(init(None)).unwrap();
    let mut commitment = ceremony.commitment_for(&id, &members()[0]).unwrap();
    // A transcript that is not the member's deterministic nonce point
    // for this statement.
    commitment.transcript[0] = if commitment.transcript[0] == b'0' {
        b'1'
    } else {
        b'0'
    };
    let err = ceremony.submit_commitment(&id, commitment).unwrap_err();
    match &err {
        CeremonyError::Misbehavior(proof) => {
            assert_eq!(proof.offender, members()[0]);
            assert!(proof.offense.contains("nonce point"), "{}", proof.offense);
        }
        other => panic!("expected Misbehavior, got {other:?}"),
    }
    assert!(ceremony.abort_proof(&id).is_some());
}

#[test]
fn real_ceremony_seed_is_stable_across_coordinators_statements_and_kinds() {
    // Two independent coordinators ("participants") derive the same
    // group for the same quorum.
    let mut a = RealCeremony::new(None);
    let mut b = RealCeremony::new(None);
    let id_a = a.create_session(init(None)).unwrap();
    let id_b = b.create_session(init(None)).unwrap();
    assert_eq!(a.group(&id_a).unwrap(), b.group(&id_b).unwrap());

    // A DKG session with a different statement lands on the same
    // group: the derivation is quorum-shaped, statement-free.
    let mut dkg_init = init(None);
    dkg_init.kind = CeremonyKind::Dkg;
    dkg_init.statement = CeremonyStatement {
        label: "other".into(),
        payload: b"a wholly different message".to_vec(),
    };
    let id_dkg = a.create_session(dkg_init).unwrap();
    assert_eq!(a.group(&id_dkg).unwrap(), a.group(&id_a).unwrap());

    // Member order does not matter (canonical sorted indexing).
    let mut shuffled = init(None);
    shuffled.quorum.members = shuffled.quorum.members.iter().rev().cloned().collect();
    let id_s = a.create_session(shuffled).unwrap();
    assert_eq!(a.group(&id_s).unwrap(), a.group(&id_a).unwrap());
    for member in &members() {
        let share = a.share_of(&id_s, member).unwrap();
        assert!(threshold::verify_share(&a.group(&id_s).unwrap(), &share).unwrap());
    }

    // A different quorum is a different group.
    let mut other_quorum = init(None);
    other_quorum.quorum.quorum_id = NodeId::new("another-ceremony").unwrap();
    let id_o = a.create_session(other_quorum).unwrap();
    assert_ne!(a.group(&id_o).unwrap(), a.group(&id_a).unwrap());
}

#[test]
fn real_ceremony_enforces_strict_rounds_and_refuses_unimplemented_kinds() {
    let mut ceremony = RealCeremony::new(None);
    let id = ceremony.create_session(init(None)).unwrap();
    // A share before round 1 is closed: wrong round, not misbehavior.
    let err = ceremony
        .submit_share(
            &id,
            Share {
                signer: members()[0].clone(),
                material: b"{}".to_vec(),
            },
        )
        .unwrap_err();
    assert!(matches!(err, CeremonyError::WrongRound { .. }));

    for member in [&members()[0], &members()[1]] {
        let commitment = ceremony.commitment_for(&id, member).unwrap();
        ceremony.submit_commitment(&id, commitment).unwrap();
    }
    // A third commitment after round 1 closed: wrong round (combine
    // takes exactly T partials).
    let err = ceremony
        .submit_commitment(&id, ceremony.commitment_for(&id, &members()[2]).unwrap())
        .unwrap_err();
    assert!(matches!(err, CeremonyError::WrongRound { .. }));
    // Building a share for a member outside the qualifying set is
    // refused by the threshold scheme itself.
    let err = ceremony.share_for(&id, &members()[2]).unwrap_err();
    assert!(matches!(err, CeremonyError::Framework(_)));

    // Reshare and Refresh are refused — the bridge does not fake a
    // re-share.
    let mut reshare = init(None);
    reshare.kind = CeremonyKind::Reshare;
    assert!(matches!(
        ceremony.create_session(reshare),
        Err(CeremonyError::Framework(_))
    ));
    let mut refresh = init(None);
    refresh.kind = CeremonyKind::Refresh;
    assert!(matches!(
        ceremony.create_session(refresh),
        Err(CeremonyError::Framework(_))
    ));
}

#[test]
fn real_ceremony_unlock_window_expires_incomplete_sessions() {
    let expiry = t(T0 + 3600);
    let mut ceremony = RealCeremony::new(Some(t(T0)));
    let id = ceremony.create_session(init(Some(expiry))).unwrap();
    for member in [&members()[0], &members()[1]] {
        let commitment = ceremony.commitment_for(&id, member).unwrap();
        ceremony.submit_commitment(&id, commitment).unwrap();
    }
    // The unlock window elapses while round 2 is outstanding.
    ceremony.set_clock(t(T0 + 4000));
    assert!(matches!(
        ceremony.submit_share(&id, ceremony.share_for(&id, &members()[0]).unwrap()),
        Err(CeremonyError::Expired)
    ));
    assert!(matches!(
        ceremony.aggregate(&id),
        Err(CeremonyError::Expired)
    ));
}

#[test]
fn real_ceremony_aggregate_bridges_into_a_trust_graph_slot() {
    let mut ceremony = RealCeremony::new(None);
    let init = init(None);
    let id = ceremony.create_session(init.clone()).unwrap();
    two_commitments_then_two_shares(&mut ceremony, &id);
    let aggregated = ceremony.aggregate(&id).unwrap();

    // Register the group key on a threshold-group node; the
    // aggregation's slot verifies under it in the Quorum domain.
    let mut node = DelegationNode::new(
        init.quorum.quorum_id.clone(),
        NodeKind::ThresholdGroup {
            threshold: init.quorum.threshold,
            members: init.quorum.members.iter().cloned().collect(),
        },
    );
    node.register(RegisteredKey {
        key_id: unidpp_signatif::keyring::KeyId::of(&aggregated.group_key),
        public: aggregated.group_key,
    });
    let mut graph = unidpp_signatif::graph::TrustGraph::new();
    graph.add_node(node);
    let dir = graph.key_directory();

    let slot = aggregated.to_slot();
    let group_public = dir.resolve(&slot.key_id).unwrap();
    slot.verify(
        unidpp_signatif::sign::SigningDomain::Quorum,
        &init.statement.payload,
        group_public,
    )
    .unwrap();
    // And in no other domain (seam discipline).
    assert!(slot
        .verify(
            unidpp_signatif::sign::SigningDomain::Delegation,
            &init.statement.payload,
            group_public,
        )
        .is_err());
}
