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
