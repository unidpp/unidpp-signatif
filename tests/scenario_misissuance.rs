//! Scenario: void-ab-initio misissuance — a retroactive distrust
//! declaration invalidating timestamped-but-post-window verifications
//! while pre-window evidentiary readings stand.
//!
//! Timeline (seconds from `T0`):
//!
//! ```text
//! T0+1000   battery-clean issued by issuer-key-a          (pre-window)
//! T0+5000   battery-bad issued by issuer-key-a            (in window)
//! T0+6000   pack-derived combined from battery-bad        (in window)
//! W = [T0+3000, T0+8000]  (the distrust window, unknown until T_DEC)
//! T0+9000   verifier verifies battery-bad: PASS (nothing known) and
//!           notarizes the historical verification
//! T0+10000  quorate body declares Misissuance on issuer-key-a, window W
//! ```
//!
//! After the declaration:
//! - `battery-bad` is void **ab initio** (issued inside W); the
//!   current-state reading fails even though its verification at
//!   T0+9000 was timestamped — timestamping does not protect against
//!   retroactive reasons;
//! - `battery-clean` (issued before W) is **re-validated**;
//! - `pack-derived` is void through the transitive cascade;
//! - the historical verification of `battery-bad` at T0+9000 is
//!   *retroactively invalidated* as a conclusion, while its
//!   evidentiary value (proof of diligence) stands;
//! - the historical verification of `battery-clean` stands.

mod common;

use common::{battery_request, pid, record_issuance, t, topology, T0};

use unidpp_signatif::graph::NodeId;
use unidpp_signatif::keyring::KeyPair;
use unidpp_signatif::revoke::{
    IssuanceIndex, QuorumAttestation, Revocation, RevocationLedger, RevocationReason,
    RevokedSubject, Standing,
};
use unidpp_signatif::sign::Suite;
use unidpp_signatif::sign::{AcceptancePolicy, SignatureSlot, SigningDomain};
use unidpp_signatif::verify::{HistoricalStanding, SignatifVerifier, VerificationTarget};
use unidpp_transform::ProvenanceGraph;
use unidpp_verdict::Reading;

const T_CLEAN: i64 = T0 + 1_000;
const T_BAD: i64 = T0 + 5_000;
const T_DERIVED: i64 = T0 + 6_000;
const W_START: i64 = T0 + 3_000;
const W_END: i64 = T0 + 8_000;
const T_VERIFY: i64 = T0 + 9_000;
const T_DECLARE: i64 = T0 + 10_000;
const T_NOW: i64 = T0 + 11_000;

struct World {
    topo: common::Topology,
    ledger: RevocationLedger,
    provenance: ProvenanceGraph,
    issuers: IssuanceIndex,
    notary: KeyPair,
}

fn world() -> World {
    let (ledger, provenance) = common::empty_state();
    World {
        topo: topology(),
        ledger,
        provenance,
        issuers: IssuanceIndex::new(),
        notary: KeyPair::seeded(Suite::EcdsaP256, b"scenario/notary").unwrap(),
    }
}

/// The quorate body that may declare retroactive distrust: 2-of-3
/// members, mirroring the root's master-list witnesses.
fn quorum_members() -> Vec<KeyPair> {
    vec![
        KeyPair::seeded(Suite::Ed25519, b"scenario/quorum-1").unwrap(),
        KeyPair::seeded(Suite::Ed25519, b"scenario/quorum-2").unwrap(),
        KeyPair::seeded(Suite::EcdsaP256, b"scenario/quorum-3").unwrap(),
    ]
}

fn declare_misissuance(w: &mut World) {
    let mut rev = Revocation {
        subject: RevokedSubject::Key(w.topo.issuer_key.key_id().clone()),
        reason: RevocationReason::Misissuance,
        declared_at: t(T_DECLARE),
        window: unidpp_model::Interval::between(t(W_START), t(W_END)).unwrap(),
        declared_by: NodeId::new("eu-super-quorum").unwrap(),
        quorum: None,
    };
    let members = quorum_members();
    let refs: Vec<&KeyPair> = members.iter().collect();
    let att =
        QuorumAttestation::mint_sign(&rev.declared_by, 2, &rev.statement_bytes(), &refs).unwrap();
    rev.quorum = Some(att);
    w.ledger.declare(rev).unwrap();
}

fn verdict_for(
    w: &World,
    log: &unidpp_event::EventLog,
    now: i64,
) -> unidpp_signatif::verify::SignatifVerdict {
    let co = common::cosign_issuance_two(log, &w.topo.issuer_key, Some(&w.topo.issuer_key_alt));
    let verifier = SignatifVerifier {
        graph: &w.topo.graph,
        bundle: &w.topo.bundle,
        ledger: &w.ledger,
        request: battery_request(t(now)),
        policy: AcceptancePolicy::any_computed(),
    };
    let target = VerificationTarget {
        log,
        co_signature: co,
        anchor: Some(log.head().unwrap()),
        profile: None,
        provided: Default::default(),
        active_links: 1,
    };
    verifier.verify(
        &target,
        t(now),
        &w.issuers,
        &w.provenance,
        Reading::CurrentState,
    )
}

#[test]
fn pre_declaration_everything_passes() {
    let mut w = world();
    let bad = pid("battery-bad");
    let log_bad = common::passport_log(&bad, T_BAD, "issuer-key-a");
    record_issuance(&mut w.issuers, &bad, T_BAD, &w.topo.issuer_key);

    let v = verdict_for(&w, &log_bad, T_VERIFY);
    assert!(v.accepted(), "nothing is known at T_VERIFY; must pass");
    assert!(!v.voids_ab_initio());
    // Two real suites signed; one (ECDSA-P256) maps onto the core's
    // carrier-framing table — Ed25519 is the SIGNATIF infrastructure
    // suite and rides in the trust report, not the carrier slots.
    assert_eq!(v.trust.slots.len(), 2);
    assert_eq!(v.verdict.cryptographic.signatures.len(), 1);
    assert!(v.verdict.cryptographic.anchor_ok == Some(true));
}

#[test]
fn retroactive_declaration_voids_in_window_and_revalidates_outside() {
    let mut w = world();
    let clean = pid("battery-clean");
    let bad = pid("battery-bad");
    let derived = pid("pack-derived");
    let log_clean = common::passport_log(&clean, T_CLEAN, "issuer-key-a");
    let log_bad = common::passport_log(&bad, T_BAD, "issuer-key-a");
    let log_derived = common::passport_log(&derived, T_DERIVED, "issuer-key-a");
    record_issuance(&mut w.issuers, &clean, T_CLEAN, &w.topo.issuer_key);
    record_issuance(&mut w.issuers, &bad, T_BAD, &w.topo.issuer_key);
    record_issuance(&mut w.issuers, &derived, T_DERIVED, &w.topo.issuer_key);
    // pack-derived is combined from battery-bad: transitive binding.
    w.provenance
        .record_combine(derived.clone(), std::slice::from_ref(&bad));

    // Pre-declaration: all valid.
    assert!(verdict_for(&w, &log_bad, T_VERIFY).accepted());

    declare_misissuance(&mut w);

    // In-window artifact: void ab initio NOW, even though its
    // verification at T_VERIFY was timestamped and passed.
    let v_bad = verdict_for(&w, &log_bad, T_NOW);
    assert!(
        !v_bad.accepted(),
        "in-window misissued artifact must fail now"
    );
    assert!(v_bad.voids_ab_initio(), "must void ab initio");
    assert!(v_bad.verdict.current_state.taints.voids_ab_initio());
    // The key's standing is void inside the window and re-validated
    // outside it.
    assert_eq!(
        w.ledger.key_standing(w.topo.issuer_key.key_id(), t(T_BAD)),
        Standing::VoidAbInitio {
            reason: "misissuance".into(),
            window: unidpp_model::Interval::between(t(W_START), t(W_END)).unwrap(),
        }
    );
    assert!(w
        .ledger
        .key_standing(w.topo.issuer_key.key_id(), t(T_CLEAN))
        .is_valid());

    // Pre-window artifact: re-validated, stands.
    let v_clean = verdict_for(&w, &log_clean, T_NOW);
    assert!(v_clean.accepted(), "pre-window artifact is re-validated");
    assert!(!v_clean.voids_ab_initio());

    // Transitive cascade: the derived pack is void through its input.
    let v_derived = verdict_for(&w, &log_derived, T_NOW);
    assert!(!v_derived.accepted());
    assert!(v_derived.voids_ab_initio());
    assert!(w.provenance.descendants(&bad).contains(&derived));
}

#[test]
fn retroactive_declaration_requires_a_quorum() {
    let mut w = world();
    let unquorate = Revocation {
        subject: RevokedSubject::Key(w.topo.issuer_key.key_id().clone()),
        reason: RevocationReason::FraudulentIssuance,
        declared_at: t(T_DECLARE),
        window: unidpp_model::Interval::between(t(W_START), t(W_END)).unwrap(),
        declared_by: NodeId::new("eu-super-quorum").unwrap(),
        quorum: None,
    };
    assert!(matches!(
        w.ledger.declare(unquorate),
        Err(unidpp_signatif::SignatifError::QuorumRequired { .. })
    ));
    // And nothing was recorded.
    assert!(w.ledger.revocations().is_empty());
}

#[test]
fn historical_stamps_retroactively_invalidated_but_evidence_stands() {
    let mut w = world();
    let clean = pid("battery-clean");
    let bad = pid("battery-bad");
    let log_clean = common::passport_log(&clean, T_CLEAN, "issuer-key-a");
    let log_bad = common::passport_log(&bad, T_BAD, "issuer-key-a");
    record_issuance(&mut w.issuers, &clean, T_CLEAN, &w.topo.issuer_key);
    record_issuance(&mut w.issuers, &bad, T_BAD, &w.topo.issuer_key);

    // A diligent verifier notarizes both at T_VERIFY (nothing known).
    let verifier = SignatifVerifier {
        graph: &w.topo.graph,
        bundle: &w.topo.bundle,
        ledger: &w.ledger,
        request: battery_request(t(T_VERIFY)),
        policy: AcceptancePolicy::any_computed(),
    };
    let hist_bad = verifier
        .verify_historical(&log_bad, t(T_VERIFY), &w.issuers, &w.provenance, &w.notary)
        .unwrap();
    let hist_clean = verifier
        .verify_historical(
            &log_clean,
            t(T_VERIFY),
            &w.issuers,
            &w.provenance,
            &w.notary,
        )
        .unwrap();
    assert_eq!(hist_bad.as_of, t(T_VERIFY));
    assert_eq!(
        hist_bad.state_hash,
        log_bad.state_hash_at(t(T_VERIFY)).unwrap()
    );
    assert!(hist_bad.verify_notary(w.notary.public()).is_ok());
    // Both passed at the time (evidentiary pass).
    assert!(matches!(
        hist_bad.still_stands(&w.ledger, &w.issuers, &w.provenance),
        HistoricalStanding::Stands {
            evidentiary_pass: true
        }
    ));
    assert!(matches!(
        hist_clean.still_stands(&w.ledger, &w.issuers, &w.provenance),
        HistoricalStanding::Stands {
            evidentiary_pass: true
        }
    ));

    // The retroactive declaration lands.
    declare_misissuance(&mut w);

    // battery-bad's stamp: the CONCLUSION is retroactively invalidated
    // (void ab initio beats the timestamp); the evidentiary value of
    // the stamp is what stands, not the pass.
    match hist_bad.still_stands(&w.ledger, &w.issuers, &w.provenance) {
        HistoricalStanding::RetroactivelyInvalidated { kind, window, .. } => {
            assert_eq!(kind, "misissued");
            assert_eq!(
                window,
                Some(unidpp_model::Interval::between(t(W_START), t(W_END)).unwrap())
            );
        }
        other => panic!("expected retroactive invalidation, got {other:?}"),
    }
    // battery-clean's stamp: entirely unaffected.
    assert!(hist_clean
        .still_stands(&w.ledger, &w.issuers, &w.provenance)
        .survives());
    // The notary stamp itself still verifies (it is evidence).
    assert!(hist_bad.verify_notary(w.notary.public()).is_ok());
    // A forged notary key does not.
    let fake = KeyPair::seeded(Suite::Ed25519, b"scenario/fake-notary").unwrap();
    assert!(hist_bad.verify_notary(fake.public()).is_err());
}

#[test]
fn prospective_reason_does_not_retroactively_invalidate() {
    let mut w = world();
    let bad = pid("battery-bad");
    let log_bad = common::passport_log(&bad, T_BAD, "issuer-key-a");
    record_issuance(&mut w.issuers, &bad, T_BAD, &w.topo.issuer_key);

    // A diligent verifier notarizes at T_VERIFY.
    let verifier = SignatifVerifier {
        graph: &w.topo.graph,
        bundle: &w.topo.bundle,
        ledger: &w.ledger,
        request: battery_request(t(T_VERIFY)),
        policy: AcceptancePolicy::any_computed(),
    };
    let hist = verifier
        .verify_historical(&log_bad, t(T_VERIFY), &w.issuers, &w.provenance, &w.notary)
        .unwrap();

    // Prospective key compromise declared AFTER the verification:
    // as-of-earlier verifications remain valid (timestamping protects).
    w.ledger
        .declare(Revocation {
            subject: RevokedSubject::Key(w.topo.issuer_key.key_id().clone()),
            reason: RevocationReason::KeyCompromise {
                after: t(T_DECLARE - 500),
            },
            declared_at: t(T_DECLARE),
            window: unidpp_model::Interval::starting(t(T_DECLARE - 500)),
            declared_by: NodeId::new("eu-root").unwrap(),
            quorum: None,
        })
        .unwrap();

    assert!(hist
        .still_stands(&w.ledger, &w.issuers, &w.provenance)
        .survives());
    // And the current standing is suspended-from, not void.
    assert_eq!(
        w.ledger.key_standing(w.topo.issuer_key.key_id(), t(T_NOW)),
        Standing::SuspendedFrom {
            reason: "key-compromise".into(),
            from: t(T_DECLARE - 500),
        }
    );
    // The artifact issued before the compromise keeps its validity in
    // the current-state reading (no ab-initio void).
    let v = verdict_for(&w, &log_bad, T_NOW);
    assert!(!v.voids_ab_initio());
}

#[test]
fn notarized_stamp_is_domain_separated() {
    let mut w = world();
    let bad = pid("battery-bad");
    let log_bad = common::passport_log(&bad, T_BAD, "issuer-key-a");
    record_issuance(&mut w.issuers, &bad, T_BAD, &w.topo.issuer_key);
    let verifier = SignatifVerifier {
        graph: &w.topo.graph,
        bundle: &w.topo.bundle,
        ledger: &w.ledger,
        request: battery_request(t(T_VERIFY)),
        policy: AcceptancePolicy::any_computed(),
    };
    let hist = verifier
        .verify_historical(&log_bad, t(T_VERIFY), &w.issuers, &w.provenance, &w.notary)
        .unwrap();
    // The stamp's signature cannot be replayed in another domain.
    let stamp = unidpp_signatif::verify::HistoricalVerification::stamp_bytes(
        &hist.subject,
        hist.as_of,
        &hist.state_hash,
    );
    let replay = SignatureSlot::sign(&w.notary, SigningDomain::TreeHead, &stamp).unwrap();
    assert!(replay
        .verify(SigningDomain::HistoricalStamp, &stamp, w.notary.public())
        .is_err());
    assert_ne!(replay.signature, hist.notary.signature);
}
