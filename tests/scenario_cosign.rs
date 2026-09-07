//! Scenario: multi-suite co-signature verification over the core's
//! canonical payloads, under policy-scoped acceptance.

mod common;

use common::{pid, t, topology, T0};

use unidpp_signatif::graph::KeyDirectory;
use unidpp_signatif::keyring::KeyPair;
use unidpp_signatif::sign::{
    AcceptancePolicy, CoSignature, SignatureSlot, SigningDomain, SlotVerdict, Suite,
};
use unidpp_signatif::SignatifError;

#[test]
fn same_payload_two_suites_any_allowed_accepts() {
    let topo = topology();
    let mut dir = KeyDirectory::new();
    dir.register(topo.issuer_key.public());
    dir.register(topo.issuer_key_alt.public());

    // The core's canonical payload: the typed event's canonical body.
    let subject = pid("battery-cosign");
    let log = common::passport_log(&subject, T0 + 60, "issuer-key-a");
    let body = log.sealed()[0].event.canonical_body().unwrap();

    let mut co = CoSignature::new(SigningDomain::ArtifactEvent, &body);
    co.sign_by(&topo.issuer_key).unwrap(); // Ed25519
    co.sign_by(&topo.issuer_key_alt).unwrap(); // ECDSA-P256

    let report = co.verify(&dir);
    assert_eq!(report.verified_count(), 2);
    assert_eq!(report.distinct_verified_suites(), 2);
    assert!(AcceptancePolicy::any_computed()
        .evaluate(&report)
        .is_accepted());
    assert!(AcceptancePolicy::multi_signed()
        .evaluate(&report)
        .is_accepted());
    // A single-suite (P256-only) jurisdiction policy accepts via the
    // P256 slot alone — policy-scoped acceptance.
    let p256_only = AcceptancePolicy::only(&[Suite::EcdsaP256]);
    assert!(p256_only.evaluate(&report).is_accepted());
    // An Ed25519-only policy accepts via the Ed25519 slot.
    let ed_only = AcceptancePolicy::only(&[Suite::Ed25519]);
    assert!(ed_only.evaluate(&report).is_accepted());
}

#[test]
fn broken_slot_degrades_multi_suite_but_any_allowed_still_accepts() {
    let topo = topology();
    let mut dir = KeyDirectory::new();
    dir.register(topo.issuer_key.public());
    dir.register(topo.issuer_key_alt.public());
    let subject = pid("battery-cosign");
    let log = common::passport_log(&subject, T0 + 60, "issuer-key-a");
    let body = log.sealed()[0].event.canonical_body().unwrap();

    let mut co = CoSignature::new(SigningDomain::ArtifactEvent, &body);
    co.sign_by(&topo.issuer_key).unwrap();
    co.sign_by(&topo.issuer_key_alt).unwrap();
    // Corrupt the Ed25519 slot.
    co.slots[0].signature.as_mut().unwrap()[3] ^= 0x40;

    let report = co.verify(&dir);
    assert_eq!(report.verified_count(), 1);
    assert!(
        matches!(&report.slots[0], SlotVerdict::Invalid { key_id, .. }
        if *key_id == *topo.issuer_key.key_id())
    );
    // Any-allowed accepts via the surviving P256 slot...
    assert!(AcceptancePolicy::any_computed()
        .evaluate(&report)
        .is_accepted());
    // ...but the multi-suite (lens-registry grade) policy rejects.
    let acceptance = AcceptancePolicy::multi_signed().evaluate(&report);
    assert!(!acceptance.is_accepted());
    // ...and an Ed25519-only jurisdiction rejects too.
    assert!(!AcceptancePolicy::only(&[Suite::Ed25519])
        .evaluate(&report)
        .is_accepted());
}

#[test]
fn framed_sm2_slot_is_deferred_and_never_fakes_verification() {
    let topo = topology();
    let mut dir = KeyDirectory::new();
    dir.register(topo.issuer_key.public());
    let subject = pid("battery-cosign");
    let log = common::passport_log(&subject, T0 + 60, "issuer-key-a");
    let body = log.sealed()[0].event.canonical_body().unwrap();

    let mut co = CoSignature::new(SigningDomain::ArtifactEvent, &body);
    co.frame_by(Suite::Sm2, topo.issuer_key.key_id());
    // Forge a plausible-looking SM2 value. Without the `sm2` binding
    // the suite is framing-only: Deferred, never faked. With the
    // binding, the value faces real verification: the anchor here is
    // the topology's Ed25519 key, so the mismatched slot is Invalid.
    co.slots[0].signature = Some(vec![0xA5u8; 64]);

    let report = co.verify(&dir);
    #[cfg(not(feature = "sm2"))]
    match &report.slots[0] {
        SlotVerdict::Deferred { suite, detail, .. } => {
            assert_eq!(suite, "sm2");
            assert!(detail.contains("GM/T 0003"), "{detail}");
        }
        other => panic!("expected Deferred, got {other:?}"),
    }
    #[cfg(feature = "sm2")]
    assert!(matches!(&report.slots[0], SlotVerdict::Invalid { .. }));
    assert!(!report.any_verified());
    assert!(!AcceptancePolicy::any_computed()
        .evaluate(&report)
        .is_accepted());
    // Direct slot verification states the same refusal.
    let err = co.slots[0]
        .verify(
            SigningDomain::ArtifactEvent,
            &body,
            topo.issuer_key.public(),
        )
        .unwrap_err();
    #[cfg(not(feature = "sm2"))]
    match &err {
        SignatifError::SuiteDeferred { suite, detail } => {
            assert_eq!(suite, "sm2");
            let _ = detail;
        }
        other => panic!("expected SuiteDeferred, got {other:?}"),
    }
    #[cfg(feature = "sm2")]
    assert!(matches!(&err, SignatifError::Crypto { .. }));
    // ML-DSA-65: the same split — deferred without the binding,
    // computed with it.
    #[cfg(not(feature = "ml-dsa"))]
    {
        let ml = KeyPair::seeded(Suite::MlDsa65, b"x").unwrap_err();
        assert!(matches!(ml, SignatifError::SuiteDeferred { .. }));
    }
    #[cfg(feature = "ml-dsa")]
    {
        let ml = KeyPair::seeded(Suite::MlDsa65, b"x").unwrap();
        let slot = SignatureSlot::sign(&ml, SigningDomain::ArtifactEvent, &body).unwrap();
        assert_eq!(slot.signature.as_ref().unwrap().len(), 3309);
        slot.verify(SigningDomain::ArtifactEvent, &body, ml.public())
            .unwrap();
    }
}

#[test]
fn tampered_payload_fails_all_suites() {
    let topo = topology();
    let mut dir = KeyDirectory::new();
    dir.register(topo.issuer_key.public());
    dir.register(topo.issuer_key_alt.public());
    let subject = pid("battery-cosign");
    let log = common::passport_log(&subject, T0 + 60, "issuer-key-a");
    let body = log.sealed()[0].event.canonical_body().unwrap();

    let mut co = CoSignature::new(SigningDomain::ArtifactEvent, &body);
    co.sign_by(&topo.issuer_key).unwrap();
    co.sign_by(&topo.issuer_key_alt).unwrap();
    // A different canonical payload (one byte changed): both fail.
    let mut forged = body.clone();
    let last = forged.len() - 1;
    forged[last] ^= 0x01;
    let report = CoSignature {
        domain: SigningDomain::ArtifactEvent,
        payload: forged,
        slots: co.slots.clone(),
        composites: Vec::new(),
    }
    .verify(&dir);
    assert_eq!(report.verified_count(), 0);
    assert!(!AcceptancePolicy::any_computed()
        .evaluate(&report)
        .is_accepted());
}

#[test]
fn determinism_of_seeded_signatures() {
    let a = KeyPair::seeded(Suite::Ed25519, b"det").unwrap();
    let b = KeyPair::seeded(Suite::Ed25519, b"det").unwrap();
    let p = KeyPair::seeded(Suite::EcdsaP256, b"det").unwrap();
    let q = KeyPair::seeded(Suite::EcdsaP256, b"det").unwrap();
    let payload = b"canonical payload".to_vec();
    let s1 = SignatureSlot::sign(&a, SigningDomain::ArtifactEvent, &payload).unwrap();
    let s2 = SignatureSlot::sign(&b, SigningDomain::ArtifactEvent, &payload).unwrap();
    let p1 = SignatureSlot::sign(&p, SigningDomain::ArtifactEvent, &payload).unwrap();
    let p2 = SignatureSlot::sign(&q, SigningDomain::ArtifactEvent, &payload).unwrap();
    // Ed25519 deterministic by construction; ECDSA-P256 via RFC 6979.
    assert_eq!(s1, s2);
    assert_eq!(p1, p2);
    // Whole co-signatures are reproducible.
    let co1 = {
        let mut c = CoSignature::new(SigningDomain::ArtifactEvent, &payload);
        c.sign_by(&a).unwrap();
        c.sign_by(&p).unwrap();
        c
    };
    let co2 = {
        let mut c = CoSignature::new(SigningDomain::ArtifactEvent, &payload);
        c.sign_by(&b).unwrap();
        c.sign_by(&q).unwrap();
        c
    };
    assert_eq!(co1, co2);
    // And stable across a serde round trip.
    let json = serde_json::to_string(&co1).unwrap();
    let rt: CoSignature = serde_json::from_str(&json).unwrap();
    assert_eq!(rt, co1);
}

#[test]
fn core_sig_slot_interop_preserves_framing() {
    let topo = topology();
    let subject = pid("battery-cosign");
    let log = common::passport_log(&subject, T0 + 60, "issuer-key-a");
    let body = log.sealed()[0].event.canonical_body().unwrap();
    let mut co = CoSignature::new(SigningDomain::ArtifactEvent, &body);
    co.sign_by(&topo.issuer_key_alt).unwrap(); // ECDSA-P256

    // The SIGNATIF slot maps onto the core's carrier framing with the
    // real signature value in place...
    let core_slot = co.slots[0].to_sig_slot().unwrap();
    assert_eq!(core_slot.suite, unidpp_model::SignatureSuite::EcdsaP256);
    assert_eq!(core_slot.signature.as_deref().map(|s| s.len()), Some(64));
    assert!(!core_slot.is_framed_only());
    assert_eq!(
        core_slot.projected_len(),
        1 + 1 + core_slot.key_id.len() + 2 + 64
    );
    // ...and round-trips back.
    let back = SignatureSlot::from_sig_slot(&core_slot).unwrap();
    assert_eq!(back, co.slots[0]);
}

#[test]
fn timestamped_event_stamps_flow_through_cosignature() {
    // A second event of the same log (a custody transfer) can be
    // co-signed too — the layer signs canonical payloads, whatever
    // their class.
    let topo = topology();
    let mut dir = KeyDirectory::new();
    dir.register(topo.issuer_key.public());
    let subject = pid("battery-cosign");
    let log = common::passport_log(&subject, T0 + 60, "issuer-key-a");
    let body = log.sealed()[1].event.canonical_body().unwrap();
    let mut co = CoSignature::new(SigningDomain::ArtifactEvent, &body);
    co.sign_by(&topo.issuer_key).unwrap();
    let report = co.verify(&dir);
    assert!(report.any_verified());
    assert_eq!(t(T0 + 70), log.sealed()[1].event.occurred_at);
}

#[test]
fn composite_slot_form_flows_through_the_pipeline() {
    // CC/SIGNATIF §3.7.4: a composite (AND-composition) carried as the
    // alternative slot form of a co-signature, end-to-end through the
    // verification pipeline.
    use unidpp_signatif::verify::{SignatifVerifier, VerificationTarget};
    use unidpp_verdict::Reading;

    let topo = topology();
    let (ledger, provenance) = common::empty_state();
    let issuers = unidpp_signatif::revoke::IssuanceIndex::new();
    let subject = pid("battery-composite");
    let log = common::passport_log(&subject, T0 + 60, "issuer-key-a");
    let body = log.sealed()[0].event.canonical_body().unwrap();

    // A co-signature whose ONLY slot form is one composite
    // (Ed25519 AND ECDSA-P256 over the same payload).
    let mut co = CoSignature::new(SigningDomain::ArtifactEvent, &body);
    co.sign_composite_by(&[&topo.issuer_key, &topo.issuer_key_alt])
        .unwrap();
    assert!(co.slots.is_empty());
    assert_eq!(co.composites.len(), 1);

    let verify = |co: CoSignature| {
        let verifier = SignatifVerifier {
            graph: &topo.graph,
            bundle: &topo.bundle,
            ledger: &ledger,
            request: common::battery_request(t(T0 + 100)),
            policy: AcceptancePolicy::multi_signed(),
        };
        let target = VerificationTarget {
            log: &log,
            co_signature: co,
            anchor: Some(log.head().unwrap()),
            profile: None,
            provided: Default::default(),
            active_links: 0,
        };
        verifier.verify(
            &target,
            t(T0 + 100),
            &issuers,
            &provenance,
            Reading::CurrentState,
        )
    };

    // Whole composite verifies: both member suites count, the strict
    // multi-signed policy is satisfied by the single composite, and
    // each member has full slot-trust rows (crypto, path, conditions).
    let verdict = verify(co.clone());
    assert!(verdict.accepted(), "verified composite must accept");
    assert!(verdict.trust.crypto.all_composites_verified());
    assert_eq!(verdict.trust.crypto.distinct_verified_suites(), 2);
    assert_eq!(verdict.trust.slots.len(), 2);
    for slot in &verdict.trust.slots {
        assert!(slot.crypto.is_ok());
        assert!(slot.path.is_ok());
    }

    // One tampered member: the composite fails as a whole (AND), no
    // suite counts, the policy rejects.
    let mut tampered = co;
    tampered.composites[0].members[0]
        .signature
        .as_mut()
        .unwrap()[0] ^= 0x01;
    let verdict = verify(tampered);
    assert!(!verdict.trust.crypto.all_composites_verified());
    assert!(!verdict.trust.crypto.any_verified());
    assert!(
        !verdict.accepted(),
        "a composite with one broken member must fail acceptance"
    );
}
