//! Scenario: delegation path-finding from an artifact signature to the
//! verifier's anchor bundle — including a failing out-of-scope path.

mod common;

use common::{battery_request, cosign_issuance, pid, t, topology, T0};

use unidpp_signatif::graph::{DelegationCredential, DelegationNode, NodeId, NodeKind, RegisteredKey};
use unidpp_signatif::scope::DelegationScope;
use unidpp_signatif::sign::{AcceptancePolicy, Suite};
use unidpp_signatif::verify::{SignatifVerifier, VerificationTarget};
use unidpp_signatif::SignatifError;
use unidpp_verdict::Reading;

#[test]
fn in_scope_path_resolves_and_verifies() {
    let topo = topology();
    let (ledger, provenance) = common::empty_state();
    let issuers = unidpp_signatif::revoke::IssuanceIndex::new();

    let at = T0 + 60;
    let subject = pid("battery-1");
    let log = common::passport_log(&subject, at, "issuer-key-a");
    let co = cosign_issuance(&log, &topo.issuer_key);

    let verifier = SignatifVerifier {
        graph: &topo.graph,
        bundle: &topo.bundle,
        ledger: &ledger,
        request: battery_request(t(at + 5)),
        policy: AcceptancePolicy::any_computed(),
    };
    let target = VerificationTarget {
        log: &log,
        co_signature: co,
        anchor: Some(log.head().unwrap()),
        profile: None,
        provided: Default::default(),
        active_links: 0,
    };
    let verdict = verifier.verify(&target, t(at + 5), &issuers, &provenance, Reading::CurrentState);

    // The trust layer: the Ed25519 slot verified, found a two-hop path
    // to the anchored eu-root, acceptance passed.
    assert!(verdict.accepted(), "in-scope artifact must be accepted");
    let slot = &verdict.trust.slots[0];
    assert!(slot.crypto.is_ok());
    assert!(slot.standing.is_valid());
    let path = slot.path.as_ref().unwrap();
    assert_eq!(path.hops(), 2);
    assert_eq!(path.root, topo.root);
    assert_eq!(path.end, topo.issuer);
    // Monotonic narrowing visible on the path: the wide grant narrowed
    // to batteries on the second hop.
    assert_eq!(
        path.credentials[0].scope.product_group,
        unidpp_signatif::scope::LayerConstraint::only(["batteries", "electronics"])
    );
    assert_eq!(
        path.effective_scope.product_group,
        unidpp_signatif::scope::LayerConstraint::only(["batteries"])
    );
    // The core verdict reflects the anchored, signed artifact.
    assert_eq!(verdict.verdict.reading_answered, Reading::CurrentState);
    assert!(verdict.verdict.cryptographic.chain_verified);
    assert!(verdict.verdict.cryptographic.anchor_ok == Some(true));
}

#[test]
fn out_of_scope_product_group_fails_the_path() {
    let topo = topology();
    // The issuer is scoped to batteries; a textiles request must fail
    // with ScopeExcluded naming the product-group layer.
    let request = unidpp_signatif::scope::ScopeRequest::new(
        "eu",
        "urn:unidpp:profile:eu-batt@3",
        "textiles",
        t(T0 + 100),
    );
    let err = topo
        .graph
        .resolve(topo.issuer_key.key_id(), &request, &topo.bundle)
        .unwrap_err();
    match &err {
        SignatifError::ScopeExcluded { key_id, detail } => {
            assert_eq!(*key_id, topo.issuer_key.key_id().to_string());
            assert!(detail.contains("product-group"), "detail was {detail}");
        }
        other => panic!("expected ScopeExcluded, got {other:?}"),
    }

    // The same artifact through the pipeline: no accepted path.
    let (ledger, provenance) = common::empty_state();
    let issuers = unidpp_signatif::revoke::IssuanceIndex::new();
    let subject = pid("textile-1");
    let log = common::passport_log(&subject, T0 + 60, "issuer-key-a");
    let co = cosign_issuance(&log, &topo.issuer_key);
    let verifier = SignatifVerifier {
        graph: &topo.graph,
        bundle: &topo.bundle,
        ledger: &ledger,
        request,
        policy: AcceptancePolicy::any_computed(),
    };
    let target = VerificationTarget {
        log: &log,
        co_signature: co,
        anchor: Some(log.head().unwrap()),
        profile: None,
        provided: Default::default(),
        active_links: 0,
    };
    let verdict = verifier.verify(&target, t(T0 + 100), &issuers, &provenance, Reading::CurrentState);
    assert!(!verdict.accepted(), "out-of-scope artifact must be rejected");
    assert!(verdict.trust.slots[0].path.is_err());
}

#[test]
fn out_of_scope_profile_version_and_authority_fail() {
    let topo = topology();
    // Profile version outside the delegation (espr@2 was granted at the
    // wide hop but narrowed away at the issuer hop).
    let wrong_profile = unidpp_signatif::scope::ScopeRequest::new(
        "eu",
        "urn:unidpp:profile:eu-espr@2",
        "batteries",
        t(T0 + 100),
    );
    assert!(matches!(
        topo.graph
            .resolve(topo.issuer_key.key_id(), &wrong_profile, &topo.bundle),
        Err(SignatifError::ScopeExcluded { .. })
    ));
    // Wrong authority layer.
    let wrong_authority = unidpp_signatif::scope::ScopeRequest::new(
        "us",
        "urn:unidpp:profile:eu-batt@3",
        "batteries",
        t(T0 + 100),
    );
    let err = topo
        .graph
        .resolve(topo.issuer_key.key_id(), &wrong_authority, &topo.bundle)
        .unwrap_err();
    assert!(err.to_string().contains("authority"), "err was {err}");
}

#[test]
fn unanchored_root_and_unlisted_keys_fail() {
    let topo = topology();
    // A root not in the trust list: paths through it never start.
    let rogue_root = NodeId::new("rogue-root").unwrap();
    let rogue_key = unidpp_signatif::keyring::KeyPair::seeded(Suite::EcdsaP256, b"rogue").unwrap();
    // A graph whose ONLY root is the rogue one (unlisted, unmastered):
    // a path exists but the bundle does not anchor the root.
    let mut g = unidpp_signatif::graph::TrustGraph::new();
    let mut rogue = DelegationNode::new(rogue_root.clone(), NodeKind::Root);
    rogue.register(RegisteredKey::of(&rogue_key));
    g.add_node(rogue);
    let mut issuer_node = DelegationNode::new(topo.issuer.clone(), NodeKind::End);
    issuer_node.register(RegisteredKey::of(&topo.issuer_key));
    g.add_node(issuer_node);
    let cred = DelegationCredential::mint_sign(
        &rogue_root,
        &topo.issuer,
        DelegationScope::unconstrained()
            .authority(["eu"])
            .product_group(["batteries"]),
        &rogue_key,
    )
    .unwrap();
    g.add_edge(cred).unwrap();
    let err = g
        .resolve(
            topo.issuer_key.key_id(),
            &battery_request(t(T0 + 100)),
            &topo.bundle,
        )
        .unwrap_err();
    assert!(matches!(err, SignatifError::Trust(_)), "err was {err}");

    // Unknown key id: no path at all.
    let unknown = unidpp_signatif::keyring::KeyId::new("k-ffffffffffffffff").unwrap();
    assert!(matches!(
        topo.graph
            .resolve(&unknown, &battery_request(t(T0 + 100)), &topo.bundle),
        Err(SignatifError::NoTrustPath { .. })
    ));
}

#[test]
fn coverage_and_freshness_degrade_explicitly_through_the_pipeline() {
    use unidpp_model::{
        CapabilityClass, DataPointRef, FreshnessRequirement, Interval, ProfileAxes, ProfileId,
        ProfileManifest, Resolution, TriggerPredicate, Traversal, VisibilityClass,
    };

    let topo = topology();
    let (ledger, provenance) = common::empty_state();
    let issuers = unidpp_signatif::revoke::IssuanceIndex::new();
    let subject = pid("battery-cov");
    let log = common::passport_log(&subject, T0 + 60, "issuer-key-a");

    let profile = ProfileManifest {
        id: ProfileId::new("urn:unidpp:profile:eu-batt").unwrap(),
        axes: ProfileAxes::jurisdiction("EU"),
        trigger: TriggerPredicate::Any,
        min_capability: CapabilityClass::Silent,
        freshness: FreshnessRequirement::FreshWithin { max_age_secs: 600 },
        effective: Interval::starting(t(T0)),
        data_points: vec![
            DataPointRef::new("ferin:eu", "carbon", None).unwrap(),
            DataPointRef::new("ferin:eu", "recycled", None).unwrap(),
        ],
        crypto_suites: vec![unidpp_model::SignatureSuite::EcdsaP256],
        confidential: false,
        resolution: Resolution::Public,
        edge_visibility: VisibilityClass::Public,
        traversal: Traversal::Public,
    };

    let verifier = SignatifVerifier {
        graph: &topo.graph,
        bundle: &topo.bundle,
        ledger: &ledger,
        request: battery_request(t(T0 + 70)),
        policy: AcceptancePolicy::any_computed(),
    };

    // Complete coverage, within the freshness window: accepted cleanly.
    let full: std::collections::BTreeSet<String> =
        ["ferin:eu/carbon".to_string(), "ferin:eu/recycled".to_string()]
            .into_iter()
            .collect();
    let co = common::cosign_issuance_two(&log, &topo.issuer_key, Some(&topo.issuer_key_alt));
    let target = VerificationTarget {
        log: &log,
        co_signature: co,
        anchor: Some(log.head().unwrap()),
        profile: Some(&profile),
        provided: full,
        active_links: 0,
    };
    let v = verifier.verify(&target, t(T0 + 70), &issuers, &provenance, Reading::Evidentiary);
    assert!(v.accepted());
    assert!(matches!(v.verdict.outcome, unidpp_verdict::Outcome::Pass));
    assert!(v.verdict.evidentiary.coverage.is_complete());
    assert_eq!(v.verdict.evidentiary.coverage.ratio(), 1.0);

    // Missing one data point: explicit coverage degradation, never a
    // silent pass.
    let partial: std::collections::BTreeSet<String> = ["ferin:eu/carbon".to_string()].into();
    let co2 = common::cosign_issuance_two(&log, &topo.issuer_key, Some(&topo.issuer_key_alt));
    let target2 = VerificationTarget {
        log: &log,
        co_signature: co2,
        anchor: Some(log.head().unwrap()),
        profile: Some(&profile),
        provided: partial,
        active_links: 0,
    };
    let v2 = verifier.verify(&target2, t(T0 + 70), &issuers, &provenance, Reading::Evidentiary);
    assert!(v2.accepted(), "accepted-but-degraded");
    match &v2.verdict.outcome {
        unidpp_verdict::Outcome::Degraded(unidpp_verdict::Degradation::CoverageIncomplete {
            missing,
        }) => assert_eq!(missing, &vec!["ferin:eu/recycled".to_string()]),
        other => panic!("expected coverage degradation, got {other:?}"),
    }
    assert!(!v2.verdict.evidentiary.coverage.is_complete());

    // Stale data: same artifact verified long after the freshness window.
    let full2: std::collections::BTreeSet<String> =
        ["ferin:eu/carbon".to_string(), "ferin:eu/recycled".to_string()]
            .into_iter()
            .collect();
    let co3 = common::cosign_issuance_two(&log, &topo.issuer_key, Some(&topo.issuer_key_alt));
    let target3 = VerificationTarget {
        log: &log,
        co_signature: co3,
        anchor: Some(log.head().unwrap()),
        profile: Some(&profile),
        provided: full2,
        active_links: 0,
    };
    let v3 =
        verifier.verify(&target3, t(T0 + 10_000), &issuers, &provenance, Reading::Evidentiary);
    assert!(matches!(
        v3.verdict.outcome,
        unidpp_verdict::Outcome::Degraded(unidpp_verdict::Degradation::StaleData { .. })
    ));
    assert_eq!(v3.verdict.freshness.label(), "stale");
}

#[test]
fn trust_list_supersession_rejects_paths_after_withdrawal() {
    let topo = topology();
    let mut bundle = topo.bundle.clone();
    bundle.trust_lists[0].supersede(&topo.root, t(T0 + 10_000));
    // Before withdrawal: fine.
    assert!(topo
        .graph
        .resolve(
            topo.issuer_key.key_id(),
            &battery_request(t(T0 + 100)),
            &topo.bundle
        )
        .is_ok());
    // After: the root is no longer anchored (legal withdrawal track).
    let err = topo
        .graph
        .resolve(
            topo.issuer_key.key_id(),
            &battery_request(t(T0 + 20_000)),
            &bundle,
        )
        .unwrap_err();
    assert!(matches!(err, SignatifError::Trust(_)), "err was {err}");
}
