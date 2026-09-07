//! Scenario: executable authorization-scope conditions (CC/SIGNATIF
//! §3.6.4, §11 `scope-conditions`, §12 `revocation-condition-withdrawal`)
//! through the verification pipeline.
//!
//! The EU topology's issuer hop is re-issued carrying conditions:
//!
//! ```text
//! eu-root ──(wide grant)──> eu-notified
//!   └─(narrow: batteries, condition: chemistry ∈ {lfp},
//!      condition: predicate urn:unidpp:rule:audit)──> issuer-key-a
//! ```
//!
//! Verification evaluates the conditions **at verify time** against
//! the concrete request: a met condition set accepts; an unmet one
//! fails with the typed `scope_condition_failed` reason and blocks
//! `accepted()`; a condition withdrawn in the ledger (§12) fails from
//! the withdrawal's effect moment onward, while earlier verifications
//! stand.

mod common;

use common::{battery_request, cosign_issuance, pid, t, topology, T0};
use unidpp_model::Interval;
use unidpp_signatif::graph::{DelegationCredential, TrustGraph};
use unidpp_signatif::revoke::{Revocation, RevocationLedger, RevocationReason, RevokedSubject};
use unidpp_signatif::scope::{DelegationScope, ScopeCondition, ScopeRequest};
use unidpp_signatif::sign::AcceptancePolicy;
use unidpp_signatif::verify::{SignatifVerifier, VerificationTarget};
use unidpp_verdict::Reading;

const T_ISSUE: i64 = T0 + 60;
const T_DEC: i64 = T0 + 5_000;

/// The EU topology with the issuer hop re-issued under the two
/// conditions (chemistry allow-list + audit predicate).
fn conditioned_topology() -> common::Topology {
    let mut topo = topology();
    let mut graph = TrustGraph::new();
    for node in topo.graph.nodes() {
        graph.add_node(node.clone());
    }
    graph.add_edge(topo.graph.edges()[0].clone()).unwrap();
    let narrow = DelegationScope::unconstrained()
        .authority(["eu"])
        .profile_version(["urn:unidpp:profile:eu-batt@3"])
        .product_group(["batteries"])
        .within(Interval::starting(t(T0)))
        .condition(ScopeCondition::Attribute {
            key: "battery-chemistry".into(),
            allowed_values: ["lfp"].into_iter().map(Into::into).collect(),
        })
        .condition(ScopeCondition::Predicate {
            expression_ref: "urn:unidpp:rule:audit".into(),
        });
    let hop =
        DelegationCredential::mint_sign(&topo.notified, &topo.issuer, narrow, &topo.notified_key)
            .unwrap();
    graph.add_edge(hop).unwrap();
    topo.graph = graph;
    topo
}

fn run(
    topo: &common::Topology,
    ledger: &RevocationLedger,
    request: ScopeRequest,
    now: i64,
) -> unidpp_signatif::verify::SignatifVerdict {
    let (provenance, issuers) = (
        unidpp_transform::ProvenanceGraph::new(),
        unidpp_signatif::revoke::IssuanceIndex::new(),
    );
    let subject = pid("battery-cond");
    let log = common::passport_log(&subject, T_ISSUE, "issuer-key-a");
    let co = cosign_issuance(&log, &topo.issuer_key);
    let verifier = SignatifVerifier {
        graph: &topo.graph,
        bundle: &topo.bundle,
        ledger,
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
    verifier.verify(
        &target,
        t(now),
        &issuers,
        &provenance,
        Reading::CurrentState,
    )
}

#[test]
fn met_conditions_accept_through_the_pipeline() {
    let topo = conditioned_topology();
    let (ledger, _prov) = common::empty_state();
    let request = battery_request(t(T0 + 100))
        .with_attribute("battery-chemistry", "lfp")
        .with_predicate("urn:unidpp:rule:audit", true);
    let verdict = run(&topo, &ledger, request, T0 + 100);
    assert!(verdict.accepted(), "conditions met: accepted");
    let slot = &verdict.trust.slots[0];
    assert!(slot.conditions.is_ok());
    // The effective scope along the path carries both conditions.
    assert_eq!(
        slot.path.as_ref().unwrap().effective_scope.conditions.len(),
        2
    );
}

#[test]
fn unmet_condition_fails_the_pipeline_with_the_typed_reason() {
    let topo = conditioned_topology();
    let (ledger, _prov) = common::empty_state();
    // The request claims an NMC battery: the chemistry allow-list
    // (LFP only) is not met.
    let request = battery_request(t(T0 + 100))
        .with_attribute("battery-chemistry", "nmc")
        .with_predicate("urn:unidpp:rule:audit", true);
    let verdict = run(&topo, &ledger, request, T0 + 100);
    assert!(!verdict.accepted(), "unmet condition must block acceptance");
    let slot = &verdict.trust.slots[0];
    assert!(slot.conditions.is_err());
    assert!(
        slot.conditions.as_ref().unwrap_err().contains("condition"),
        "detail was {:?}",
        slot.conditions
    );
    assert!(
        slot.path.is_err(),
        "path-finding enforces the condition too"
    );
    // Path-finding alone reports the typed failure reason.
    let err = topo
        .graph
        .resolve(
            topo.issuer_key.key_id(),
            &battery_request(t(T0 + 100)).with_attribute("battery-chemistry", "nmc"),
            &topo.bundle,
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            unidpp_signatif::SignatifError::ScopeConditionFailed { .. }
        ),
        "err was {err}"
    );
    // A predicate that evaluated false fails the same way.
    let request = battery_request(t(T0 + 100))
        .with_attribute("battery-chemistry", "lfp")
        .with_predicate("urn:unidpp:rule:audit", false);
    assert!(!run(&topo, &ledger, request, T0 + 100).accepted());
}

#[test]
fn withdrawn_condition_fails_from_the_effect_moment_only() {
    let topo = conditioned_topology();
    let (mut ledger, _prov) = common::empty_state();
    // The granting authority withdraws the chemistry condition from
    // the issuer (prospective §12 declaration; no quorum needed).
    ledger
        .declare(Revocation {
            subject: RevokedSubject::Condition {
                node: topo.issuer.clone(),
                condition: ScopeCondition::Attribute {
                    key: "battery-chemistry".into(),
                    allowed_values: ["lfp"].into_iter().map(Into::into).collect(),
                },
            },
            reason: RevocationReason::ConditionWithdrawal,
            declared_at: t(T_DEC),
            window: Interval::starting(t(T_DEC)),
            declared_by: topo.notified.clone(),
            quorum: None,
        })
        .unwrap();

    let request = battery_request(t(T0 + 100))
        .with_attribute("battery-chemistry", "lfp")
        .with_predicate("urn:unidpp:rule:audit", true);

    // Before the withdrawal's effect moment: the condition still
    // authorizes, the artifact is accepted.
    let before = run(&topo, &ledger, request.clone(), T_DEC - 1);
    assert!(before.accepted(), "pre-withdrawal verification stands");
    assert!(before.trust.slots[0].conditions.is_ok());

    // From the effect moment on: the still-carried condition is
    // withdrawn — the §12 propagation fails the verify-time condition
    // check (the predicate condition alone no longer saves it).
    let after = run(&topo, &ledger, request, T_DEC + 1);
    assert!(
        !after.accepted(),
        "withdrawn condition must block acceptance"
    );
    let detail = after.trust.slots[0]
        .conditions
        .as_ref()
        .unwrap_err()
        .clone();
    assert!(detail.contains("withdrawn"), "detail was {detail}");
    // The other condition is untouched: a scope carrying only the
    // predicate still verifies (targeted withdrawal, not blanket).
}
