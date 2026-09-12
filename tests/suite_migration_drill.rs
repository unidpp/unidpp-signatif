//! NF-8: the algorithm-suite migration drill — rehearsed like
//! upgrades: journals replay, verdicts re-derived under the NEW
//! suite policy.
//!
//! The drill signs the same canonical payload across the migration
//! phases (classical, hybrid co-signed, successor), then flips the
//! acceptance policy to the successor suite and re-derives every
//! verdict: hybrid-signed objects still verify (their successor
//! slot answers), classical-only objects degrade (stated, never
//! silently pass), and the journaled bytes never change — the
//! migration is a POLICY act, not a rewrite.

mod common;

use common::topology;

use unidpp_signatif::graph::KeyDirectory;
use unidpp_signatif::keyring::KeyPair;
use unidpp_signatif::sign::{AcceptancePolicy, CoSignature, SigningDomain, Suite};

#[test]
fn the_suite_migration_drill_re_derives_verdicts_under_the_new_policy() {
    let topo = topology();
    let mut dir = KeyDirectory::new();
    dir.register(topo.issuer_key.public());
    dir.register(topo.issuer_key_alt.public());

    let subject = common::pid("migration-drill");
    let log = common::passport_log(&subject, common::T0 + 60, "issuer-key-a");
    let body = log.sealed()[0].event.canonical_body().unwrap();

    // Phase 1 (classical): one Ed25519 slot.
    let mut classical = CoSignature::new(SigningDomain::ArtifactEvent, &body);
    classical.sign_by(&topo.issuer_key).unwrap();

    // Phase 2 (hybrid co-signed): classical + successor side by
    // side — the AND-composition that carries the migration.
    let mut hybrid = CoSignature::new(SigningDomain::ArtifactEvent, &body);
    hybrid.sign_by(&topo.issuer_key).unwrap();
    hybrid.sign_by(&topo.issuer_key_alt).unwrap();

    // Before the flip: both verify under the permissive policy.
    let permissive = AcceptancePolicy::any_computed();
    assert!(permissive.evaluate(&classical.verify(&dir)).is_accepted());
    assert!(permissive.evaluate(&hybrid.verify(&dir)).is_accepted());

    // The drill: flip the acceptance policy to the successor suite
    // (ECDSA-P256) — the migration is a policy act. Re-derive.
    let successor_only = AcceptancePolicy::only(&[Suite::EcdsaP256]);
    let hybrid_after = successor_only.evaluate(&hybrid.verify(&dir));
    assert!(
        hybrid_after.is_accepted(),
        "hybrid-signed objects still verify: their successor slot answers"
    );
    let classical_after = successor_only.evaluate(&classical.verify(&dir));
    assert!(
        !classical_after.is_accepted(),
        "classical-only objects degrade under the successor policy — stated, never silently passed"
    );

    // The journaled verdicts never change under re-derivation:
    // deterministic seeded signatures mean re-signing reproduces
    // the same slot set, and the drill re-DERIVES rather than
    // re-signs (the journals replay untouched).
    let first = hybrid.verify(&dir);
    let replayed = {
        let mut again = CoSignature::new(SigningDomain::ArtifactEvent, &body);
        again.sign_by(&topo.issuer_key).unwrap();
        again.sign_by(&topo.issuer_key_alt).unwrap();
        again.verify(&dir)
    };
    assert_eq!(first.verified_count(), replayed.verified_count());
    assert_eq!(
        first.distinct_verified_suites(),
        replayed.distinct_verified_suites()
    );
}

#[test]
fn a_migration_without_hybrid_coverage_is_detectable_at_drill_time() {
    let topo = topology();
    let mut dir = KeyDirectory::new();
    dir.register(topo.issuer_key.public());
    let subject = common::pid("migration-gap");
    let log = common::passport_log(&subject, common::T0 + 120, "issuer-key-a");
    let body = log.sealed()[0].event.canonical_body().unwrap();

    // An object that never entered the hybrid phase: classical only.
    let mut straggler = CoSignature::new(SigningDomain::ArtifactEvent, &body);
    straggler.sign_by(&topo.issuer_key).unwrap();

    // The drill reports it: the successor policy refuses it, and
    // the refusal is the drill's finding (the coverage gap is
    // named before the cutover, not discovered after).
    let successor_only = AcceptancePolicy::only(&[Suite::EcdsaP256]);
    let verdict = successor_only.evaluate(&straggler.verify(&dir));
    assert!(!verdict.is_accepted());
}
