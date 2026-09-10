//! CN-2 golden vectors: the canonical bytes and digests of the
//! sovereign attestation statement, pinned as versioned fixtures
//! and replayed in CI (spec Annex B, B.4). The statement's canonical
//! form is what the service signs in the SOVEREIGN-ATTESTATION
//! domain and what the quorum co-signs in the QUORUM domain.
//! Regeneration: UNIDPP_UPDATE_FIXTURES=1 cargo test.

use unidpp_signatif::sovereign::{AttestationStatement, ClaimClass};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn check(name: &str, value: serde_json::Value) {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/canonical");
    let path = format!("{dir}/{name}");
    if std::env::var("UNIDPP_UPDATE_FIXTURES").is_ok() {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        return;
    }
    let pinned: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("fixture {name} unreadable ({e}); regenerate with UNIDPP_UPDATE_FIXTURES=1")
        }))
        .unwrap();
    assert_eq!(
        pinned, value,
        "{name}: canonical-form drift — if intended, regenerate with \
         UNIDPP_UPDATE_FIXTURES=1 and review the diff"
    );
}

#[test]
fn vector_attestation_statement() {
    let statement = AttestationStatement {
        segment: "cn-dynamic".into(),
        state_commitment: [0x42; 32],
        claim: ClaimClass::Conformity,
        value: "pass".into(),
        as_of: "2030-06-01T08:00:00Z".into(),
        governing_policy: "cn-dynamic-bms".into(),
        governing_policy_version: 1,
        subject: "urn:unidpp:passport:pack-0001".into(),
    };
    check(
        "attestation-statement.json",
        serde_json::json!({
            "version": 1,
            "family": "signatif/attestation-statement",
            "signing_domain": "UNIDPP-SIGNATIF/SOVEREIGN-ATTESTATION",
            "quorum_domain": "UNIDPP-SIGNATIF/QUORUM",
            "statement": serde_json::to_value(&statement).unwrap(),
            "canonical_hex": hex(&statement.canonical_bytes()),
            "digest_hex": hex(&statement.digest()),
        }),
    );
}
