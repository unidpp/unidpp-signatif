//! CN-2 golden vectors: the canonical bytes and digests of the
//! sovereign attestation statement, pinned as versioned fixtures
//! and replayed in CI (spec Annex B, B.4). The statement's canonical
//! form is what the service signs in the SOVEREIGN-ATTESTATION
//! domain and what the quorum co-signs in the QUORUM domain.
//! Regeneration: UNIDPP_UPDATE_FIXTURES=1 cargo test.

use unidpp_grid::{PolicyObject, RevealClass};
use unidpp_s13::{S13Request, S13Response};
use unidpp_signatif::declaration::{
    ClassPosture, HarmonizationLevel, InteropDeclaration, RecognitionMode, TransportMode,
};
use unidpp_signatif::frozen::FrozenView;
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

#[test]
fn vector_frozen_view() {
    let (view, _graph) = unidpp_signatif::frozen::example::battery_view();
    check(
        "frozen-view.json",
        serde_json::json!({
            "version": 1,
            "family": "signatif/frozen-view",
            "note": "SI-1's worked example — the battery frozen view (payload + 5-axis descriptor + lens + spine-proved inputs + dossier bundle + instructions)",
            "view": serde_json::to_value(&view).unwrap(),
            "canonical_hex": hex(&view.canonical_bytes()),
            "digest_hex": hex(&view.digest()),
        }),
    );
    // The example must satisfy its own contract (the fixture pins a
    // VALID view, not just any bytes).
    let json = serde_json::to_string(&view).unwrap();
    let back: FrozenView = serde_json::from_str(&json).unwrap();
    assert_eq!(back.digest(), view.digest());
}

#[test]
fn vector_interop_declaration() {
    // A signed declaration of the EU battery scheme's posture toward
    // its CN counterpart: two postures (the named class and the "*"
    // fallback), issued by a seeded declarer key whose public hex
    // rides the fixture — the foreign harness verifies the signature
    // without a trust graph (the graph is the suite's reading).
    let key = unidpp_signatif::keyring::KeyPair::seeded(
        unidpp_signatif::sign::Suite::Ed25519,
        b"decl/eu-battery-scheme",
    )
    .unwrap();
    let declaration = InteropDeclaration::issue(
        "eu-battery-scheme",
        "cn-battery-scheme",
        1,
        vec![
            ClassPosture {
                data_class: "*".into(),
                level: HarmonizationLevel::L1,
                recognition: RecognitionMode::BilateralAnchors,
                transports: vec![TransportMode::Document],
                escalation: None,
                reciprocity: None,
            },
            ClassPosture {
                data_class: "battery.dynamic-state".into(),
                level: HarmonizationLevel::L3,
                recognition: RecognitionMode::MasterListMesh,
                transports: vec![TransportMode::Hub, TransportMode::Protocol],
                escalation: Some("urn:unidpp:ceremony:eu-cn-escalation@1".into()),
                reciprocity: Some("urn:unidpp:treaty:eu-cn-mra@2".into()),
            },
        ],
        "2030-01-01T00:00:00Z",
        None,
        &key,
    )
    .unwrap();
    check(
        "interop-declaration.json",
        serde_json::json!({
            "version": 1,
            "family": "signatif/interop-declaration",
            "declaration": serde_json::to_value(&declaration).unwrap(),
            "declarer_public_hex": hex(key.public().as_bytes()),
            "canonical_hex": hex(&declaration.canonical_bytes()),
            "digest_hex": hex(&declaration.digest()),
        }),
    );
}

#[test]
fn vector_s13_signed_exchange() {
    // The F2 class material as data: a verifier-signed request and
    // the custodian's signed response over the canonical-fixtures'
    // request/response objects, both publics riding the fixture so
    // the foreign harness verifies the S13-MESSAGE signatures
    // without a trust graph.
    let verifier_key = unidpp_signatif::keyring::KeyPair::seeded(
        unidpp_signatif::sign::Suite::Ed25519,
        b"s13/de-zoll",
    )
    .unwrap();
    let custodian_key = unidpp_signatif::keyring::KeyPair::seeded(
        unidpp_signatif::sign::Suite::Ed25519,
        b"s13/weilian",
    )
    .unwrap();
    let request = S13Request {
        verifier: "de-zoll".into(),
        subject: "urn:unidpp:passport:pack-0001".into(),
        profile: "urn:unidpp:profile:eu-battery".into(),
        segment: "cn-dynamic".into(),
        at: "2030-06-01T08:00:00Z".into(),
    };
    let policy = PolicyObject {
        policy_id: "cn-dynamic-bms".into(),
        version: 1,
        authority: "cn-samr".into(),
        readers: vec!["cn-customs".into()],
        verifiers: vec!["cn-customs".into(), "de-zoll".into()],
        writers: vec!["weilian-shenzhen".into()],
        reveal: RevealClass::OriginSealed,
        suites: vec!["sm2".into()],
        valid_from: "2027-01-01T00:00:00Z".into(),
        valid_to: None,
        superseded_by: None,
    };
    let signed_request =
        unidpp_signatif::s13::SignedS13Request::issue(request, "de-zoll", &verifier_key).unwrap();
    let response = S13Response::evaluate(&signed_request.request, &policy, "weilian-shenzhen");
    let signed_response =
        unidpp_signatif::s13::SignedS13Response::issue(response, &custodian_key).unwrap();
    check(
        "s13-signed-exchange.json",
        serde_json::json!({
            "version": 1,
            "family": "signatif/s13-signed-exchange",
            "policy": serde_json::to_value(&policy).unwrap(),
            "signed_request": serde_json::to_value(&signed_request).unwrap(),
            "requester_public_hex": hex(verifier_key.public().as_bytes()),
            "signed_response": serde_json::to_value(&signed_response).unwrap(),
            "responder_public_hex": hex(custodian_key.public().as_bytes()),
        }),
    );
}
