//! The device-credential drill (ID-5 / RC-2's demonstration step).
//!
//! Real machinery from `unidpp_signatif::device`: the worked example
//! as a narrated, self-asserting runner — the manufacture-time
//! certificate binding the device key to the static segment's
//! commitment, per-segment operational slot keys certified by their
//! segment authority, attestation path-finding through the chain,
//! wrong-segment refusal, revocation scoped to one slot-key chain
//! (the other segment unaffected), forged-credential refusal, and
//! the edge-commitment law: commit first, reveal later, never
//! contradict.
//!
//! Every step prints the fact it just proved; any failure aborts
//! with a non-zero exit. The demonstration beat (G-DEVICE) drives
//! this binary.

use unidpp_signatif::device::{
    slot_standing, verify_reveal, DeviceCertificate, EdgeCommitment, RevealVerdict, SlotCredential,
    SlotStanding,
};
use unidpp_signatif::graph::{DelegationNode, NodeKind, RegisteredKey, TrustGraph};
use unidpp_signatif::keyring::{KeyId, KeyPair};
use unidpp_signatif::sign::Suite;
use unidpp_signatif::SignatifError;

fn say(what: &str) {
    println!("    {what}");
}

fn ok(what: &str) {
    println!("  \x1b[32m[ok]\x1b[0m   {what}");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn fail(what: &str) -> ! {
    eprintln!("device-drill: FAILED — {what}");
    std::process::exit(1);
}

fn main() {
    // The cast: a manufacturer, one segment authority, and one
    // device with two operational segments.
    let maker = KeyPair::seeded(Suite::Ed25519, b"drill/maker").expect("seed");
    let authority = KeyPair::seeded(Suite::Ed25519, b"drill/samr").expect("seed");
    let device_key = KeyPair::seeded(Suite::Ed25519, b"drill/device").expect("seed");
    let bms_slot = KeyPair::seeded(Suite::Ed25519, b"drill/slot-bms").expect("seed");
    let tpms_slot = KeyPair::seeded(Suite::Ed25519, b"drill/slot-tpms").expect("seed");

    let mut graph = TrustGraph::new();
    for (id, key) in [("momiji", &maker), ("cn-samr", &authority)] {
        let mut node = DelegationNode::new(
            unidpp_signatif::graph::NodeId::new(id).expect("node id"),
            NodeKind::Delegated,
        );
        node.register(RegisteredKey {
            key_id: KeyId::of(key.public()),
            public: *key.public(),
        });
        graph.add_node(node);
    }

    println!("device-drill — the device as a cryptographic principal (ID-5, RC-2)");
    println!("----------------------------------------------------------------------");

    // 1. The manufacture-time certificate.
    let static_commitment = unidpp_model::sha256(&[b"pack-0001 static state"]).0;
    let certificate = DeviceCertificate::issue(
        "urn:unidpp:device:pack-0001",
        &hex(device_key.public().as_bytes()),
        "static",
        static_commitment,
        "momiji",
        &maker,
    )
    .unwrap_or_else(|e: SignatifError| fail(&e.to_string()));
    certificate
        .verify(&graph)
        .unwrap_or_else(|e| fail(&format!("the manufacture certificate: {e}")));
    ok("the manufacture certificate binds the device key to the static segment's commitment");

    // 2. Per-segment slot credentials.
    let bms = SlotCredential::issue(
        "urn:unidpp:device:pack-0001",
        &hex(bms_slot.public().as_bytes()),
        "cn-dynamic",
        "cn-samr",
        "2027-01-01T00:00:00Z",
        None,
        &authority,
    )
    .expect("bms credential");
    let tpms = SlotCredential::issue(
        "urn:unidpp:device:pack-0001",
        &hex(tpms_slot.public().as_bytes()),
        "eu-static",
        "cn-samr",
        "2027-01-01T00:00:00Z",
        None,
        &authority,
    )
    .expect("tpms credential");
    let credentials = vec![bms.clone(), tpms.clone()];
    say("two operational slot keys, each certified for ITS segment by cn-samr");

    // 3. Path-finding.
    match slot_standing(
        &credentials,
        "urn:unidpp:device:pack-0001",
        &hex(bms_slot.public().as_bytes()),
        "cn-dynamic",
        &graph,
        &[],
    ) {
        SlotStanding::Certified { authority } if authority == "cn-samr" => {
            ok("a cn-dynamic attestation path-finds: device key - slot credential - cn-samr");
        }
        other => fail(&format!("expected certification, got {other:?}")),
    }

    // 4. Wrong-segment refusal.
    match slot_standing(
        &credentials,
        "urn:unidpp:device:pack-0001",
        &hex(bms_slot.public().as_bytes()),
        "eu-static",
        &graph,
        &[],
    ) {
        SlotStanding::NoChain { reason } if reason.contains("not the claimed") => {
            ok("the bms slot claiming eu-static is refused, the credential and claim named");
        }
        other => fail(&format!("expected wrong-segment refusal, got {other:?}")),
    }

    // 5. Scoped revocation.
    let revoked = vec![hex(bms_slot.public().as_bytes())];
    match slot_standing(
        &credentials,
        "urn:unidpp:device:pack-0001",
        &hex(bms_slot.public().as_bytes()),
        "cn-dynamic",
        &graph,
        &revoked,
    ) {
        SlotStanding::Revoked { segment, .. } if segment == "cn-dynamic" => {
            ok("revoking the bms slot-key chain kills cn-dynamic attestations only");
        }
        other => fail(&format!("expected scoped revocation, got {other:?}")),
    }
    match slot_standing(
        &credentials,
        "urn:unidpp:device:pack-0001",
        &hex(tpms_slot.public().as_bytes()),
        "eu-static",
        &graph,
        &revoked,
    ) {
        SlotStanding::Certified { .. } => {
            ok("the tpms slot's eu-static attestations are unaffected — scope is the key, not the device");
        }
        other => fail(&format!("the unaffected segment wavered: {other:?}")),
    }

    // 6. A forged credential.
    let impostor = KeyPair::seeded(Suite::Ed25519, b"drill/impostor").expect("seed");
    let forged = SlotCredential::issue(
        "urn:unidpp:device:pack-0001",
        &hex(bms_slot.public().as_bytes()),
        "cn-dynamic",
        "cn-samr",
        "2027-01-01T00:00:00Z",
        None,
        &impostor,
    )
    .expect("forged");
    match slot_standing(
        &[forged],
        "urn:unidpp:device:pack-0001",
        &hex(bms_slot.public().as_bytes()),
        "cn-dynamic",
        &graph,
        &[],
    ) {
        SlotStanding::NoChain { reason } if reason.contains("does not verify") => {
            ok("a forged credential signed by a non-authority key fails the graph");
        }
        other => fail(&format!("a forged credential stood: {other:?}")),
    }

    // 7. The edge-commitment law.
    let prefix = b"bms events 0..42, canonical bytes";
    let commitment =
        EdgeCommitment::commit("urn:unidpp:device:pack-0001", "cn-dynamic", 42, prefix);
    match verify_reveal(&commitment, 42, prefix) {
        RevealVerdict::Consistent => {
            ok("commit first, reveal later: the reveal recomputes the prior commitment");
        }
        other => fail(&format!("the consistent reveal wavered: {other:?}")),
    }
    match verify_reveal(&commitment, 42, b"bms events 0..42, EDITED bytes") {
        RevealVerdict::Contradicted { .. } => {
            ok("an edited reveal is REJECTED — never contradict a prior commitment");
        }
        other => fail(&format!("a contradiction passed: {other:?}")),
    }
    match verify_reveal(&commitment, 41, prefix) {
        RevealVerdict::Contradicted { .. } => {
            ok("a shortened reveal is rejected too — the prefix length is committed");
        }
        other => fail(&format!("a length contradiction passed: {other:?}")),
    }

    println!("----------------------------------------------------------------------");
    println!("device-drill: 10/10 — the device is a principal, revocation is scoped, and the edge never contradicts");
}
