//! The 2-of-3 ceremony acceptance, end to end against the real
//! `ceremony` binary: init, every member verifies their share, two
//! shares sign, the group signature verifies; one share is refused;
//! shares from a different group are refused; a forged partial aborts
//! with the culprit named.

use std::path::PathBuf;
use std::process::Command;

fn ceremony(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_ceremony"))
        .args(args)
        .output()
        .expect("run ceremony binary");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn workdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ceremony-it-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn write(path: &PathBuf, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write fixture");
}

#[test]
fn two_of_three_ceremony_end_to_end() {
    let dir = workdir("main");
    let (ok, out, err) = ceremony(&[
        "init",
        "--threshold",
        "2",
        "--members",
        "3",
        "--seed",
        "deadbeef0011223344",
        "--out",
        dir.to_str().unwrap(),
    ]);
    assert!(ok, "init failed: {err}");
    assert!(out.contains("2-of-3 ceremony generated"), "{out}");
    let group = dir.join("group.json");
    assert!(group.exists());
    for index in 1..=3 {
        assert!(dir.join(format!("member-{index}.json")).exists());
    }

    // Every member verifies their share.
    for index in 1..=3 {
        let (ok, out, err) = ceremony(&[
            "verify-share",
            "--group",
            group.to_str().unwrap(),
            "--share",
            dir.join(format!("member-{index}.json")).to_str().unwrap(),
        ]);
        assert!(ok, "member {index}: {err}");
        assert!(out.contains("share verifies"), "{out}");
    }

    // Two shares sign.
    let message = dir.join("statement.bin");
    write(
        &message,
        b"root statement: the trust list head of 2026-09-07",
    );
    let signature = dir.join("signature.json");
    let (ok, out, err) = ceremony(&[
        "sign",
        "--group",
        group.to_str().unwrap(),
        "--share",
        dir.join("member-1.json").to_str().unwrap(),
        "--share",
        dir.join("member-2.json").to_str().unwrap(),
        "--message",
        message.to_str().unwrap(),
        "--out",
        signature.to_str().unwrap(),
    ]);
    assert!(ok, "sign failed: {err}");
    assert!(out.contains("signed by [1, 2]"), "{out}");

    // The group signature verifies.
    let (ok, out, err) = ceremony(&[
        "verify",
        "--group",
        group.to_str().unwrap(),
        "--signature",
        signature.to_str().unwrap(),
        "--message",
        message.to_str().unwrap(),
    ]);
    assert!(ok, "verify failed: {err}");
    assert!(out.contains("group signature verifies"), "{out}");

    // The signature names its qualifying set.
    let text = std::fs::read_to_string(&signature).unwrap();
    assert!(text.contains("\"signers\""));
    assert!(text.contains("ed25519-threshold-schnorr/feldman"));
}

#[test]
fn one_share_cannot_sign() {
    let dir = workdir("single");
    ceremony(&[
        "init",
        "--threshold",
        "2",
        "--members",
        "3",
        "--seed",
        "cafebabe",
        "--out",
        dir.to_str().unwrap(),
    ]);
    let group = dir.join("group.json");
    let message = dir.join("m.bin");
    write(&message, b"m");
    let (ok, _out, err) = ceremony(&[
        "sign",
        "--group",
        group.to_str().unwrap(),
        "--share",
        dir.join("member-1.json").to_str().unwrap(),
        "--message",
        message.to_str().unwrap(),
    ]);
    assert!(!ok, "one share must not sign");
    assert!(err.contains("exactly 2 shares"), "{err}");
}

#[test]
fn shares_from_a_different_group_are_refused() {
    let a = workdir("group-a");
    let b = workdir("group-b");
    ceremony(&[
        "init",
        "--threshold",
        "2",
        "--members",
        "3",
        "--seed",
        "0a0a",
        "--out",
        a.to_str().unwrap(),
    ]);
    ceremony(&[
        "init",
        "--threshold",
        "2",
        "--members",
        "3",
        "--seed",
        "0b0b",
        "--out",
        b.to_str().unwrap(),
    ]);
    // A's member 1 verifies against A's group...
    let (ok, _, _) = ceremony(&[
        "verify-share",
        "--group",
        a.join("group.json").to_str().unwrap(),
        "--share",
        a.join("member-1.json").to_str().unwrap(),
    ]);
    assert!(ok);
    // ...but not against B's.
    let (ok, out, err) = ceremony(&[
        "verify-share",
        "--group",
        b.join("group.json").to_str().unwrap(),
        "--share",
        a.join("member-1.json").to_str().unwrap(),
    ]);
    assert!(!ok);
    assert!(err.contains("does NOT match"), "{err}");
    assert!(out.is_empty());

    // Mixed-group signing: B's member-2's share is a different
    // polynomial — its partial fails the commitment check, the culprit
    // is named.
    let message = a.join("m.bin");
    write(&message, b"m");
    let (ok, _out, err) = ceremony(&[
        "sign",
        "--group",
        a.join("group.json").to_str().unwrap(),
        "--share",
        a.join("member-1.json").to_str().unwrap(),
        "--share",
        b.join("member-2.json").to_str().unwrap(),
        "--message",
        message.to_str().unwrap(),
    ]);
    assert!(!ok, "a mixed-group set must not sign");
    assert!(
        err.contains("member 2") && err.contains("invalid partial"),
        "the culprit must be named: {err}"
    );
}

#[test]
fn a_tampered_share_is_caught_at_verify_share() {
    let dir = workdir("tampered");
    ceremony(&[
        "init",
        "--threshold",
        "2",
        "--members",
        "3",
        "--seed",
        "cccc",
        "--out",
        dir.to_str().unwrap(),
    ]);
    let share_path = dir.join("member-2.json");
    let text = std::fs::read_to_string(&share_path).unwrap();
    // Flip one hex digit of the share scalar (still 64 chars, so the
    // tamper reaches the commitment check, not the parser).
    let mut bytes = text.into_bytes();
    if let Some(position) = bytes.windows(10).position(|w| w == b"\"share\": \"") {
        let digit = position + 10;
        bytes[digit] = if bytes[digit] == b'0' { b'1' } else { b'0' };
    }
    std::fs::write(&share_path, bytes).unwrap();
    let (ok, _out, err) = ceremony(&[
        "verify-share",
        "--group",
        dir.join("group.json").to_str().unwrap(),
        "--share",
        share_path.to_str().unwrap(),
    ]);
    assert!(!ok);
    assert!(err.contains("does NOT match"), "{err}");
}
