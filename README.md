# unidpp-signatif
Part of UniDPP (github.com/unidpp).
Rust workspace implementing the international DPP framework per
the UniDPP design framework invariants I1–I14. License: Apache-2.0.

The UniDPP trust integration: the layer that turns the core's framing
types into operations — a delegation trust graph with scoped edges,
multi-suite signatures with real computation, revocation with
retroactivity, transparency anchoring, graded verification, and the
ceremony/envelope machinery below.

## Feature flags

| Feature | What it activates |
|---|---|
| *(default: none)* | Ed25519 and ECDSA-P256 (RFC 6979) computation, unconditionally. SM2, ML-DSA and ML-KEM-768 stay framing-only: every path returns an explicit `SuiteDeferred` error, never a faked result. |
| `sm2` | SM2 (GB/T 32918 / GM/T 0003.2) real signing/verification — deterministic RFC 6979-style nonces over SM3, via the RustCrypto `sm2` crate. |
| `ml-dsa` | ML-DSA-65 (FIPS 204) seeded keygen and deterministic signing, via the `ml-dsa` crate. MlDsa44/87 remain framed either way. |
| `ml-kem` | ML-KEM-768 (FIPS 203) for envelope encryption, via the `ml-kem` crate. Without it, the envelope's PQ recipient path refuses; X25519 computes unconditionally. |
| `confium` | The Confium threshold-ceremony seam: the `CeremonyCoordinator` trait with the interface-only `MockCeremony` and the real `RealCeremony` (see below). |
| `slh-dsa` | Deliberate stub: the FIPS 205 suites refuse with `Unsupported` until a PQ binding crate passes review. |

Every combination is exercised in CI (`.github/workflows/test.yml`):
fmt, clippy `-D warnings`, and the full test suite for `""`, `sm2`,
`ml-dsa`, `ml-kem`, `sm2,ml-dsa,ml-kem`, and `confium`. Locally:

```console
$ cargo test --features sm2
$ cargo test --features "sm2,ml-dsa,ml-kem"
$ cargo test --features confium
```

## Threshold root ceremonies (M-of-K)

A root key belongs to no single key holder and no single country.
`threshold` implements that with real cryptography: Shamir shares of
degree M−1 over the Ed25519 scalar field, Feldman commitments shipped
with the group key (every member verifies their own share;
`verify_share`), and M partial signatures that Lagrange-combine into
**one standard Ed25519 signature** under the group key — verifiable by
any Ed25519 verifier, with no threshold machinery on the verifier's
side. A forged partial aborts the ceremony with the culprit's index
named; fewer than M shares reveal nothing and cannot sign.

```rust
use unidpp_signatif::threshold;

let (group, shares) = threshold::generate(b"ceremony seed", 2, 3)?;   // M-of-K
for share in &shares {
    assert!(threshold::verify_share(&group, share)?);                  // Feldman check
}
let message = b"root statement";
let nonces: Vec<_> = shares.iter().take(2)                             // the qualifying set
    .map(|s| Ok((s.index, threshold::nonce_point(s, message)?)))
    .collect::<Result<_, unidpp_signatif::SignatifError>>()?;
let partials: Vec<_> = shares.iter().take(2)
    .map(|s| threshold::sign_partial(&group, s, message, &nonces))
    .collect::<Result<_, _>>()?;
let signature = threshold::combine(&group, message, &partials)?;       // names the culprit on a bad partial
threshold::verify(&group, message, &signature)?;                       // standard Ed25519 equation
```

Behind the `confium` feature, the same protocol is driven through the
seam's session API (`confium::real::RealCeremony`, a
`CeremonyCoordinator`):
`create_session` → `submit_commitment` (nonce points) → `submit_share`
(partials) → `aggregate` (`combine`, returned as the seam's
`AggregatedSignature`, whose `to_slot()` verifies in the `Quorum`
signing domain under the registered group key). The ceremony seed
derives deterministically from the quorum spec, so participants and
tests land on the same group — which also means the derivation is
public-data-derived: a harness for tests, rehearsals and integration,
not a production root ceremony. `confium::mock::MockCeremony` stays
for interface-only tests.

### The `ceremony` binary (operator runs)

```console
$ cargo run --bin ceremony -- init --threshold 2 --members 3 --seed <HEX> --out DIR
  DIR/group.json (public), DIR/member-1.json … (SECRET)
$ cargo run --bin ceremony -- verify-share --group DIR/group.json --share DIR/member-1.json
$ cargo run --bin ceremony -- sign --group DIR/group.json \
      --share DIR/member-1.json --share DIR/member-2.json \
      --message statement.bin --out signature.json
$ cargo run --bin ceremony -- verify --group DIR/group.json \
      --signature signature.json --message statement.bin
```

Without `--seed`, `init` derives the ceremony from OS entropy
(production); `--seed` keeps a ceremony reproducible (tests,
rehearsals). The group file is public — pin it as the root anchor;
member share files travel out of band and stay confidential. A
qualifying set of exactly `--threshold` shares signs: fewer is
refused, a forged partial aborts with the culprit's index named.

## Envelope encryption per recipient KEM

One payload, one AES-256-GCM ciphertext, and the payload key wrapped
**once per recipient KEM** — each jurisdiction's allowed
key-establishment machine opens the same content, without either
learning the other's key material. X25519 (static-ephemeral ECDH +
HKDF-SHA256) always computes; ML-KEM-768 with the `ml-kem` feature.

```rust
use unidpp_signatif::envelope::{
    envelope_encrypt, envelope_open, EnvelopeSeed, KemKeyPair, KemSuite,
};

let eu = KemKeyPair::seeded(KemSuite::X25519, b"eu-recipient")?;   // production keys: CSPRNG
let seed = EnvelopeSeed::from_bytes(&[0x42; 32])?;                 // production seed: CSPRNG
let envelope = envelope_encrypt(
    b"battery chemistry: LFP",
    b"routing-context-aad",
    &[*eu.public()],
    &seed,
)?;
let opened = envelope_open(&envelope, &eu)?;                       // fails on any tampering
assert_eq!(opened, b"battery chemistry: LFP");
```

## Roll-up attestation signing

The cryptographic half of `unidpp-transform`'s roll-up: a
domain-separated signature over a traversal-set attestation's
canonical body, installed into the attestation's core slot.

```rust
use unidpp_signatif::keyring::KeyPair;
use unidpp_signatif::rollup::{check_rollup_signature, sign_rollup};
use unidpp_signatif::sign::Suite;

let key = KeyPair::seeded(Suite::EcdsaP256, b"rollup-attester")?;  // production keys: CSPRNG/HSM
// `attestation` is a RollupAttestation from unidpp-transform's
// rollup::RollupAttestation::build over a TraversalSet.
sign_rollup(&key, &mut attestation)?;
// Later, against the pinned anchor (the predicate verify_rollup takes):
check_rollup_signature(slot, body, key.public())?;
```

## Testing

```console
$ cargo fmt --all -- --check
$ cargo clippy --all-targets -- -D warnings
$ cargo test                                # default features
$ cargo test --features confium             # the ceremony seam (mock + real)
```

Licensed under [Apache-2.0](LICENSE).
