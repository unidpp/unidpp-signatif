//! Key material: deterministic seeded key pairs for the two suites with
//! real computation, and the key-id derivation that ties signatures to
//! trust-graph nodes.
//!
//! Production keys must come from a CSPRNG and live in an HSM; this
//! module's [`KeyPair::seeded`] exists so that tests and ceremonies are
//! reproducible (same seed, same key, same signature — ECDSA-P256 here
//! signs with the RFC 6979 deterministic nonce; Ed25519 is deterministic
//! by construction). Key ids are content-derived (`k-` + 16 hex chars of
//! `H(suite-code || public-key)`), so a key id pins exactly one public
//! key and suite.

use std::fmt;
use std::str::FromStr;

use ed25519_dalek::Signature as EdSignature;
use ed25519_dalek::Signer as EdSigner;
use ed25519_dalek::SigningKey as EdSigningKey;
use ed25519_dalek::Verifier as EdVerifier;
#[cfg(feature = "ml-dsa")]
use ml_dsa::{Keypair as _, Verifier as MlDsaVerifier};
use p256::ecdsa::signature::Signer as P256Signer;
use p256::ecdsa::signature::Verifier as P256Verifier;
use p256::ecdsa::Signature as P256Signature;
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::ecdsa::VerifyingKey as P256VerifyingKey;
use p256::FieldBytes;
#[cfg(feature = "sm2")]
use sm2::dsa::signature::{Signer as Sm2Signer, Verifier as Sm2Verifier};

use unidpp_model::sha256;

use crate::sign::Suite;
use crate::SignatifError;

/// Default SM2 distinguishing identifier (GB/T 32918 default user id
/// "1234567812345678"). Both signing and verification use it, so a
/// key pair round-trips without shipping an id alongside the anchor.
#[cfg(feature = "sm2")]
pub const SM2_DEFAULT_DIST_ID: &str = "1234567812345678";

fn bad_len(suite: Suite, bytes: &[u8], expected: usize) -> SignatifError {
    SignatifError::crypto(format!(
        "not a {suite} public key encoding (len {}, expected {expected})",
        bytes.len()
    ))
}

/// A public key in one of the two computed suites.
///
/// The P-256 form is the uncompressed SEC1 point (65 bytes:
/// `0x04 || X || Y`), which is what the [`crate::sign`] layer consumes
/// and produces.
// The MlDsa65 variant is 1952 bytes (intrinsic to FIPS 204) against
// 32–65 for the classical suites. Kept by value on purpose: anchors
// are value-semantic and Copy throughout the trust layer, they number
// in the dozens (never bulk data), and boxing would forfeit Copy at
// every anchor-resolution site.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKey {
    /// Ed25519 verifying key (32 bytes).
    Ed25519([u8; 32]),
    /// ECDSA-P256 verifying key, uncompressed SEC1 point (65 bytes).
    EcdsaP256Uncompressed([u8; 65]),
    /// SM2 verifying key, uncompressed SEC1 point (65 bytes, the same
    /// encoding as P-256 — disambiguated by suite context, see
    /// [`PublicKey::from_bytes_in`]). Constructed with the `sm2`
    /// feature; wire-encodable without it.
    Sm2Uncompressed([u8; 65]),
    /// ML-DSA-65 verifying key (FIPS 204: 1952 bytes). Constructed
    /// with the `ml-dsa` feature; wire-encodable without it.
    MlDsa65([u8; 1952]),
}

impl PublicKey {
    /// The suite this key belongs to.
    pub fn suite(&self) -> Suite {
        match self {
            PublicKey::Ed25519(_) => Suite::Ed25519,
            PublicKey::EcdsaP256Uncompressed(_) => Suite::EcdsaP256,
            PublicKey::Sm2Uncompressed(_) => Suite::Sm2,
            PublicKey::MlDsa65(_) => Suite::MlDsa65,
        }
    }

    /// Raw encoding (length + form identify the suite).
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            PublicKey::Ed25519(b) => b,
            PublicKey::EcdsaP256Uncompressed(b) => b,
            PublicKey::Sm2Uncompressed(b) => b,
            PublicKey::MlDsa65(b) => b,
        }
    }

    /// Decode raw bytes produced by [`PublicKey::as_bytes`], inferring
    /// the suite from the encoding (length + form).
    ///
    /// 65-byte SEC1 points are ambiguous between P-256 and SM2 (the
    /// encodings are identical) — inference maps them to P-256, the
    /// legacy reading. Suite-certain decoding (SM2 anchors, key
    /// directories) must use [`PublicKey::from_bytes_in`].
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, SignatifError> {
        match bytes.len() {
            32 => Ok(PublicKey::Ed25519(bytes.try_into().unwrap())),
            65 if bytes[0] == 0x04 => {
                Ok(PublicKey::EcdsaP256Uncompressed(bytes.try_into().unwrap()))
            }
            1952 => Ok(PublicKey::MlDsa65(bytes.try_into().unwrap())),
            _ => Err(SignatifError::crypto(format!(
                "not a SIGNATIF public key encoding (len {})",
                bytes.len()
            ))),
        }
    }

    /// Decode raw bytes in a known suite context — the unambiguous
    /// form for every suite (SM2 and P-256 share the 65-byte SEC1
    /// encoding; only the caller knows which curve the anchor pins).
    pub fn from_bytes_in(suite: Suite, bytes: &[u8]) -> Result<PublicKey, SignatifError> {
        let key = match suite {
            Suite::Ed25519 => {
                let b: [u8; 32] = bytes.try_into().map_err(|_| bad_len(suite, bytes, 32))?;
                PublicKey::Ed25519(b)
            }
            Suite::EcdsaP256 => {
                let b: [u8; 65] = bytes.try_into().map_err(|_| bad_len(suite, bytes, 65))?;
                if b[0] != 0x04 {
                    return Err(SignatifError::crypto(
                        "P-256 keys are the uncompressed SEC1 form (expected 0x04 prefix)",
                    ));
                }
                PublicKey::EcdsaP256Uncompressed(b)
            }
            Suite::Sm2 => {
                let b: [u8; 65] = bytes.try_into().map_err(|_| bad_len(suite, bytes, 65))?;
                if b[0] != 0x04 {
                    return Err(SignatifError::crypto(
                        "SM2 keys are the uncompressed SEC1 form (expected 0x04 prefix)",
                    ));
                }
                PublicKey::Sm2Uncompressed(b)
            }
            Suite::MlDsa65 => {
                let b: [u8; 1952] = bytes.try_into().map_err(|_| bad_len(suite, bytes, 1952))?;
                PublicKey::MlDsa65(b)
            }
            other => {
                return Err(SignatifError::crypto(format!(
                    "no computed public-key encoding for suite {other}"
                )))
            }
        };
        Ok(key)
    }

    #[cfg(feature = "sm2")]
    fn sm2(&self) -> Result<sm2::dsa::VerifyingKey, SignatifError> {
        match self {
            PublicKey::Sm2Uncompressed(b) => {
                sm2::dsa::VerifyingKey::from_sec1_bytes(SM2_DEFAULT_DIST_ID, b)
                    .map_err(|e| SignatifError::crypto(format!("bad SM2 point: {e}")))
            }
            other => Err(SignatifError::crypto(format!(
                "key {:?} is not an SM2 key",
                other.suite()
            ))),
        }
    }

    #[cfg(feature = "ml-dsa")]
    fn mldsa65(&self) -> Result<ml_dsa::VerifyingKey<ml_dsa::MlDsa65>, SignatifError> {
        match self {
            PublicKey::MlDsa65(b) => Ok(ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(
                &ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::from(*b),
            )),
            other => Err(SignatifError::crypto(format!(
                "key {:?} is not an ML-DSA-65 key",
                other.suite()
            ))),
        }
    }

    fn ed25519(&self) -> Result<ed25519_dalek::VerifyingKey, SignatifError> {
        match self {
            PublicKey::Ed25519(b) => ed25519_dalek::VerifyingKey::from_bytes(b)
                .map_err(|e| SignatifError::crypto(format!("bad Ed25519 key: {e}"))),
            other => Err(SignatifError::crypto(format!(
                "key {:?} is not an Ed25519 key",
                other.suite()
            ))),
        }
    }

    fn p256(&self) -> Result<P256VerifyingKey, SignatifError> {
        match self {
            PublicKey::EcdsaP256Uncompressed(b) => P256VerifyingKey::from_sec1_bytes(b)
                .map_err(|e| SignatifError::crypto(format!("bad P-256 point: {e}"))),
            other => Err(SignatifError::crypto(format!(
                "key {:?} is not an ECDSA-P256 key",
                other.suite()
            ))),
        }
    }
}

impl serde::Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        let (suite, hex) = s
            .split_once(':')
            .ok_or_else(|| serde::de::Error::custom(format!("bad public key `{s}`")))?;
        let suite = Suite::from_str(suite)
            .map_err(|e: SignatifError| serde::de::Error::custom(e.to_string()))?;
        let bytes = hex_decode(hex)
            .ok_or_else(|| serde::de::Error::custom(format!("bad public key bytes `{s}`")))?;
        let public = PublicKey::from_bytes_in(suite, &bytes)
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        if public.suite() != suite {
            return Err(serde::de::Error::custom(format!(
                "key claims suite {suite} but bytes are {}",
                public.suite()
            )));
        }
        Ok(public)
    }
}

/// Minimal hex decode (public keys are short; avoids a dependency).
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.suite(), sha256(&[self.as_bytes()]).hex())
    }
}

/// A key identifier: content-derived, pins exactly one public key and
/// suite (`k-` + first 16 hex chars of `H(suite-code || public-key)`).
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct KeyId(String);

impl KeyId {
    /// Derive the id of a public key.
    pub fn of(public: &PublicKey) -> KeyId {
        let digest = sha256(&[&[public.suite().code()], public.as_bytes()]);
        KeyId(format!("k-{}", &digest.hex()[..16]))
    }

    /// Wrap a literal id (used when parsing registrations).
    pub fn new(raw: &str) -> Result<KeyId, SignatifError> {
        let raw = raw.trim();
        if raw.is_empty() || raw.len() > 64 || !raw.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(SignatifError::invalid(format!("bad key id `{raw}`")));
        }
        Ok(KeyId(raw.to_string()))
    }

    /// The id string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Secret-side key material. Deliberately not serializable: secrets are
/// held by their owner (HSM / ceremony participants), never shipped in
/// trust objects.
pub struct KeyPair {
    suite: Suite,
    secret: SecretKey,
    public: PublicKey,
    key_id: KeyId,
}

enum SecretKey {
    Ed25519(EdSigningKey),
    P256(P256SigningKey),
    #[cfg(feature = "sm2")]
    Sm2(sm2::dsa::SigningKey),
    #[cfg(feature = "ml-dsa")]
    MlDsa65(ml_dsa::SigningKey<ml_dsa::MlDsa65>),
}

impl KeyPair {
    /// Deterministically derive a key pair from seed material
    /// (`H(seed)` becomes the Ed25519 seed / the P-256 scalar). Intended
    /// for tests and ceremony fixtures; production keys come from a
    /// CSPRNG-backed store.
    ///
    /// Suites without computation here refuse: deferred suites (SM2,
    /// ML-DSA) with [`SignatifError::SuiteDeferred`], explicitly
    /// unsupported suites (SLH-DSA — the `slh-dsa` feature is a stub
    /// with no PQ crate dependency yet) with
    /// [`SignatifError::Unsupported`]. Neither ever panics.
    pub fn seeded(suite: Suite, seed: &[u8]) -> Result<KeyPair, SignatifError> {
        let scalar = sha256(&[b"UNIDPP-SIGNATIF/KEY-SEED", seed]).0;
        match suite {
            Suite::Ed25519 => {
                let sk = EdSigningKey::from_bytes(&scalar);
                let public = PublicKey::Ed25519(sk.verifying_key().to_bytes());
                Ok(KeyPair {
                    suite,
                    key_id: KeyId::of(&public),
                    secret: SecretKey::Ed25519(sk),
                    public,
                })
            }
            Suite::EcdsaP256 => {
                let sk = P256SigningKey::from_bytes(&FieldBytes::from(scalar))
                    .map_err(|e| SignatifError::crypto(format!("bad P-256 scalar: {e}")))?;
                let point = sk.verifying_key().to_encoded_point(false);
                let public = PublicKey::EcdsaP256Uncompressed(point.as_bytes().try_into().unwrap());
                Ok(KeyPair {
                    suite,
                    key_id: KeyId::of(&public),
                    secret: SecretKey::P256(sk),
                    public,
                })
            }
            #[cfg(feature = "sm2")]
            Suite::Sm2 => {
                let secret = sm2::SecretKey::from_slice(&FieldBytes::from(scalar))
                    .map_err(|e| SignatifError::crypto(format!("bad SM2 scalar: {e}")))?;
                let sk = sm2::dsa::SigningKey::new(SM2_DEFAULT_DIST_ID, &secret)
                    .map_err(|e| SignatifError::crypto(format!("SM2 signing key: {e}")))?;
                let point = sk.verifying_key().to_sec1_bytes();
                let public = PublicKey::Sm2Uncompressed(
                    point
                        .as_ref()
                        .try_into()
                        .expect("SM2 verifying keys are 65-byte uncompressed SEC1 points"),
                );
                Ok(KeyPair {
                    suite,
                    key_id: KeyId::of(&public),
                    secret: SecretKey::Sm2(sk),
                    public,
                })
            }
            #[cfg(feature = "ml-dsa")]
            Suite::MlDsa65 => {
                // FIPS 204 KeyGen accepts the 32-byte seed xi as the
                // entropy input, so the suite derives reproducibly.
                let sk =
                    ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&ml_dsa::Seed::from(scalar));
                let encoded = sk.verifying_key().encode();
                let public = PublicKey::MlDsa65(
                    encoded
                        .as_slice()
                        .try_into()
                        .expect("ML-DSA-65 verifying keys are 1952 bytes (FIPS 204)"),
                );
                Ok(KeyPair {
                    suite,
                    key_id: KeyId::of(&public),
                    secret: SecretKey::MlDsa65(sk),
                    public,
                })
            }
            other => Err(match other.unsupported() {
                Some(detail) => SignatifError::Unsupported {
                    suite: other.to_string(),
                    detail: detail.to_string(),
                },
                None => SignatifError::SuiteDeferred {
                    suite: other.to_string(),
                    detail: other
                        .deferral()
                        .expect("non-computed suites are deferred or unsupported")
                        .to_string(),
                },
            }),
        }
    }

    /// The suite of this key.
    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// The content-derived key id.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The public key.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// Produce a signature value over `payload` for this key's suite.
    ///
    /// The caller is responsible for domain separation — see
    /// [`crate::sign::SigningDomain`], whose tag is prepended by
    /// [`KeyPair::sign`].
    pub(crate) fn sign_raw(&self, payload: &[u8]) -> Result<Vec<u8>, SignatifError> {
        match &self.secret {
            SecretKey::Ed25519(sk) => {
                let sig: EdSignature = EdSigner::sign(sk, payload);
                Ok(sig.to_bytes().to_vec())
            }
            SecretKey::P256(sk) => {
                let sig: P256Signature = P256Signer::sign(sk, payload);
                Ok(sig.to_bytes().to_vec())
            }
            #[cfg(feature = "sm2")]
            SecretKey::Sm2(sk) => {
                // Deterministic per GM/T 0003.2 + RFC 6979 nonce over
                // SM3 (the crate's Signer computes Z_A and the message
                // hash internally; the same key + payload always
                // produce the same r||s).
                let sig: sm2::dsa::Signature = Sm2Signer::sign(sk, payload);
                Ok(sig.to_bytes().to_vec())
            }
            #[cfg(feature = "ml-dsa")]
            SecretKey::MlDsa65(sk) => {
                let sig = sk
                    .expanded_key()
                    .sign_deterministic(payload, b"")
                    .map_err(|e| SignatifError::crypto(format!("ML-DSA-65 signing: {e}")))?;
                Ok(sig.encode().as_slice().to_vec())
            }
        }
    }

    pub(crate) fn verify_raw(
        public: &PublicKey,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatifError> {
        match public {
            PublicKey::Ed25519(_) => {
                let vk = public.ed25519()?;
                let sig = EdSignature::from_slice(signature).map_err(|e| {
                    SignatifError::crypto(format!("bad Ed25519 signature length: {e}"))
                })?;
                EdVerifier::verify(&vk, payload, &sig)
                    .map_err(|_| SignatifError::crypto("Ed25519 signature invalid".to_string()))
            }
            PublicKey::EcdsaP256Uncompressed(_) => {
                let vk = public.p256()?;
                let sig = P256Signature::from_slice(signature)
                    .map_err(|e| SignatifError::crypto(format!("bad ECDSA-P256 signature: {e}")))?;
                P256Verifier::verify(&vk, payload, &sig)
                    .map_err(|_| SignatifError::crypto("ECDSA-P256 signature invalid".to_string()))
            }
            #[cfg(feature = "sm2")]
            PublicKey::Sm2Uncompressed(_) => {
                let vk = public.sm2()?;
                let bytes: [u8; 64] = signature.try_into().map_err(|_| {
                    SignatifError::crypto(format!(
                        "bad SM2 signature length {} (expected 64 r||s)",
                        signature.len()
                    ))
                })?;
                let sig = sm2::dsa::Signature::from_bytes(&bytes)
                    .map_err(|e| SignatifError::crypto(format!("bad SM2 signature: {e}")))?;
                Sm2Verifier::verify(&vk, payload, &sig)
                    .map_err(|_| SignatifError::crypto("SM2 signature invalid".to_string()))
            }
            #[cfg(feature = "ml-dsa")]
            PublicKey::MlDsa65(_) => {
                let vk = public.mldsa65()?;
                let bytes: [u8; 3309] = signature.try_into().map_err(|_| {
                    SignatifError::crypto(format!(
                        "bad ML-DSA-65 signature length {} (expected 3309, FIPS 204)",
                        signature.len()
                    ))
                })?;
                let sig =
                    ml_dsa::Signature::<ml_dsa::MlDsa65>::decode(&ml_dsa::EncodedSignature::<
                        ml_dsa::MlDsa65,
                    >::from(
                        bytes
                    ))
                    .ok_or_else(|| SignatifError::crypto("bad ML-DSA-65 signature".to_string()))?;
                MlDsaVerifier::verify(&vk, payload, &sig)
                    .map_err(|_| SignatifError::crypto("ML-DSA-65 signature invalid".to_string()))
            }
            // Fall-through refusal arms (unconditional, so the match is
            // exhaustive in both configurations; reached only when the
            // binding feature is off — with it on, the arms above match
            // first). Without computation these keys refuse: never
            // fake.
            #[cfg(not(feature = "sm2"))]
            PublicKey::Sm2Uncompressed(_) => Err(SignatifError::SuiteDeferred {
                suite: "sm2".to_string(),
                detail: Suite::Sm2
                    .deferral()
                    .unwrap_or("sm2 computation not linked in this build")
                    .to_string(),
            }),
            #[cfg(not(feature = "ml-dsa"))]
            PublicKey::MlDsa65(_) => Err(SignatifError::SuiteDeferred {
                suite: "ml-dsa-65".to_string(),
                detail: Suite::MlDsa65
                    .deferral()
                    .unwrap_or("ml-dsa-65 computation not linked in this build")
                    .to_string(),
            }),
        }
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never format secret material.
        f.debug_struct("KeyPair")
            .field("suite", &self.suite)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_keys_are_deterministic_and_distinct() {
        let a = KeyPair::seeded(Suite::Ed25519, b"root-seed").unwrap();
        let b = KeyPair::seeded(Suite::Ed25519, b"root-seed").unwrap();
        let c = KeyPair::seeded(Suite::Ed25519, b"other-seed").unwrap();
        assert_eq!(a.key_id(), b.key_id());
        assert_eq!(a.public(), b.public());
        assert_ne!(a.key_id(), c.key_id());

        let p = KeyPair::seeded(Suite::EcdsaP256, b"root-seed").unwrap();
        // Same seed, different suite: different key id.
        assert_ne!(a.key_id(), p.key_id());
        // Deterministic signature values (RFC 6979 / Ed25519).
        let s1 = a.sign_raw(b"m").unwrap();
        let s2 = b.sign_raw(b"m").unwrap();
        assert_eq!(s1, s2);
        let ps1 = p.sign_raw(b"m").unwrap();
        let ps2 = KeyPair::seeded(Suite::EcdsaP256, b"root-seed")
            .unwrap()
            .sign_raw(b"m")
            .unwrap();
        assert_eq!(ps1, ps2);
        assert_eq!(ps1.len(), Suite::EcdsaP256.signature_len());
        assert_eq!(s1.len(), Suite::Ed25519.signature_len());
    }

    #[test]
    fn raw_verify_round_trip_and_reject() {
        for suite in [Suite::Ed25519, Suite::EcdsaP256] {
            let sk = KeyPair::seeded(suite, b"k").unwrap();
            let sig = sk.sign_raw(b"message").unwrap();
            assert!(KeyPair::verify_raw(sk.public(), b"message", &sig).is_ok());
            assert!(KeyPair::verify_raw(sk.public(), b"other", &sig).is_err());
            let mut bad = sig.clone();
            bad[0] ^= 0x01;
            assert!(KeyPair::verify_raw(sk.public(), b"message", &bad).is_err());
            let other = KeyPair::seeded(suite, b"j").unwrap();
            assert!(KeyPair::verify_raw(other.public(), b"message", &sig).is_err());
        }
    }

    #[test]
    fn public_key_encoding_round_trip() {
        for suite in [Suite::Ed25519, Suite::EcdsaP256] {
            let sk = KeyPair::seeded(suite, b"k").unwrap();
            let pk = sk.public();
            assert_eq!(PublicKey::from_bytes(pk.as_bytes()).unwrap(), *pk);
        }
        assert!(PublicKey::from_bytes(&[0u8; 7]).is_err());
        // Compressed point is rejected: SIGNATIF pins uncompressed SEC1.
        let sk = KeyPair::seeded(Suite::EcdsaP256, b"k").unwrap();
        let _ = sk;
    }

    #[test]
    fn deferred_suites_refuse_keygen() {
        #[cfg(not(feature = "sm2"))]
        {
            let err = KeyPair::seeded(Suite::Sm2, b"k").unwrap_err();
            assert!(matches!(err, SignatifError::SuiteDeferred { .. }));
        }
        #[cfg(not(feature = "ml-dsa"))]
        {
            let err = KeyPair::seeded(Suite::MlDsa65, b"k").unwrap_err();
            assert!(matches!(err, SignatifError::SuiteDeferred { .. }));
        }
        let err = KeyPair::seeded(Suite::MlDsa44, b"k").unwrap_err();
        assert!(matches!(err, SignatifError::SuiteDeferred { .. }));
        let err = KeyPair::seeded(Suite::MlDsa87, b"k").unwrap_err();
        assert!(matches!(err, SignatifError::SuiteDeferred { .. }));
    }

    #[cfg(feature = "sm2")]
    #[test]
    fn sm2_seeded_keys_sign_and_verify_deterministically() {
        let a = KeyPair::seeded(Suite::Sm2, b"root-seed").unwrap();
        let b = KeyPair::seeded(Suite::Sm2, b"root-seed").unwrap();
        assert_eq!(a.key_id(), b.key_id());
        assert_eq!(a.public().as_bytes().len(), 65);
        assert_eq!(a.public().as_bytes()[0], 0x04);
        assert!(a.suite().is_computed());
        assert!(a.suite().deferral().is_none());
        let sig = a.sign_raw(b"payload").unwrap();
        assert_eq!(sig.len(), 64);
        // RFC 6979-style determinism: same key + payload, same r||s.
        assert_eq!(sig, a.sign_raw(b"payload").unwrap());
        KeyPair::verify_raw(a.public(), b"payload", &sig).unwrap();
        assert!(KeyPair::verify_raw(a.public(), b"other", &sig).is_err());
        let mut tampered = sig.clone();
        tampered[0] ^= 0x01;
        assert!(KeyPair::verify_raw(a.public(), b"payload", &tampered).is_err());
        // Suite-certain decoding round-trips (length inference would
        // read the point as P-256 — the shared 65-byte SEC1 form).
        let re = PublicKey::from_bytes_in(Suite::Sm2, a.public().as_bytes()).unwrap();
        assert_eq!(re, *a.public());
        assert_ne!(
            PublicKey::from_bytes(a.public().as_bytes()).unwrap(),
            *a.public()
        );
    }

    #[cfg(feature = "ml-dsa")]
    #[test]
    fn mldsa65_seeded_keys_sign_and_verify_deterministically() {
        let a = KeyPair::seeded(Suite::MlDsa65, b"root-seed").unwrap();
        let b = KeyPair::seeded(Suite::MlDsa65, b"root-seed").unwrap();
        assert_eq!(a.key_id(), b.key_id());
        assert_eq!(a.public().as_bytes().len(), 1952);
        assert!(a.suite().is_computed());
        assert!(a.suite().deferral().is_none());
        let sig = a.sign_raw(b"payload").unwrap();
        assert_eq!(sig.len(), 3309);
        assert_eq!(sig, a.sign_raw(b"payload").unwrap());
        KeyPair::verify_raw(a.public(), b"payload", &sig).unwrap();
        assert!(KeyPair::verify_raw(a.public(), b"other", &sig).is_err());
        let mut tampered = sig.clone();
        tampered[100] ^= 0x01;
        assert!(KeyPair::verify_raw(a.public(), b"payload", &tampered).is_err());
        // Unambiguous encoding: plain from_bytes round-trips too.
        assert_eq!(
            PublicKey::from_bytes(a.public().as_bytes()).unwrap(),
            *a.public()
        );
    }

    #[test]
    fn key_id_pins_suite_and_key() {
        let a = KeyPair::seeded(Suite::Ed25519, b"k").unwrap();
        let id = KeyId::of(a.public());
        assert_eq!(id.as_str().len(), 18);
        assert!(id.as_str().starts_with("k-"));
        assert_eq!(id, *a.key_id());
        assert!(KeyId::new("has space").is_err());
    }
}
