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
use p256::ecdsa::signature::Signer as P256Signer;
use p256::ecdsa::signature::Verifier as P256Verifier;
use p256::ecdsa::Signature as P256Signature;
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::ecdsa::VerifyingKey as P256VerifyingKey;
use p256::FieldBytes;

use unidpp_model::sha256;

use crate::sign::Suite;
use crate::SignatifError;

/// A public key in one of the two computed suites.
///
/// The P-256 form is the uncompressed SEC1 point (65 bytes:
/// `0x04 || X || Y`), which is what the [`crate::sign`] layer consumes
/// and produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKey {
    /// Ed25519 verifying key (32 bytes).
    Ed25519([u8; 32]),
    /// ECDSA-P256 verifying key, uncompressed SEC1 point (65 bytes).
    EcdsaP256Uncompressed([u8; 65]),
}

impl PublicKey {
    /// The suite this key belongs to.
    pub fn suite(&self) -> Suite {
        match self {
            PublicKey::Ed25519(_) => Suite::Ed25519,
            PublicKey::EcdsaP256Uncompressed(_) => Suite::EcdsaP256,
        }
    }

    /// Raw encoding (length + form identify the suite).
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            PublicKey::Ed25519(b) => b,
            PublicKey::EcdsaP256Uncompressed(b) => b,
        }
    }

    /// Decode raw bytes produced by [`PublicKey::as_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, SignatifError> {
        match bytes.len() {
            32 => Ok(PublicKey::Ed25519(bytes.try_into().unwrap())),
            65 if bytes[0] == 0x04 => {
                Ok(PublicKey::EcdsaP256Uncompressed(bytes.try_into().unwrap()))
            }
            _ => Err(SignatifError::crypto(format!(
                "not a SIGNATIF public key encoding (len {})",
                bytes.len()
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
        let public =
            PublicKey::from_bytes(&bytes).map_err(|e| serde::de::Error::custom(e.to_string()))?;
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
}

impl KeyPair {
    /// Deterministically derive a key pair from seed material
    /// (`H(seed)` becomes the Ed25519 seed / the P-256 scalar). Intended
    /// for tests and ceremony fixtures; production keys come from a
    /// CSPRNG-backed store.
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
            deferred => Err(SignatifError::SuiteDeferred {
                suite: deferred.to_string(),
                detail: deferred.deferral().unwrap().to_string(),
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
        let err = KeyPair::seeded(Suite::Sm2, b"k").unwrap_err();
        assert!(matches!(err, SignatifError::SuiteDeferred { .. }));
        let err = KeyPair::seeded(Suite::MlDsa65, b"k").unwrap_err();
        assert!(matches!(err, SignatifError::SuiteDeferred { .. }));
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
