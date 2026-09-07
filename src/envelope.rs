//! Envelope encryption per recipient KEM (CC/SIGNATIF sovereign-suite
//! doctrine): one payload, one AES-256-GCM ciphertext, and one
//! encapsulated payload key **per recipient KEM** — each jurisdiction's
//! allowed key-establishment machine wraps the same content key, so a
//! CN-anchored recipient opens under its KEM and an EU-anchored
//! recipient opens under theirs without either learning the other's
//! key material.
//!
//! Structure (the classic hybrid envelope):
//!
//! ```text
//! payload ──AES-256-GCM(payload_key, content_nonce)──▶ ciphertext
//! payload_key ──KEK_i = KEM_i(...)──▶ wrapped_key_i   (one per recipient)
//! ```
//!
//! Entropy is caller-supplied ([`EnvelopeSeed`]): production derives
//! it from a CSPRNG per envelope; tests pass a fixed seed so envelopes
//! are reproducible. Per-envelope nonces, the payload key, and every
//! ephemeral KEM secret are domain-separated derivations of the seed —
//! never reused across envelopes (a different seed yields a different
//! payload key, nonces, and ephemerals).
//!
//! Recipient KEMs: DHKEM-style X25519 (static-ephemeral ECDH +
//! HKDF-SHA256) always; ML-KEM-768 (FIPS 203, deterministic
//! encapsulation) behind the `ml-kem` feature. A suite without
//! computation in this build refuses loudly — never a faked wrap.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use sha2::Sha256;
use unidpp_model::sha256;

use crate::SignatifError;

/// AES-256-GCM nonce length.
const NONCE_LEN: usize = 12;
/// AES-256 content/wrap key length.
const KEY_LEN: usize = 32;
/// HKDF domain-separation salt for every envelope derivation.
const HKDF_SALT: &[u8] = b"UNIDPP-SIGNATIF/ENVELOPE";

/// The key-establishment suites an envelope recipient may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KemSuite {
    /// Static-ephemeral X25519 + HKDF-SHA256 (the always-computed
    /// path).
    X25519,
    /// ML-KEM-768 (FIPS 203) — computes with the `ml-kem` feature,
    /// refuses without it.
    MlKem768,
}

impl KemSuite {
    /// All suites, canonical order.
    pub const ALL: &'static [KemSuite] = &[KemSuite::X25519, KemSuite::MlKem768];

    /// Canonical wire token.
    pub fn as_str(self) -> &'static str {
        match self {
            KemSuite::X25519 => "x25519",
            KemSuite::MlKem768 => "ml-kem-768",
        }
    }

    /// Parse a suite token (case-insensitive).
    pub fn parse_token(s: &str) -> Result<KemSuite, SignatifError> {
        let squashed = s.trim().to_ascii_lowercase().replace(['-', '_'], "");
        KemSuite::ALL
            .iter()
            .copied()
            .find(|suite| suite.as_str().replace('-', "") == squashed)
            .ok_or_else(|| SignatifError::invalid(format!("unknown KEM suite `{s}`")))
    }

    /// Whether this suite computes in this build.
    pub fn is_computed(self) -> bool {
        match self {
            KemSuite::X25519 => true,
            #[cfg(feature = "ml-kem")]
            KemSuite::MlKem768 => true,
            #[cfg(not(feature = "ml-kem"))]
            KemSuite::MlKem768 => false,
        }
    }

    /// The documented refusal for suites without computation here.
    pub fn deferral(self) -> Option<&'static str> {
        match self {
            KemSuite::MlKem768 if !self.is_computed() => Some(
                "ML-KEM-768 (FIPS 203) computation requires the `ml-kem` feature (the \
                 `ml-kem` crate); the envelope refuses to fake a wrap",
            ),
            _ => None,
        }
    }
}

/// A recipient public key in one KEM suite.
// ML-KEM-768 keys are 1184 bytes (intrinsic to FIPS 203) against 32
// for X25519. By value on purpose: recipient lists are short, the type
// is Copy like every other public key here, and boxing would ripple
// through every recipient-list construction.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemPublicKey {
    /// X25519 public key (32 bytes).
    X25519([u8; 32]),
    /// ML-KEM-768 encapsulation key (1184 bytes, FIPS 203).
    MlKem768([u8; 1184]),
}

impl KemPublicKey {
    /// The suite this key belongs to.
    pub fn suite(&self) -> KemSuite {
        match self {
            KemPublicKey::X25519(_) => KemSuite::X25519,
            KemPublicKey::MlKem768(_) => KemSuite::MlKem768,
        }
    }

    /// Raw encoding.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            KemPublicKey::X25519(b) => b,
            KemPublicKey::MlKem768(b) => b,
        }
    }

    /// Content-derived recipient identity (`k-` + 16 hex of
    /// `H(suite || key)` — the same id shape as signing keys).
    pub fn key_id(&self) -> String {
        let digest = sha256(&[self.suite().as_str().as_bytes(), self.as_bytes()]);
        format!("k-{}", &digest.hex()[..16])
    }
}

/// Secret-side recipient key material. Deliberately not serializable.
pub struct KemKeyPair {
    suite: KemSuite,
    secret: KemSecret,
    public: KemPublicKey,
}

enum KemSecret {
    X25519(x25519_dalek::StaticSecret),
    #[cfg(feature = "ml-kem")]
    MlKem768(Box<ml_kem::DecapsulationKey<ml_kem::MlKem768>>),
}

impl KemKeyPair {
    /// Deterministically derive a recipient key pair from seed material
    /// (`H(seed)` domain-separated per suite). Intended for tests and
    /// ceremonies; production keys come from a CSPRNG-backed store.
    pub fn seeded(suite: KemSuite, seed: &[u8]) -> Result<KemKeyPair, SignatifError> {
        if !suite.is_computed() {
            return Err(SignatifError::SuiteDeferred {
                suite: suite.as_str().to_string(),
                detail: suite
                    .deferral()
                    .expect("non-computed suites carry a deferral")
                    .to_string(),
            });
        }
        match suite {
            KemSuite::X25519 => {
                let scalar = hkdf_expand(seed, b"recipient/x25519", 32);
                let secret = x25519_dalek::StaticSecret::from(clamp_array(scalar));
                let public = x25519_dalek::PublicKey::from(&secret);
                Ok(KemKeyPair {
                    suite,
                    secret: KemSecret::X25519(secret),
                    public: KemPublicKey::X25519(public.to_bytes()),
                })
            }
            #[cfg(feature = "ml-kem")]
            KemSuite::MlKem768 => {
                let mut seed64 = [0u8; 64];
                seed64.copy_from_slice(&hkdf_expand(seed, b"recipient/ml-kem-768", 64));
                let secret = ml_kem::DecapsulationKey::<ml_kem::MlKem768>::from_seed(
                    ml_kem::Seed::from(seed64),
                );
                use ml_kem::KeyExport as _;
                let public = secret.encapsulation_key().to_bytes().to_vec();
                let public: [u8; 1184] = public
                    .try_into()
                    .expect("ML-KEM-768 encapsulation keys are 1184 bytes (FIPS 203)");
                Ok(KemKeyPair {
                    suite,
                    secret: KemSecret::MlKem768(Box::new(secret)),
                    public: KemPublicKey::MlKem768(public),
                })
            }
            #[cfg(not(feature = "ml-kem"))]
            KemSuite::MlKem768 => unreachable!("guarded by is_computed above"),
        }
    }

    /// The suite of this key.
    pub fn suite(&self) -> KemSuite {
        self.suite
    }

    /// The public key.
    pub fn public(&self) -> &KemPublicKey {
        &self.public
    }
}

impl std::fmt::Debug for KemKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never format secret material.
        f.debug_struct("KemKeyPair")
            .field("suite", &self.suite.as_str())
            .field("public", &self.public.key_id())
            .finish_non_exhaustive()
    }
}

/// Per-envelope entropy supplied by the caller (CSPRNG output in
/// production, a fixed seed in tests — determinism for ceremonies).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeSeed([u8; 32]);

impl EnvelopeSeed {
    /// Wrap exactly 32 bytes of entropy.
    pub fn from_bytes(bytes: &[u8]) -> Result<EnvelopeSeed, SignatifError> {
        let b: [u8; 32] = bytes
            .try_into()
            .map_err(|_| SignatifError::invalid("an envelope seed is exactly 32 bytes"))?;
        Ok(EnvelopeSeed(b))
    }
}

/// One recipient block: the KEM output and the wrapped payload key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EnvelopeRecipient {
    /// The KEM suite used for this wrap.
    pub kem: String,
    /// The recipient's content-derived key id (who this wrap opens for).
    pub key_id: String,
    /// The KEM encapsulated key: X25519 ephemeral public key, or the
    /// ML-KEM-768 ciphertext.
    pub encapsulated_key: String,
    /// The payload key wrapped under this recipient's KEK.
    pub wrapped_key: String,
    /// The wrap nonce (hex).
    pub wrap_nonce: String,
}

/// A sealed envelope: one ciphertext, N recipient wraps.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Envelope {
    /// The content cipher (always AES-256-GCM in this version).
    pub cipher: String,
    /// The content nonce (hex).
    pub nonce: String,
    /// The ciphertext (hex; includes the GCM tag).
    pub ciphertext: String,
    /// The authenticated-but-unencrypted context (routing/profile
    /// hints a relay may read).
    pub aad: String,
    /// One wrap per recipient KEM.
    pub recipients: Vec<EnvelopeRecipient>,
}

impl Envelope {
    /// The recipient block for `key_id`, when present.
    pub fn recipient(&self, key_id: &str) -> Option<&EnvelopeRecipient> {
        self.recipients.iter().find(|r| r.key_id == key_id)
    }
}

/// Seal `payload` for every recipient: derive the content key, nonces,
/// and ephemerals from `seed` (domain-separated per purpose and per
/// recipient), encrypt once, and wrap the content key once per
/// recipient KEM.
pub fn envelope_encrypt(
    payload: &[u8],
    aad: &[u8],
    recipients: &[KemPublicKey],
    seed: &EnvelopeSeed,
) -> Result<Envelope, SignatifError> {
    if recipients.is_empty() {
        return Err(SignatifError::invalid(
            "an envelope needs at least one recipient",
        ));
    }
    let payload_key = hkdf_expand(&seed.0, b"content-key", KEY_LEN);
    let content_nonce = hkdf_expand(&seed.0, b"content-nonce", NONCE_LEN);
    let cipher = aes_cipher(&payload_key)?;
    let ciphertext = cipher
        .encrypt(nonce(&content_nonce), Payload { msg: payload, aad })
        .map_err(|_| SignatifError::crypto("content encryption failed".to_string()))?;

    let mut blocks = Vec::with_capacity(recipients.len());
    for (index, recipient) in recipients.iter().enumerate() {
        let wrap = wrap_for(recipient, index, &payload_key, seed)?;
        blocks.push(EnvelopeRecipient {
            kem: recipient.suite().as_str().to_string(),
            key_id: recipient.key_id(),
            encapsulated_key: hex(&wrap.encapsulated_key),
            wrapped_key: hex(&wrap.wrapped_key),
            wrap_nonce: hex(&wrap.wrap_nonce),
        });
    }
    Ok(Envelope {
        cipher: "aes-256-gcm".to_string(),
        nonce: hex(&content_nonce),
        ciphertext: hex(&ciphertext),
        aad: hex(aad),
        recipients: blocks,
    })
}

/// Open an envelope for one recipient: re-run the KEM with the
/// recipient's private key, unwrap the content key, decrypt the
/// payload. Any tampering — ciphertext, tag, wrap, or encapsulated
/// key — fails the GCM verification.
pub fn envelope_open(
    envelope: &Envelope,
    recipient: &KemKeyPair,
) -> Result<Vec<u8>, SignatifError> {
    let block = envelope
        .recipient(&recipient.public().key_id())
        .ok_or_else(|| {
            SignatifError::crypto(format!(
                "the envelope carries no wrap for recipient {}",
                recipient.public().key_id()
            ))
        })?;
    let suite = KemSuite::parse_token(&block.kem)?;
    if suite != recipient.suite() {
        return Err(SignatifError::crypto(format!(
            "wrap is `{}` but the recipient key is `{}`",
            block.kem,
            recipient.suite().as_str()
        )));
    }
    let payload_key = unwrap_for(recipient, block)?;
    let cipher = aes_cipher(&payload_key)?;
    let content_nonce = unhex(&envelope.nonce)
        .ok_or_else(|| SignatifError::crypto("bad content nonce hex".to_string()))?;
    let aad =
        unhex(&envelope.aad).ok_or_else(|| SignatifError::crypto("bad aad hex".to_string()))?;
    cipher
        .decrypt(
            nonce(&content_nonce),
            Payload {
                msg: &unhex(&envelope.ciphertext)
                    .ok_or_else(|| SignatifError::crypto("bad ciphertext hex".to_string()))?,
                aad: &aad,
            },
        )
        .map_err(|_| {
            SignatifError::crypto(
                "envelope authentication failed (tampered ciphertext, aad, or tag)".to_string(),
            )
        })
}

// ---------------------------------------------------------------------------
// Per-suite wrapping
// ---------------------------------------------------------------------------

struct Wrap {
    encapsulated_key: Vec<u8>,
    wrapped_key: Vec<u8>,
    wrap_nonce: Vec<u8>,
}

fn wrap_for(
    recipient: &KemPublicKey,
    index: usize,
    payload_key: &[u8],
    seed: &EnvelopeSeed,
) -> Result<Wrap, SignatifError> {
    let wrap_nonce = hkdf_expand(&seed.0, format!("wrap-nonce/{index}").as_bytes(), NONCE_LEN);
    match recipient {
        KemPublicKey::X25519(public) => {
            // Static-ephemeral X25519 + HKDF: the ephemeral secret is a
            // per-recipient derivation of the envelope seed.
            let eph_scalar =
                hkdf_expand(&seed.0, format!("ephemeral/x25519/{index}").as_bytes(), 32);
            let eph_secret = x25519_dalek::StaticSecret::from(clamp_array(eph_scalar));
            let eph_public = x25519_dalek::PublicKey::from(&eph_secret);
            let shared = eph_secret.diffie_hellman(&x25519_dalek::PublicKey::from(*public));
            let kek = hkdf(
                &[&shared.as_bytes()[..], &eph_public.as_bytes()[..], public],
                b"x25519",
                KEY_LEN,
            );
            Ok(Wrap {
                encapsulated_key: eph_public.as_bytes().to_vec(),
                wrapped_key: seal(
                    &kek,
                    &wrap_nonce,
                    payload_key,
                    recipient.key_id().as_bytes(),
                )?,
                wrap_nonce,
            })
        }
        #[cfg(feature = "ml-kem")]
        KemPublicKey::MlKem768(public) => {
            use ml_kem::TryKeyInit as _;
            let encap_key = ml_kem::EncapsulationKey::<ml_kem::MlKem768>::new_from_slice(public)
                .map_err(|_| {
                    SignatifError::crypto("bad ML-KEM-768 encapsulation key".to_string())
                })?;
            // Deterministic encapsulation: the FIPS 203 message input
            // is a per-recipient derivation of the envelope seed.
            let m: [u8; 32] = hkdf_expand(&seed.0, format!("mlkem-m/{index}").as_bytes(), 32)
                .try_into()
                .expect("32-byte HKDF output");
            let (ciphertext, shared) = encap_key.encapsulate_deterministic(&ml_kem::B32::from(m));
            let kek = hkdf(&[shared.as_slice()], b"ml-kem-768", KEY_LEN);
            Ok(Wrap {
                encapsulated_key: ciphertext.as_slice().to_vec(),
                wrapped_key: seal(
                    &kek,
                    &wrap_nonce,
                    payload_key,
                    recipient.key_id().as_bytes(),
                )?,
                wrap_nonce,
            })
        }
        #[cfg(not(feature = "ml-kem"))]
        KemPublicKey::MlKem768(_) => Err(SignatifError::SuiteDeferred {
            suite: KemSuite::MlKem768.as_str().to_string(),
            detail: KemSuite::MlKem768
                .deferral()
                .expect("the deferral exists when the suite does not compute")
                .to_string(),
        }),
    }
}

fn unwrap_for(recipient: &KemKeyPair, block: &EnvelopeRecipient) -> Result<Vec<u8>, SignatifError> {
    let wrap_nonce = unhex(&block.wrap_nonce)
        .ok_or_else(|| SignatifError::crypto("bad wrap nonce hex".to_string()))?;
    let wrapped = unhex(&block.wrapped_key)
        .ok_or_else(|| SignatifError::crypto("bad wrapped key hex".to_string()))?;
    let encapsulated = unhex(&block.encapsulated_key)
        .ok_or_else(|| SignatifError::crypto("bad encapsulated key hex".to_string()))?;
    let aad: &[u8] = block.key_id.as_bytes();
    match (&recipient.secret, recipient.suite()) {
        (KemSecret::X25519(secret), KemSuite::X25519) => {
            let KemPublicKey::X25519(public) = recipient.public() else {
                unreachable!("suite and key shape agree by construction");
            };
            let eph_public_bytes: [u8; 32] = encapsulated.try_into().map_err(|_| {
                SignatifError::crypto("x25519 wrap carries a 32-byte ephemeral key".to_string())
            })?;
            let eph_public = x25519_dalek::PublicKey::from(eph_public_bytes);
            let shared = secret.diffie_hellman(&eph_public);
            let kek = hkdf(
                &[&shared.as_bytes()[..], &eph_public_bytes, public],
                b"x25519",
                KEY_LEN,
            );
            open(&kek, &wrap_nonce, &wrapped, aad)
        }
        #[cfg(feature = "ml-kem")]
        (KemSecret::MlKem768(secret), KemSuite::MlKem768) => {
            use ml_kem::Decapsulate as _;
            let ct: [u8; 1088] = encapsulated.try_into().map_err(|_| {
                SignatifError::crypto("ml-kem-768 wrap carries a 1088-byte ciphertext")
            })?;
            let shared = secret.decapsulate(&ml_kem::Ciphertext::<ml_kem::MlKem768>::from(ct));
            let kek = hkdf(&[shared.as_slice()], b"ml-kem-768", KEY_LEN);
            open(&kek, &wrap_nonce, &wrapped, aad)
        }
        _ => Err(SignatifError::crypto(format!(
            "recipient suite `{}` does not match the wrap's KEM",
            recipient.suite().as_str()
        ))),
    }
}

// ---------------------------------------------------------------------------
// Primitives (thin, domain-labelled wrappers)
// ---------------------------------------------------------------------------

fn aes_cipher(key: &[u8]) -> Result<Aes256Gcm, SignatifError> {
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| SignatifError::crypto("AES-256 keys are 32 bytes".to_string()))
}

fn nonce(bytes: &[u8]) -> &aes_gcm::Nonce<aes_gcm::aead::consts::U12> {
    // generic-array 0.14's from_slice; aes-gcm 0.10 sits on that line.
    #[allow(deprecated)]
    aes_gcm::Nonce::from_slice(bytes)
}

/// Seal the payload key under a KEK, authenticating the recipient's
/// key id as the wrap's AAD (a wrap is bound to exactly one recipient).
fn seal(
    key: &[u8],
    nonce_bytes: &[u8],
    plaintext: &[u8],
    recipient_key_id: &[u8],
) -> Result<Vec<u8>, SignatifError> {
    let cipher = aes_cipher(key)?;
    cipher
        .encrypt(
            nonce(nonce_bytes),
            Payload {
                msg: plaintext,
                aad: recipient_key_id,
            },
        )
        .map_err(|_| SignatifError::crypto("payload-key wrap failed".to_string()))
}

fn open(
    key: &[u8],
    nonce_bytes: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, SignatifError> {
    let cipher = aes_cipher(key)?;
    let plain = cipher
        .decrypt(
            nonce(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| {
            SignatifError::crypto(
                "wrap authentication failed (wrong key or tampered wrap)".to_string(),
            )
        })?;
    if plain.len() != KEY_LEN {
        return Err(SignatifError::crypto(
            "unwrapped payload key is not 32 bytes".to_string(),
        ));
    }
    Ok(plain)
}

fn hkdf_expand(ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    hkdf(&[ikm], info, len)
}

fn hkdf(ikm_parts: &[&[u8]], info: &[u8], len: usize) -> Vec<u8> {
    // Concatenate the IKM parts (the KEM shared secret plus the public
    // context, per the DHKEM binding pattern).
    let mut ikm = Vec::new();
    for part in ikm_parts {
        ikm.extend_from_slice(part);
    }
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &ikm);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out).expect("valid HKDF length");
    out
}

/// X25519 scalars are clamped by the dalek constructor; the derivation
/// feeds the raw HKDF output through the same clamp.
fn clamp_array(mut bytes: Vec<u8>) -> [u8; 32] {
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(tag: &str) -> EnvelopeSeed {
        EnvelopeSeed::from_bytes(&sha256(&[tag.as_bytes()]).0).unwrap()
    }

    fn recipient(suite: KemSuite, tag: &str) -> KemKeyPair {
        KemKeyPair::seeded(suite, &[tag.as_bytes(), b"/recipient"].concat()).unwrap()
    }

    #[test]
    fn x25519_envelope_round_trips_and_is_deterministic() {
        let eu = recipient(KemSuite::X25519, "eu");
        let a = envelope_encrypt(
            b"battery chemistry: LFP",
            b"ctx-1",
            &[*eu.public()],
            &seed("s1"),
        )
        .unwrap();
        let b = envelope_encrypt(
            b"battery chemistry: LFP",
            b"ctx-1",
            &[*eu.public()],
            &seed("s1"),
        )
        .unwrap();
        assert_eq!(a, b, "same seed + inputs => the same envelope");
        let opened = envelope_open(&a, &eu).unwrap();
        assert_eq!(opened, b"battery chemistry: LFP");
        assert_eq!(a.cipher, "aes-256-gcm");
        assert_eq!(a.recipients.len(), 1);
        assert_eq!(a.recipients[0].kem, "x25519");
        assert_eq!(a.recipients[0].key_id, eu.public().key_id());
    }

    #[test]
    fn distinct_seeds_never_reuse_payload_keys_or_nonces() {
        let eu = recipient(KemSuite::X25519, "eu");
        let a = envelope_encrypt(b"m", b"a", &[*eu.public()], &seed("s1")).unwrap();
        let b = envelope_encrypt(b"m", b"a", &[*eu.public()], &seed("s2")).unwrap();
        assert_ne!(a.nonce, b.nonce, "content nonces must differ");
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_ne!(
            a.recipients[0].encapsulated_key, b.recipients[0].encapsulated_key,
            "ephemeral keys must differ"
        );
        assert_ne!(a.recipients[0].wrapped_key, b.recipients[0].wrapped_key);
    }

    #[test]
    fn tampering_is_detected_at_every_layer() {
        let eu = recipient(KemSuite::X25519, "eu");
        let envelope =
            envelope_encrypt(b"secret payload", b"aad-1", &[*eu.public()], &seed("s")).unwrap();
        // Tamper the ciphertext.
        let mut tampered = envelope.clone();
        let mut bytes = unhex(&tampered.ciphertext).unwrap();
        bytes[0] ^= 0x01;
        tampered.ciphertext = hex(&bytes);
        assert!(envelope_open(&tampered, &eu).is_err());
        // Tamper the wrapped key.
        let mut tampered = envelope.clone();
        let mut bytes = unhex(&tampered.recipients[0].wrapped_key).unwrap();
        bytes[0] ^= 0x01;
        tampered.recipients[0].wrapped_key = hex(&bytes);
        assert!(envelope_open(&tampered, &eu).is_err());
        // Tamper the ephemeral key (wrong ECDH => wrong KEK).
        let mut tampered = envelope.clone();
        let mut bytes = unhex(&tampered.recipients[0].encapsulated_key).unwrap();
        bytes[0] ^= 0x01;
        tampered.recipients[0].encapsulated_key = hex(&bytes);
        assert!(envelope_open(&tampered, &eu).is_err());
        // Tamper the AAD (authenticated routing context).
        let mut tampered = envelope.clone();
        tampered.aad = hex(b"other");
        assert!(envelope_open(&tampered, &eu).is_err());
        // The untampered envelope still opens.
        assert_eq!(envelope_open(&envelope, &eu).unwrap(), b"secret payload");
    }

    #[test]
    fn a_stranger_cannot_open() {
        let eu = recipient(KemSuite::X25519, "eu");
        let envelope = envelope_encrypt(b"m", b"a", &[*eu.public()], &seed("s")).unwrap();
        let stranger = recipient(KemSuite::X25519, "stranger");
        let err = envelope_open(&envelope, &stranger).unwrap_err();
        assert!(err.to_string().contains("no wrap for recipient"), "{err}");
    }

    #[test]
    fn multi_recipient_envelope_opens_under_each_independently() {
        // The sovereign doctrine: EU (X25519) and CN (X25519, different
        // key) recipients plus a second wrap for the same holder — one
        // ciphertext, one wrap each, each opens alone.
        let eu = recipient(KemSuite::X25519, "eu");
        let cn = recipient(KemSuite::X25519, "cn");
        let payload = b"shared but jurisdictionally wrapped";
        let envelope = envelope_encrypt(
            payload,
            b"route:eu+cn",
            &[*eu.public(), *cn.public()],
            &seed("multi"),
        )
        .unwrap();
        assert_eq!(envelope.recipients.len(), 2);
        assert_ne!(
            envelope.recipients[0].encapsulated_key, envelope.recipients[1].encapsulated_key,
            "per-recipient ephemerals must not be reused"
        );
        assert_eq!(envelope_open(&envelope, &eu).unwrap(), payload);
        assert_eq!(envelope_open(&envelope, &cn).unwrap(), payload);
    }

    #[test]
    fn suite_tokens_parse_and_gate() {
        assert_eq!(KemSuite::parse_token("x25519").unwrap(), KemSuite::X25519);
        assert_eq!(
            KemSuite::parse_token("ML-KEM-768").unwrap(),
            KemSuite::MlKem768
        );
        assert!(KemSuite::parse_token("rsa").is_err());
        assert!(KemSuite::X25519.is_computed());
        #[cfg(feature = "ml-kem")]
        assert!(KemSuite::MlKem768.is_computed());
        #[cfg(not(feature = "ml-kem"))]
        {
            assert!(!KemSuite::MlKem768.is_computed());
            assert!(KemSuite::MlKem768.deferral().is_some());
            let err = KemKeyPair::seeded(KemSuite::MlKem768, b"k").unwrap_err();
            assert!(matches!(err, SignatifError::SuiteDeferred { .. }));
        }
    }

    #[cfg(feature = "ml-kem")]
    #[test]
    fn ml_kem_envelope_round_trips_alone_and_alongside_x25519() {
        let pq = recipient(KemSuite::MlKem768, "pq");
        let classical = recipient(KemSuite::X25519, "classical");
        // The hybrid migration shape: one payload, classical + PQ wraps.
        let envelope = envelope_encrypt(
            b"hybrid payload",
            b"hybrid",
            &[*classical.public(), *pq.public()],
            &seed("hybrid"),
        )
        .unwrap();
        assert_eq!(envelope.recipients.len(), 2);
        assert_eq!(envelope.recipients[1].kem, "ml-kem-768");
        assert_eq!(
            envelope.recipients[1].encapsulated_key.len(),
            1088 * 2,
            "ML-KEM-768 ciphertext is 1088 bytes (hex-doubled)"
        );
        assert_eq!(
            envelope_open(&envelope, &classical).unwrap(),
            b"hybrid payload"
        );
        assert_eq!(envelope_open(&envelope, &pq).unwrap(), b"hybrid payload");
        // PQ-only envelope.
        let envelope = envelope_encrypt(b"pq only", b"pq", &[*pq.public()], &seed("pq")).unwrap();
        assert_eq!(envelope_open(&envelope, &pq).unwrap(), b"pq only");
        // A tampered KEM ciphertext fails the wrap authentication.
        let mut tampered = envelope.clone();
        let mut bytes = unhex(&tampered.recipients[0].encapsulated_key).unwrap();
        bytes[10] ^= 0x01;
        tampered.recipients[0].encapsulated_key = hex(&bytes);
        assert!(envelope_open(&tampered, &pq).is_err());
    }

    #[test]
    fn empty_recipient_list_is_refused() {
        let err = envelope_encrypt(b"m", b"a", &[], &seed("s")).unwrap_err();
        assert!(err.to_string().contains("at least one recipient"));
    }
}
