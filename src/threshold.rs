//! M-of-K threshold root ceremonies — real threshold Schnorr over
//! Ed25519.
//!
//! The trust-registry doctrine: a root key belongs to **no single
//! key holder and no single country**. This module implements the
//! ceremony that makes that true with actual cryptography:
//!
//! - **Distributed generation** ([`generate`]): a Shamir polynomial of
//!   degree `M-1` over the Ed25519 scalar field; each of the `K`
//!   members holds one evaluation. The group public key is the
//!   polynomial's constant term times the basepoint — known to
//!   everyone, matching no member's share. Feldman commitments
//!   (`C_j = f_j·B`) ship with the group key so **every member
//!   verifies their own share** ([`verify_share`]) without learning
//!   anything about the others.
//! - **Threshold signing** ([`sign_partial`], [`combine`]): a
//!   qualifying set of `M` members each contributes a partial
//!   signature. Nonces are deterministic per (share, message) —
//!   derived from the member's **own** share alone, so no nonce
//!   agreement round and no nonce-leak surface between members. The
//!   combiner verifies every partial against the Feldman commitments
//!   (a misbehaving member aborts the ceremony, identified by index)
//!   and Lagrange-interpolates the partials into **one standard
//!   Ed25519 signature** under the group key — verifiable by any
//!   Ed25519 verifier, with no threshold machinery on the verifier's
//!   side.
//!
//! The group signature is *deterministic per (qualifying set,
//! message)*: the same set re-signing the same bytes yields the same
//! signature; a different qualifying set yields a different, equally
//! valid one.
//!
//! # Trust assumptions
//!
//! - **Who runs init**: the polynomial exists whole only inside
//!   [`generate`]. In production the seed is CSPRNG entropy consumed
//!   by a dealer (or a DKG; this crate ships the dealer form, the
//!   honest-dealer assumption is documented and the share
//!   verification makes a *lying* dealer detectable by every member
//!   immediately).
//! - **Share distribution channel**: out of band and confidential per
//!   member. Shares are the only secret material; the group key and
//!   commitments are public.
//! - **Honest majority**: fewer than `M` shares reveal nothing about
//!   the group scalar (Shamir). At combination time the combiner sees
//!   `M` partials and reconstructs *no secret* — partials combine
//!   linearly; the group scalar never exists again after `generate`.
//! - **Combiner trust**: the combiner sees partials (public-safe:
//!   they verify against commitments) and learns only the signature.
//!   A malicious combiner can suppress a ceremony, not forge one.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use unidpp_model::sha256;

use crate::SignatifError;

/// The wire label of this ceremony's algorithm.
pub const ALGORITHM: &str = "ed25519-threshold-schnorr/feldman";

/// A generated group: the public half everyone pins.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GroupKey {
    /// Minimum members needed to sign.
    pub threshold: usize,
    /// Total members.
    pub members: usize,
    /// The group public key (compressed Ed25519 point, 32 bytes hex).
    pub group_public: String,
    /// Feldman commitments `C_j = f_j·B` for `j` in `0..threshold`
    /// (compressed points, hex) — `C_0` is the group key.
    pub commitments: Vec<String>,
    /// The algorithm label.
    pub algorithm: String,
}

/// One member's share. Secret material — the file it lives in is
/// confidential to that member.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MemberShare {
    /// The member's evaluation index (`1..=members`).
    pub index: u32,
    /// The share scalar (32 bytes hex, canonical).
    pub share: String,
}

/// A partial signature contributed by one qualifying member.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PartialSignature {
    /// The contributor's index.
    pub index: u32,
    /// The member's nonce point `R_i` (compressed, hex).
    pub nonce: String,
    /// The partial scalar `s_i` (32 bytes hex).
    pub partial: String,
}

/// The combined group signature — a standard Ed25519 signature under
/// the group key, plus the qualifying set (for audit; verification
/// ignores it beyond threshold bookkeeping).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GroupSignature {
    /// `R` (compressed point, hex).
    pub r: String,
    /// `s` (scalar, hex).
    pub s: String,
    /// The qualifying set's indices, ascending.
    pub signers: Vec<u32>,
    /// The algorithm label.
    pub algorithm: String,
}

// ---------------------------------------------------------------------------
// Scalar helpers
// ---------------------------------------------------------------------------

fn scalar_from_seed(parts: &[&[u8]]) -> Scalar {
    // SHA-512 widened reduction — the Ed25519 scalar-derivation
    // pattern: 64 bytes of hash folded into the scalar field.
    let mut hasher = Sha512::new();
    for part in parts {
        hasher.update(part);
    }
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hasher.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn scalar_of(share: &MemberShare) -> Result<Scalar, SignatifError> {
    let bytes = unhex32(&share.share).ok_or_else(|| {
        SignatifError::invalid(format!("share {} is not 32-byte hex", share.index))
    })?;
    Scalar::from_canonical_bytes(bytes)
        .into_option()
        .ok_or_else(|| {
            SignatifError::invalid(format!(
                "share {} is not a canonical scalar (reduced mod l)",
                share.index
            ))
        })
}

fn compressed(point_hex: &str) -> Result<CompressedEdwardsY, SignatifError> {
    let bytes = unhex32(point_hex).ok_or_else(|| {
        SignatifError::invalid(format!("`{point_hex}` is not a 32-byte point encoding"))
    })?;
    Ok(CompressedEdwardsY(bytes))
}

/// x-coordinate of a member index, as a curve scalar.
fn index_scalar(index: u32) -> Scalar {
    Scalar::from(index as u64)
}

/// The Lagrange coefficient at x = 0 for `index` over `signers`.
fn lagrange_zero(index: u32, signers: &[u32]) -> Scalar {
    let me = index_scalar(index);
    let mut coeff = Scalar::ONE;
    for &other in signers {
        if other == index {
            continue;
        }
        let x_j = index_scalar(other);
        let x_j_minus_x_i = x_j - me;
        coeff *= x_j * x_j_minus_x_i.invert();
    }
    coeff
}

// ---------------------------------------------------------------------------
// Generation (the honest-dealer form)
// ---------------------------------------------------------------------------

/// Generate an M-of-K group from seed entropy (CSPRNG output in
/// production; a fixed seed keeps ceremonies reproducible in tests).
/// Returns the public group key and every member's share. The
/// polynomial exists only inside this function.
pub fn generate(
    seed: &[u8],
    threshold: usize,
    members: usize,
) -> Result<(GroupKey, Vec<MemberShare>), SignatifError> {
    if threshold == 0 || threshold > members {
        return Err(SignatifError::invalid(format!(
            "a {threshold}-of-{members} quorum is degenerate (need 1 <= M <= K)"
        )));
    }
    let ceremony = sha256(&[b"UNIDPP-SIGNATIF/CEREMONY", seed]).hex();
    let coefficients: Vec<Scalar> = (0..threshold)
        .map(|j| scalar_from_seed(&[ceremony.as_bytes(), b"|f|", &j.to_le_bytes()]))
        .collect();
    let group_point = coefficients[0] * ED25519_BASEPOINT_POINT;
    let commitments: Vec<String> = coefficients
        .iter()
        .map(|c| hex32(&(c * ED25519_BASEPOINT_POINT).compress().0))
        .collect();
    let shares: Vec<MemberShare> = (1..=members as u32)
        .map(|index| {
            let mut value = Scalar::ZERO;
            // Horner over the polynomial at x = index.
            for coefficient in coefficients.iter().rev() {
                value = value * index_scalar(index) + coefficient;
            }
            MemberShare {
                index,
                share: hex32(&value.to_bytes()),
            }
        })
        .collect();
    Ok((
        GroupKey {
            threshold,
            members,
            group_public: hex32(&group_point.compress().0),
            commitments,
            algorithm: ALGORITHM.to_string(),
        },
        shares,
    ))
}

/// Verify a member's share against the Feldman commitments:
/// `share·B == Σ_j C_j · index^j`. A lying dealer or a corrupted
/// share fails here — detectable by the member alone.
pub fn verify_share(group: &GroupKey, share: &MemberShare) -> Result<bool, SignatifError> {
    if share.index == 0 || share.index as usize > group.members {
        return Err(SignatifError::invalid(format!(
            "member index {} is outside 1..={}",
            share.index, group.members
        )));
    }
    if group.commitments.len() != group.threshold {
        return Err(SignatifError::invalid(
            "the group key does not carry threshold-many commitments",
        ));
    }
    let commitment_points: Result<Vec<_>, _> = group
        .commitments
        .iter()
        .map(|c| {
            compressed(c)?
                .decompress()
                .ok_or_else(|| SignatifError::invalid("a commitment is not a valid point"))
        })
        .collect();
    let commitment_points = commitment_points?;
    let mut expected = curve25519_dalek::edwards::EdwardsPoint::identity();
    let mut power = Scalar::ONE;
    let x = index_scalar(share.index);
    for point in &commitment_points {
        expected += power * point;
        power *= x;
    }
    let share_point = scalar_of(share)? * ED25519_BASEPOINT_POINT;
    Ok(share_point.compress() == expected.compress())
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// Round 1: the member's deterministic nonce point for `message` —
/// published before any partial (a real distributed ceremony runs this
/// round across members; the combiner collects these, then members
/// contribute partials over the group nonce).
pub fn nonce_point(share: &MemberShare, message: &[u8]) -> Result<String, SignatifError> {
    let secret = scalar_of(share)?;
    let nonce = scalar_from_seed(&[
        b"UNIDPP-SIGNATIF/CEREMONY/NONCE",
        &secret.to_bytes(),
        message,
    ]);
    let point = nonce * ED25519_BASEPOINT_POINT;
    Ok(hex32(&point.compress().0))
}

/// The member-side contribution for `message`: the deterministic
/// nonce point `R_i` (round 1) and the partial signature `s_i` over
/// the **group** nonce `R = Σ R_j` (round 2). Both derive from the
/// member's own share and the message alone; nothing secret leaves
/// this function.
pub fn sign_partial(
    group: &GroupKey,
    share: &MemberShare,
    message: &[u8],
    nonce_points: &[(u32, String)],
) -> Result<PartialSignature, SignatifError> {
    let signers: Vec<u32> = nonce_points.iter().map(|(index, _)| *index).collect();
    if signers.len() < group.threshold {
        return Err(SignatifError::invalid(format!(
            "a qualifying set needs {} members, {} contributed",
            group.threshold,
            signers.len()
        )));
    }
    if !signers.contains(&share.index) {
        return Err(SignatifError::invalid(format!(
            "member {} is not part of the qualifying set {:?}",
            share.index, signers
        )));
    }
    let secret = scalar_of(share)?;
    // The member's nonce: deterministic from the member's own share
    // and the message (domain-separated from the share-derivation
    // seed).
    let nonce = scalar_from_seed(&[
        b"UNIDPP-SIGNATIF/CEREMONY/NONCE",
        &secret.to_bytes(),
        message,
    ]);
    let nonce_point = nonce * ED25519_BASEPOINT_POINT;
    // The group nonce: the sum of the qualifying set's nonce points.
    let mut r_point = curve25519_dalek::edwards::EdwardsPoint::identity();
    for (index, point_hex) in nonce_points {
        let point = compressed(point_hex)?
            .decompress()
            .ok_or_else(|| SignatifError::invalid(format!("member {index}: bad nonce point")))?;
        r_point += point;
    }
    // The Ed25519 challenge c = H(R || A || M), reduced mod l.
    let group_public = compressed(&group.group_public)?;
    let mut hasher = Sha512::new();
    hasher.update(r_point.compress().as_bytes());
    hasher.update(group_public.as_bytes());
    hasher.update(message);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hasher.finalize());
    let challenge = Scalar::from_bytes_mod_order_wide(&wide);
    // s_i = r_i + c · λ_i · a_i
    let lambda = lagrange_zero(share.index, &signers);
    let partial = nonce + challenge * lambda * secret;
    Ok(PartialSignature {
        index: share.index,
        nonce: hex32(&nonce_point.compress().0),
        partial: hex32(&partial.to_bytes()),
    })
}

/// The combiner: verify every partial against the Feldman commitments
/// (a bad partial aborts the ceremony with the culprit's index), then
/// combine into one standard Ed25519 group signature.
pub fn combine(
    group: &GroupKey,
    message: &[u8],
    partials: &[PartialSignature],
) -> Result<GroupSignature, SignatifError> {
    if partials.len() != group.threshold {
        return Err(SignatifError::invalid(format!(
            "combination takes exactly {} partials, got {}",
            group.threshold,
            partials.len()
        )));
    }
    let mut signers: Vec<u32> = partials.iter().map(|p| p.index).collect();
    signers.sort_unstable();
    signers.dedup();
    if signers.len() != partials.len() {
        return Err(SignatifError::invalid(
            "a member contributed twice — one member, one partial",
        ));
    }
    // Rebuild the group nonce from the partials' nonce points.
    let mut r_point = curve25519_dalek::edwards::EdwardsPoint::identity();
    for partial in partials {
        let point = compressed(&partial.nonce)?
            .decompress()
            .ok_or_else(|| SignatifError::invalid("a nonce point is not on the curve"))?;
        r_point += point;
    }
    let group_public = compressed(&group.group_public)?;
    let mut hasher = Sha512::new();
    hasher.update(r_point.compress().as_bytes());
    hasher.update(group_public.as_bytes());
    hasher.update(message);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hasher.finalize());
    let challenge = Scalar::from_bytes_mod_order_wide(&wide);

    // Verify each partial: s_i·B == R_i + c·λ_i·A_i, with A_i the
    // commitment-evaluated member key.
    let commitment_points: Result<Vec<_>, _> = group
        .commitments
        .iter()
        .map(|c| {
            compressed(c)?
                .decompress()
                .ok_or_else(|| SignatifError::invalid("a commitment is not a valid point"))
        })
        .collect();
    let commitment_points = commitment_points?;
    let mut total = Scalar::ZERO;
    for partial in partials {
        let s_i = Scalar::from_canonical_bytes(
            unhex32(&partial.partial)
                .ok_or_else(|| SignatifError::invalid("a partial is not 32-byte hex"))?,
        )
        .into_option()
        .ok_or_else(|| SignatifError::invalid("a partial is not a canonical scalar"))?;
        let r_i = compressed(&partial.nonce)?
            .decompress()
            .ok_or_else(|| SignatifError::invalid("a nonce point is not on the curve"))?;
        let x = index_scalar(partial.index);
        let mut a_i_point = curve25519_dalek::edwards::EdwardsPoint::identity();
        let mut power = Scalar::ONE;
        for point in &commitment_points {
            a_i_point += power * point;
            power *= x;
        }
        let lambda = lagrange_zero(partial.index, &signers);
        let left = s_i * ED25519_BASEPOINT_POINT;
        let right = r_i + challenge * lambda * a_i_point;
        if left.compress() != right.compress() {
            return Err(SignatifError::crypto(format!(
                "member {} contributed an invalid partial — ceremony aborted, culprit identified",
                partial.index
            )));
        }
        total += s_i;
    }
    Ok(GroupSignature {
        r: hex32(&r_point.compress().0),
        s: hex32(&total.to_bytes()),
        signers,
        algorithm: ALGORITHM.to_string(),
    })
}

/// Verify a group signature under the group public key — the standard
/// Ed25519 equation `[s]B = R + [c]A`, so any Ed25519 verifier
/// accepts the combined signature; this function additionally checks
/// the qualifying set's size against the threshold.
pub fn verify(
    group: &GroupKey,
    message: &[u8],
    signature: &GroupSignature,
) -> Result<(), SignatifError> {
    if signature.signers.len() != group.threshold {
        return Err(SignatifError::crypto(format!(
            "signature names {} signers but the threshold is {}",
            signature.signers.len(),
            group.threshold
        )));
    }
    let public = compressed(&group.group_public)?
        .decompress()
        .ok_or_else(|| SignatifError::invalid("the group public key is not a valid point"))?;
    let r = compressed(&signature.r)?
        .decompress()
        .ok_or_else(|| SignatifError::invalid("signature R is not a valid point"))?;
    let s = Scalar::from_canonical_bytes(
        unhex32(&signature.s)
            .ok_or_else(|| SignatifError::invalid("signature s is not 32-byte hex"))?,
    )
    .into_option()
    .ok_or_else(|| SignatifError::invalid("signature s is not a canonical scalar"))?;
    let group_public = compressed(&group.group_public)?;
    let mut hasher = Sha512::new();
    hasher.update(r.compress().as_bytes());
    hasher.update(group_public.as_bytes());
    hasher.update(message);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hasher.finalize());
    let challenge = Scalar::from_bytes_mod_order_wide(&wide);
    let check = s * ED25519_BASEPOINT_POINT - challenge * public;
    if check.compress() == r.compress() {
        Ok(())
    } else {
        Err(SignatifError::crypto(
            "group signature verification failed".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Ceremony JSON (the binary's file shapes)
// ---------------------------------------------------------------------------

impl GroupKey {
    /// Parse from the ceremony `group.json` shape.
    pub fn from_json(text: &str) -> Result<GroupKey, SignatifError> {
        let v: Value = serde_json::from_str(text)
            .map_err(|e| SignatifError::invalid(format!("group file: {e}")))?;
        let group = GroupKey {
            threshold: v["threshold"].as_u64().unwrap_or(0) as usize,
            members: v["members"].as_u64().unwrap_or(0) as usize,
            group_public: v["group_public"].as_str().unwrap_or_default().to_string(),
            commitments: v["commitments"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|c| c.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
            algorithm: v["algorithm"].as_str().unwrap_or_default().to_string(),
        };
        if group.algorithm != ALGORITHM {
            return Err(SignatifError::invalid(format!(
                "group algorithm `{}` is not `{ALGORITHM}`",
                group.algorithm
            )));
        }
        Ok(group)
    }

    /// Serialize to the ceremony `group.json` shape.
    pub fn to_json(&self) -> Value {
        json!({
            "threshold": self.threshold,
            "members": self.members,
            "group_public": self.group_public,
            "commitments": self.commitments,
            "algorithm": self.algorithm,
        })
    }
}

impl MemberShare {
    /// Parse from the ceremony `member-N.json` shape.
    pub fn from_json(text: &str) -> Result<MemberShare, SignatifError> {
        let v: Value = serde_json::from_str(text)
            .map_err(|e| SignatifError::invalid(format!("share file: {e}")))?;
        Ok(MemberShare {
            index: v["index"].as_u64().unwrap_or(0) as u32,
            share: v["share"].as_str().unwrap_or_default().to_string(),
        })
    }

    /// Serialize to the ceremony `member-N.json` shape.
    pub fn to_json(&self) -> Value {
        json!({"index": self.index, "share": self.share})
    }
}

impl GroupSignature {
    /// Parse from the ceremony `signature.json` shape.
    pub fn from_json(text: &str) -> Result<GroupSignature, SignatifError> {
        let v: Value = serde_json::from_str(text)
            .map_err(|e| SignatifError::invalid(format!("signature file: {e}")))?;
        Ok(GroupSignature {
            r: v["r"].as_str().unwrap_or_default().to_string(),
            s: v["s"].as_str().unwrap_or_default().to_string(),
            signers: v["signers"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_u64().map(|n| n as u32))
                        .collect()
                })
                .unwrap_or_default(),
            algorithm: v["algorithm"].as_str().unwrap_or_default().to_string(),
        })
    }

    /// Serialize to the ceremony `signature.json` shape.
    pub fn to_json(&self) -> Value {
        json!({
            "r": self.r,
            "s": self.s,
            "signers": self.signers,
            "algorithm": self.algorithm,
        })
    }

    /// The standard Ed25519 signature bytes (`R || s`) — verifiable by
    /// any Ed25519 verifier under the group public key.
    pub fn to_ed25519_bytes(&self) -> Result<[u8; 64], SignatifError> {
        let mut out = [0u8; 64];
        let r = unhex32(&self.r)
            .ok_or_else(|| SignatifError::invalid("signature R is not 32-byte hex"))?;
        let s = unhex32(&self.s)
            .ok_or_else(|| SignatifError::invalid("signature s is not 32-byte hex"))?;
        out[..32].copy_from_slice(&r);
        out[32..].copy_from_slice(&s);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group_2_of_3() -> (GroupKey, Vec<MemberShare>) {
        generate(b"ceremony-test-seed", 2, 3).unwrap()
    }

    fn qualifying(
        group: &GroupKey,
        shares: &[&MemberShare],
        message: &[u8],
    ) -> Vec<PartialSignature> {
        // Round 1: nonce points.
        let nonces: Vec<(u32, String)> = shares
            .iter()
            .map(|share| {
                let nonce = scalar_from_seed(&[
                    b"UNIDPP-SIGNATIF/CEREMONY/NONCE",
                    &scalar_of(share).unwrap().to_bytes(),
                    message,
                ]);
                let point = nonce * ED25519_BASEPOINT_POINT;
                (share.index, hex32(&point.compress().0))
            })
            .collect();
        // Round 2: partials.
        shares
            .iter()
            .map(|share| sign_partial(group, share, message, &nonces).unwrap())
            .collect()
    }

    #[test]
    fn shares_verify_and_the_group_key_matches_no_member() {
        let (group, shares) = group_2_of_3();
        assert_eq!(group.algorithm, ALGORITHM);
        assert_eq!(group.commitments.len(), 2);
        // C_0 is the group public key.
        assert_eq!(group.commitments[0], group.group_public);
        for share in &shares {
            assert!(
                verify_share(&group, share).unwrap(),
                "share {}",
                share.index
            );
        }
        // A tampered share fails verification.
        let mut bad = shares[0].clone();
        let mut bytes = unhex32(&bad.share).unwrap();
        bytes[0] ^= 0x01;
        bad.share = hex32(&bytes);
        assert!(!verify_share(&group, &bad).unwrap());
        // A share from a different group fails.
        let (other, _) = generate(b"other-seed", 2, 3).unwrap();
        assert!(!verify_share(&other, &shares[0]).unwrap());
    }

    #[test]
    fn two_of_three_signing_round_trips_under_every_qualifying_pair() {
        let (group, shares) = group_2_of_3();
        let message = b"threshold root statement";
        for pair in [[0usize, 1], [0, 2], [1, 2]] {
            let set: Vec<&MemberShare> = pair.iter().map(|&i| &shares[i]).collect();
            let partials = qualifying(&group, &set, message);
            let signature = combine(&group, message, &partials).unwrap();
            assert_eq!(signature.signers.len(), 2);
            verify(&group, message, &signature).unwrap();
            // The combined signature is a *standard* Ed25519
            // signature under the group key.
            let public_bytes = unhex32(&group.group_public).unwrap();
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&public_bytes).unwrap();
            let sig = ed25519_dalek::Signature::from_bytes(&signature.to_ed25519_bytes().unwrap());
            use ed25519_dalek::Verifier as _;
            vk.verify(message, &sig).unwrap();
        }
        // A different qualifying set produces a different (equally
        // valid) signature: determinism is per-set.
        let a: Vec<&MemberShare> = vec![&shares[0], &shares[1]];
        let b: Vec<&MemberShare> = vec![&shares[0], &shares[2]];
        let sig_a = combine(&group, message, &qualifying(&group, &a, message)).unwrap();
        let sig_b = combine(&group, message, &qualifying(&group, &b, message)).unwrap();
        assert_ne!(sig_a.s, sig_b.s);
        verify(&group, message, &sig_a).unwrap();
        verify(&group, message, &sig_b).unwrap();
    }

    #[test]
    fn fewer_than_threshold_partials_are_refused_everywhere() {
        let (group, shares) = group_2_of_3();
        let message = b"m";
        // One member alone cannot even contribute a partial against a
        // one-member qualifying set.
        let err = sign_partial(
            &group,
            &shares[0],
            message,
            &[(1, shares_of_nonce(&shares[0], message))],
        )
        .unwrap_err();
        assert!(err.to_string().contains("qualifying set needs 2"), "{err}");
        // Combination with one partial refuses.
        let nonces = vec![shares_of_nonce(&shares[0], message)];
        let _ = nonces;
        let single = vec![PartialSignature {
            index: 1,
            nonce: shares_of_nonce(&shares[0], message),
            partial: "00".repeat(32),
        }];
        let err = combine(&group, message, &single).unwrap_err();
        assert!(err.to_string().contains("exactly 2 partials"), "{err}");
    }

    fn shares_of_nonce(share: &MemberShare, message: &[u8]) -> String {
        let nonce = scalar_from_seed(&[
            b"UNIDPP-SIGNATIF/CEREMONY/NONCE",
            &scalar_of(share).unwrap().to_bytes(),
            message,
        ]);
        hex32(&(nonce * ED25519_BASEPOINT_POINT).compress().0)
    }

    #[test]
    fn a_forged_partial_aborts_with_the_culprit_named() {
        let (group, shares) = group_2_of_3();
        let message = b"m";
        let set: Vec<&MemberShare> = vec![&shares[0], &shares[1]];
        let mut partials = qualifying(&group, &set, message);
        // Forging member 2's partial scalar.
        let mut bytes = unhex32(&partials[1].partial).unwrap();
        bytes[0] ^= 0x01;
        partials[1].partial = hex32(&bytes);
        let err = combine(&group, message, &partials).unwrap_err();
        assert!(err.to_string().contains("member 2"), "{err}");
        assert!(err.to_string().contains("invalid partial"), "{err}");
    }

    #[test]
    fn tampered_signature_or_message_fails_verification() {
        let (group, shares) = group_2_of_3();
        let message = b"statement";
        let set: Vec<&MemberShare> = vec![&shares[0], &shares[1]];
        let signature = combine(&group, message, &qualifying(&group, &set, message)).unwrap();
        verify(&group, message, &signature).unwrap();
        // Different message.
        assert!(verify(&group, b"other statement", &signature).is_err());
        // Tampered s.
        let mut tampered = signature.clone();
        let mut bytes = unhex32(&tampered.s).unwrap();
        bytes[0] ^= 0x01;
        tampered.s = hex32(&bytes);
        assert!(verify(&group, message, &tampered).is_err());
        // A signature naming fewer signers than the threshold.
        let mut thin = signature.clone();
        thin.signers = vec![1];
        assert!(verify(&group, message, &thin).is_err());
    }

    #[test]
    fn degenerate_quorums_are_refused() {
        assert!(generate(b"s", 0, 3).is_err());
        assert!(generate(b"s", 4, 3).is_err());
    }

    #[test]
    fn ceremony_files_round_trip() {
        let (group, shares) = group_2_of_3();
        let text = serde_json::to_string_pretty(&group.to_json()).unwrap();
        assert_eq!(GroupKey::from_json(&text).unwrap(), group);
        let text = serde_json::to_string_pretty(&shares[0].to_json()).unwrap();
        assert_eq!(MemberShare::from_json(&text).unwrap(), shares[0]);
        let (group, shares) = group_2_of_3();
        let set: Vec<&MemberShare> = vec![&shares[0], &shares[1]];
        let signature = combine(&group, b"m", &qualifying(&group, &set, b"m")).unwrap();
        let text = serde_json::to_string_pretty(&signature.to_json()).unwrap();
        assert_eq!(GroupSignature::from_json(&text).unwrap(), signature);
        assert_eq!(signature.to_ed25519_bytes().unwrap().len(), 64);
    }
}
