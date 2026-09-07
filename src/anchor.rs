//! Transparency anchoring: an append-only Merkle log with inclusion and
//! consistency proofs, signed tree heads, salted commitment leaves, a
//! log-of-logs M-of-K master list, and external time anchoring of tree
//! heads (CC/SIGNATIF §13 `transparency-anchoring`).
//!
//! Hashing follows the Confium transparency-log specification
//! (specs/specs/42-transparency-log.adoc, "RFC 6962 Merkle tree"):
//!
//! - leaf hash: `SHA-256(0x01 ‖ entry_hash)`
//! - internal hash: `SHA-256(0x02 ‖ left ‖ right)`
//!
//! with the 0x01/0x02 domain separation preventing second-preimage
//! attacks. (RFC 6962 itself uses 0x00/0x01; SIGNATIF follows the
//! Confium constants deliberately so the seam composes with Confium's
//! `confium-transparency` crate when the real binding lands.)
//!
//! **Logs anchor commitments, never facts** (the UniDPP design framework, enumeration
//! resistance): a leaf is [`LogEntry::commitment`] — a salted hash of
//! an event head or fact reference ([`salted_commitment`]) — plus an
//! opaque `salt_ref` into the owner-side salt store. A log operator
//! cannot correlate edges from what it hosts.
//!
//! The tree structure is the RFC 6962 "Merkle tree of leaves" over
//! `n` leaves with split point `k` = the largest power of two strictly
//! smaller than `n`; inclusion proofs carry `(sibling, side)` pairs
//! ([`ProofNode`]/[`Side`]) and consistency proofs carry the
//! RFC 6962 SUBPROOF node list.

use std::collections::BTreeMap;

use unidpp_model::{sha256, CanonicalWriter, Hash, Timestamp};

use crate::keyring::{KeyPair, PublicKey};
use crate::sign::{SignatureSlot, SigningDomain};
use crate::SignatifError;

/// Leaf hash: `SHA-256(0x01 ‖ entry_hash)`.
pub fn leaf_hash(entry: &Hash) -> Hash {
    sha256(&[&[0x01], entry.as_bytes()])
}

/// Internal node hash: `SHA-256(0x02 ‖ left ‖ right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    sha256(&[&[0x02], left.as_bytes(), right.as_bytes()])
}

/// The RFC 6962 split point: the largest power of two strictly smaller
/// than `n` (undefined for n < 2).
fn split(n: u64) -> u64 {
    debug_assert!(n >= 2);
    1u64 << (n - 1).ilog2()
}

/// Salted commitment to a fact reference: what the log anchors. The
/// salt is consumed here and never persisted beside the commitment —
/// salt discipline is the owner's (core `SaltStore` analogue).
pub fn salted_commitment(fact_ref: &[u8], salt: &[u8; 32]) -> Hash {
    sha256(&[salt, fact_ref])
}

/// Which side of the computed hash a proof sibling sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Side {
    /// Sibling is the left operand.
    Left,
    /// Sibling is the right operand.
    Right,
}

/// One rung of an inclusion proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProofNode {
    /// The sibling hash.
    pub sibling: Hash,
    /// Which side the sibling is on.
    pub side: Side,
}

/// An inclusion proof for the leaf at `leaf_index` in a tree of
/// `tree_size` leaves.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InclusionProof {
    /// Index of the proven leaf.
    pub leaf_index: u64,
    /// Size of the tree the proof was produced from.
    pub tree_size: u64,
    /// Siblings from the leaf level up.
    pub path: Vec<ProofNode>,
}

/// A consistency proof that the first `old_size` leaves of a
/// `new_size`-leaf tree hash to `old_root` (RFC 6962 SUBPROOF list).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConsistencyProof {
    /// Prefix size.
    pub old_size: u64,
    /// Full size.
    pub new_size: u64,
    /// Proof nodes (deepest first).
    pub path: Vec<Hash>,
}

/// One log entry: a commitment and an opaque salt reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LogEntry {
    /// The anchored commitment (e.g. an event-log head, a salted fact
    /// commitment, or a witness's tree-head commitment).
    pub commitment: Hash,
    /// Opaque owner-side salt reference (never the salt).
    pub salt_ref: Option<u64>,
}

impl LogEntry {
    /// An unsalted entry (the commitment itself binds the content).
    pub fn public(commitment: Hash) -> LogEntry {
        LogEntry {
            commitment,
            salt_ref: None,
        }
    }

    /// A salted entry (the salt whitens the anchored commitment; only
    /// the reference is recorded).
    pub fn salted(commitment: Hash, salt_ref: u64) -> LogEntry {
        LogEntry {
            commitment,
            salt_ref: Some(salt_ref),
        }
    }
}

/// An append-only transparency log over commitment leaves.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TransparencyLog {
    /// Operator-assigned log identity.
    pub log_id: String,
    entries: Vec<LogEntry>,
}

impl TransparencyLog {
    /// New empty log.
    pub fn new(log_id: &str) -> TransparencyLog {
        TransparencyLog {
            log_id: log_id.to_string(),
            entries: Vec::new(),
        }
    }

    /// Append an entry; returns its sequence number.
    pub fn append(&mut self, entry: LogEntry) -> u64 {
        self.entries.push(entry);
        (self.entries.len() - 1) as u64
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entry at `seq`.
    pub fn entry(&self, seq: u64) -> Result<&LogEntry, SignatifError> {
        self.entries.get(seq as usize).ok_or_else(|| {
            SignatifError::Transparency(format!("log `{}` has no entry {seq}", self.log_id))
        })
    }

    fn leaf_hashes(&self) -> Vec<Hash> {
        self.entries
            .iter()
            .map(|e| leaf_hash(&e.commitment))
            .collect()
    }

    /// The current tree root (None for an empty log).
    pub fn root(&self) -> Option<Hash> {
        mth(&self.leaf_hashes())
    }

    /// The root of the prefix of the first `size` leaves (for signing
    /// historical tree heads and consistency anchors).
    pub fn root_at_size(&self, size: u64) -> Result<Hash, SignatifError> {
        if size > self.len() as u64 {
            return Err(SignatifError::Transparency(format!(
                "log `{}` has only {} entries, not {size}",
                self.log_id,
                self.len()
            )));
        }
        mth(&self.leaf_hashes()[..size as usize]).ok_or_else(|| {
            SignatifError::Transparency("root of an empty prefix is undefined".into())
        })
    }

    /// Inclusion proof for the entry at `seq` against the current tree.
    pub fn inclusion_proof(&self, seq: u64) -> Result<InclusionProof, SignatifError> {
        let n = self.len() as u64;
        if n == 0 || seq >= n {
            return Err(SignatifError::Transparency(format!(
                "cannot prove inclusion of {seq} in log `{}` of size {n}",
                self.log_id
            )));
        }
        let leaves = self.leaf_hashes();
        let mut path = Vec::new();
        path_recursive(seq, &leaves, &mut path);
        Ok(InclusionProof {
            leaf_index: seq,
            tree_size: n,
            path,
        })
    }

    /// Consistency proof between the prefix of the first `old_size`
    /// leaves and the current tree (RFC 6962 PROOF).
    pub fn consistency_proof(&self, old_size: u64) -> Result<ConsistencyProof, SignatifError> {
        let new_size = self.len() as u64;
        if old_size > new_size {
            return Err(SignatifError::Transparency(format!(
                "consistency proof backwards ({old_size} > {new_size}) is impossible"
            )));
        }
        let leaves = self.leaf_hashes();
        let mut path = Vec::new();
        if old_size > 0 {
            sub_proof(old_size, &leaves, true, &mut path);
        }
        Ok(ConsistencyProof {
            old_size,
            new_size,
            path,
        })
    }

    /// Sign a tree head for the current size with the operator's key.
    pub fn sign_tree_head(
        &self,
        at: Timestamp,
        operator_key: &KeyPair,
    ) -> Result<SignedTreeHead, SignatifError> {
        let root = self
            .root()
            .ok_or_else(|| SignatifError::Transparency("cannot sign an empty tree head".into()))?;
        let tree_size = self.len() as u64;
        let slot = SignatureSlot::sign(
            operator_key,
            SigningDomain::TreeHead,
            &SignedTreeHead::canonical_bytes(&self.log_id, tree_size, at, &root),
        )?;
        Ok(SignedTreeHead {
            log_id: self.log_id.clone(),
            tree_size,
            timestamp: at,
            root,
            signature: slot,
            external_anchor: None,
        })
    }
}

/// A signed tree head: the operator's signed statement of the tree
/// size, timestamp, and root. Verifiers pin STHs (gossip/witness them)
/// so a log cannot rewrite history without detection.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedTreeHead {
    /// Log identity.
    pub log_id: String,
    /// Tree size when signed.
    pub tree_size: u64,
    /// Signature moment.
    pub timestamp: Timestamp,
    /// Tree root.
    pub root: Hash,
    /// Operator's signature slot.
    pub signature: SignatureSlot,
    /// The external time anchor of this head (CC/SIGNATIF §13
    /// `transparency-anchoring`): the commitment the operator produced
    /// for submission to an external, irrefutable time source. `None`
    /// until [`SignedTreeHead::anchored_externally`] is used. The
    /// anchor commits *to* the signed head bytes (the operator
    /// signature is not weakened by attaching it afterwards).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_anchor: Option<ExternalAnchor>,
}

impl SignedTreeHead {
    /// Canonical signed bytes.
    pub fn canonical_bytes(
        log_id: &str,
        tree_size: u64,
        timestamp: Timestamp,
        root: &Hash,
    ) -> Vec<u8> {
        let mut w = CanonicalWriter::new();
        w.write_str(log_id);
        w.write_u64(tree_size);
        w.write_i64(timestamp.secs);
        w.write_u32(timestamp.nanos);
        w.write_hash(root);
        w.into_bytes()
    }

    /// Verify the operator's signature.
    pub fn verify(&self, operator: &PublicKey) -> Result<(), SignatifError> {
        self.signature.verify(
            SigningDomain::TreeHead,
            &SignedTreeHead::canonical_bytes(
                &self.log_id,
                self.tree_size,
                self.timestamp,
                &self.root,
            ),
            operator,
        )
    }

    /// The commitment leaf this STH contributes to a log-of-logs.
    pub fn lol_commitment(&self) -> Hash {
        let mut w = CanonicalWriter::new();
        w.write_str(&self.log_id);
        w.write_u64(self.tree_size);
        w.write_hash(&self.root);
        let inner = w.into_bytes();
        sha256(&[b"UNIDPP-SIGNATIF/WITNESS-STH", &inner])
    }

    /// Produce and attach an external time anchor for this head
    /// (CC/SIGNATIF §13 `transparency-anchoring`): builds the
    /// commitment payload for `method` (see
    /// [`external_anchor_payload`]) and records it on the head. The
    /// anchor commits *to* the head's canonical bytes, so attaching it
    /// after the operator's signature is sound; any later mutation of
    /// the head breaks [`SignedTreeHead::verify_external_anchor`].
    pub fn anchored_externally(mut self, method: ExternalAnchorMethod) -> SignedTreeHead {
        self.external_anchor = Some(external_anchor_payload(&self, &method));
        self
    }

    /// Verify this head's attached external anchor (if any) against the
    /// head's own bytes — the no-network half of the external-anchoring
    /// check (that the *completed* proof from the time source really
    /// covers this payload is verified by the deployment against the
    /// source's proof format).
    pub fn verify_external_anchor(&self) -> Result<(), SignatifError> {
        match &self.external_anchor {
            None => Err(SignatifError::Transparency(format!(
                "tree head of log `{}` carries no external anchor",
                self.log_id
            ))),
            Some(anchor) => verify_external_anchor(anchor, self),
        }
    }
}

/// Where a tree head is anchored for irrefutable external time
/// (CC/SIGNATIF §13 `transparency-anchoring`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ExternalAnchorMethod {
    /// An RFC 3161 time-stamp authority: the payload is a minimal DER
    /// `TimeStampReq` carrying SHA-256 of the head's canonical bytes.
    Rfc3161 {
        /// The TSA endpoint the request bytes are submitted to.
        tsa_url: String,
    },
    /// An OpenTimestamps-style lite commitment: SHA-256 of the head's
    /// canonical bytes plus a rendezvous point (a calendar/aggregator
    /// URI that batches commitments into an upstream anchor).
    OtsLite {
        /// The rendezvous URI (calendar/aggregator) to submit the
        /// digest to.
        rendezvous: String,
    },
}

impl ExternalAnchorMethod {
    /// Stable method token (part of the OTS-lite payload bytes).
    pub fn token(&self) -> &'static str {
        match self {
            ExternalAnchorMethod::Rfc3161 { .. } => "rfc3161",
            ExternalAnchorMethod::OtsLite { .. } => "ots-lite",
        }
    }

    /// The submission target (TSA URL or rendezvous URI) — where the
    /// payload is sent; the library itself never performs the call.
    pub fn submission_target(&self) -> &str {
        match self {
            ExternalAnchorMethod::Rfc3161 { tsa_url } => tsa_url,
            ExternalAnchorMethod::OtsLite { rendezvous } => rendezvous,
        }
    }
}

/// An external time-anchor commitment: the exact bytes a log operator
/// submits to an external time source, plus the digest they commit to.
///
/// **No network calls are made by this library.** The documented
/// submission flow (CC/SIGNATIF §13): (1) the operator builds the
/// payload with [`external_anchor_payload`]; (2) submits `payload` to
/// [`ExternalAnchorMethod::submission_target`] — an RFC 3161 TSA via
/// HTTP (content-type `application/timestamp-query`) or an
/// OpenTimestamps-style calendar; (3) stores the returned proof
/// (RFC 3161 `TimeStampResp` / OTS proof file) deployment-side; (4)
/// verification of the completed proof against the time source is a
/// deployment concern (it needs the source's trust anchors), while
/// [`verify_external_anchor`] checks — offline — that a given anchor
/// really commits to a given tree head.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExternalAnchor {
    /// The anchoring method (and its submission target).
    pub method: ExternalAnchorMethod,
    /// SHA-256 of the head's canonical bytes — the committed digest.
    pub digest: Hash,
    /// Request nonce (RFC 3161: binds the response to this request;
    /// OTS-lite carries 0). Derived deterministically from the digest
    /// so the payload is reproducible; deployments may substitute a
    /// CSPRNG nonce before submission.
    pub nonce: u64,
    /// The exact bytes to submit.
    pub payload: Vec<u8>,
}

/// Build the external-anchor commitment payload for a signed tree
/// head: `sha256(head-canonical-bytes)` plus the method's submission
/// framing.
///
/// - [`ExternalAnchorMethod::OtsLite`]: canonical length-prefixed
///   bytes `tag || rendezvous || digest` (the OpenTimestamps-style
///   "digest + rendezvous point" commitment);
/// - [`ExternalAnchorMethod::Rfc3161`]: a minimal DER `TimeStampReq`
///   (`version=1`, SHA-256 `messageImprint`, `nonce`) ready for
///   `application/timestamp-query` submission.
pub fn external_anchor_payload(
    sth: &SignedTreeHead,
    method: &ExternalAnchorMethod,
) -> ExternalAnchor {
    let digest = sha256(&[&SignedTreeHead::canonical_bytes(
        &sth.log_id,
        sth.tree_size,
        sth.timestamp,
        &sth.root,
    )]);
    let nonce = u64::from_be_bytes(digest.as_bytes()[..8].try_into().unwrap());
    let payload = match method {
        ExternalAnchorMethod::OtsLite { rendezvous } => {
            let mut w = CanonicalWriter::new();
            w.write_str("UNIDPP-SIGNATIF/EXTERNAL-ANCHOR");
            w.write_str("ots-lite");
            w.write_str(rendezvous);
            w.write_hash(&digest);
            w.into_bytes()
        }
        ExternalAnchorMethod::Rfc3161 { .. } => rfc3161_timestamp_req(&digest, nonce),
    };
    ExternalAnchor {
        method: method.clone(),
        digest,
        nonce,
        payload,
    }
}

/// Verify that an external anchor commits to exactly this tree head:
/// the anchor's digest and payload are recomputed from the head's
/// canonical bytes under the anchor's own method and compared. A head
/// with a different size, timestamp, or root produces a different
/// digest, so any post-hoc mutation of the head is caught offline.
pub fn verify_external_anchor(
    anchor: &ExternalAnchor,
    sth: &SignedTreeHead,
) -> Result<(), SignatifError> {
    let expected = external_anchor_payload(sth, &anchor.method);
    if anchor.digest != expected.digest {
        return Err(SignatifError::Transparency(format!(
            "external anchor commits to digest {}, but the head hashes to {}",
            anchor.digest, expected.digest
        )));
    }
    if anchor.payload != expected.payload {
        return Err(SignatifError::Transparency(
            "external anchor payload does not match the head (bytes differ)".into(),
        ));
    }
    Ok(())
}

// ---- Minimal DER (RFC 3161 timestamp request) -------------------------
//
// Hand-rolled to keep the crate dependency-free (the request is three
// nested SEQUENCEs: version, messageImprint, nonce).

/// DER length octets (short form below 128, long form above).
fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let mut bytes = Vec::new();
        let mut n = len;
        while n > 0 {
            bytes.push((n & 0xff) as u8);
            n >>= 8;
        }
        bytes.reverse();
        let mut out = vec![0x80 | bytes.len() as u8];
        out.extend_from_slice(&bytes);
        out
    }
}

/// One DER TLV (tag, length, content).
fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + content.len());
    out.push(tag);
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// Minimal RFC 3161 `TimeStampReq`: version 1, SHA-256 messageImprint
/// (OID 2.16.840.1.101.3.4.2.1 with NULL parameters), nonce. No
/// certReq, no extensions.
fn rfc3161_timestamp_req(digest: &Hash, nonce: u64) -> Vec<u8> {
    let version = der_tlv(0x02, &[1]); // INTEGER 1
    let oid = der_tlv(
        0x06,
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
    );
    let null = der_tlv(0x05, &[]);
    let mut alg_id_content = oid;
    alg_id_content.extend_from_slice(&null);
    let alg_id = der_tlv(0x30, &alg_id_content);
    let hashed_message = der_tlv(0x04, digest.as_bytes());
    let mut imprint_content = alg_id;
    imprint_content.extend_from_slice(&hashed_message);
    let message_imprint = der_tlv(0x30, &imprint_content);
    let nonce_int = der_tlv(0x02, &nonce.to_be_bytes());
    let mut req_content = version;
    req_content.extend_from_slice(&message_imprint);
    req_content.extend_from_slice(&nonce_int);
    der_tlv(0x30, &req_content)
}

/// Verify an inclusion proof: reconstruct the root from the entry's
/// commitment and the proof path, and compare.
pub fn verify_inclusion(
    entry: &Hash,
    proof: &InclusionProof,
    root: &Hash,
) -> Result<(), SignatifError> {
    if proof.leaf_index >= proof.tree_size {
        return Err(SignatifError::Transparency(format!(
            "proof claims leaf {} in a tree of {}",
            proof.leaf_index, proof.tree_size
        )));
    }
    let mut current = leaf_hash(entry);
    for node in &proof.path {
        current = match node.side {
            Side::Left => node_hash(&node.sibling, &current),
            Side::Right => node_hash(&current, &node.sibling),
        };
    }
    if current == *root {
        Ok(())
    } else {
        Err(SignatifError::Transparency(format!(
            "inclusion proof reconstructs {current}, not the pinned root {root}"
        )))
    }
}

/// Verify a consistency proof: the first `old_size` leaves of the
/// `new_size` tree must hash to `old_root`, and the whole tree to
/// `new_root`.
///
/// The verification walks the same recursion the generator used,
/// consuming proof nodes deepest-first; the old root is threaded down
/// the left spine as the known anchor (exactly once), and any node the
/// b=false branch needs comes from the proof.
pub fn verify_consistency(
    old_size: u64,
    old_root: &Hash,
    new_size: u64,
    new_root: &Hash,
    proof: &[Hash],
) -> Result<(), SignatifError> {
    if old_size > new_size {
        return Err(SignatifError::Transparency(format!(
            "cannot verify consistency {old_size} -> {new_size} (shrinking)"
        )));
    }
    if old_size == new_size {
        if !proof.is_empty() {
            return Err(SignatifError::Transparency(
                "consistency proof for equal sizes must be empty".into(),
            ));
        }
        if old_root != new_root {
            return Err(SignatifError::Transparency(
                "equal sizes must have equal roots".into(),
            ));
        }
        return Ok(());
    }
    if old_size == 0 {
        if !proof.is_empty() {
            return Err(SignatifError::Transparency(
                "consistency proof from the empty prefix must be empty".into(),
            ));
        }
        return Ok(());
    }
    let mut idx = 0usize;
    let (computed_old, computed_new) =
        sub_verify(old_size, new_size, proof, &mut idx, Some(*old_root))?;
    if idx != proof.len() {
        return Err(SignatifError::Transparency(format!(
            "consistency proof has {} leftover nodes",
            proof.len() - idx
        )));
    }
    if computed_old != *old_root {
        return Err(SignatifError::Transparency(format!(
            "consistency proof reconstructs prefix root {computed_old}, not {old_root}"
        )));
    }
    if computed_new != *new_root {
        return Err(SignatifError::Transparency(format!(
            "consistency proof reconstructs root {computed_new}, not {new_root}"
        )));
    }
    Ok(())
}

fn next_node(proof: &[Hash], idx: &mut usize) -> Result<Hash, SignatifError> {
    let h = proof
        .get(*idx)
        .copied()
        .ok_or_else(|| SignatifError::Transparency("consistency proof is truncated".into()))?;
    *idx += 1;
    Ok(h)
}

fn sub_verify(
    m: u64,
    n: u64,
    proof: &[Hash],
    idx: &mut usize,
    known_old: Option<Hash>,
) -> Result<(Hash, Hash), SignatifError> {
    if m == n {
        // Base: this subtree is exactly the old prefix. If it is
        // externally anchored, the known root stands in; otherwise the
        // generator emitted its hash as a proof node.
        let h = match known_old {
            Some(h) => h,
            None => next_node(proof, idx)?,
        };
        return Ok((h, h));
    }
    let k = split(n);
    if m <= k {
        let (o, ne) = sub_verify(m, k, proof, idx, known_old)?;
        let sib = next_node(proof, idx)?;
        Ok((o, node_hash(&ne, &sib)))
    } else {
        let (o, ne) = sub_verify(m - k, n - k, proof, idx, None)?;
        let sib = next_node(proof, idx)?;
        Ok((node_hash(&sib, &o), node_hash(&sib, &ne)))
    }
}

/// MTH over a slice of leaf hashes (RFC 6962 MTH, Confium constants).
fn mth(leaves: &[Hash]) -> Option<Hash> {
    match leaves.len() {
        0 => None,
        1 => Some(leaves[0]),
        n => {
            let k = split(n as u64) as usize;
            Some(node_hash(
                &mth(&leaves[..k]).unwrap(),
                &mth(&leaves[k..]).unwrap(),
            ))
        }
    }
}

fn path_recursive(m: u64, leaves: &[Hash], path: &mut Vec<ProofNode>) {
    let n = leaves.len() as u64;
    if n == 1 {
        return;
    }
    let k = split(n);
    if m < k {
        path_recursive(m, &leaves[..k as usize], path);
        path.push(ProofNode {
            sibling: mth(&leaves[k as usize..]).unwrap(),
            side: Side::Right,
        });
    } else {
        path_recursive(m - k, &leaves[k as usize..], path);
        path.push(ProofNode {
            sibling: mth(&leaves[..k as usize]).unwrap(),
            side: Side::Left,
        });
    }
}

fn sub_proof(m: u64, leaves: &[Hash], anchored: bool, path: &mut Vec<Hash>) {
    let n = leaves.len() as u64;
    if m == n {
        if !anchored {
            path.push(mth(leaves).unwrap());
        }
        return;
    }
    let k = split(n);
    if m <= k {
        sub_proof(m, &leaves[..k as usize], anchored, path);
        path.push(mth(&leaves[k as usize..]).unwrap());
    } else {
        sub_proof(m - k, &leaves[k as usize..], false, path);
        path.push(mth(&leaves[..k as usize]).unwrap());
    }
}

/// The log-of-logs: witness logs' signed tree heads anchored as leaves
/// of one master log, with an M-of-K quorum for master-list acceptance.
///
/// This is the transparency analogue of the trust master list: a root
/// or artifact is *globally* anchored when M of the K independent
/// witness logs carry (an STH containing) its commitment.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LogOfLogs {
    /// The master log itself.
    pub log: TransparencyLog,
    /// Required distinct witnesses (M).
    pub m: usize,
    /// Total witnesses (K).
    pub k: usize,
    seq_by_log: BTreeMap<String, Vec<u64>>,
}

impl LogOfLogs {
    /// New empty log-of-logs over K witnesses requiring M.
    pub fn new(m: usize, k: usize) -> LogOfLogs {
        LogOfLogs {
            log: TransparencyLog::new("log-of-logs"),
            m,
            k,
            seq_by_log: BTreeMap::new(),
        }
    }

    /// Anchor a witness STH; returns its sequence number.
    pub fn append_witness_sth(&mut self, sth: &SignedTreeHead) -> u64 {
        let seq = self.log.append(LogEntry::public(sth.lol_commitment()));
        self.seq_by_log
            .entry(sth.log_id.clone())
            .or_default()
            .push(seq);
        seq
    }

    /// Inclusion proof of a witness STH's commitment in the master log.
    pub fn witness_proof(&self, sth: &SignedTreeHead) -> Result<InclusionProof, SignatifError> {
        let seq = self
            .seq_by_log
            .get(&sth.log_id)
            .and_then(|seqs| seqs.last().copied())
            .ok_or_else(|| {
                SignatifError::Transparency(format!(
                    "witness log `{}` has no anchored STH",
                    sth.log_id
                ))
            })?;
        self.log.inclusion_proof(seq)
    }

    /// The master root (None when nothing is anchored yet).
    pub fn root(&self) -> Option<Hash> {
        self.log.root()
    }
}

/// Verify an M-of-K master quorum: at least `m` distinct witness logs'
/// STHs verify (operator signature + inclusion into the master root).
///
/// Each item is a triple of the witness's STH, the operator key, and
/// the inclusion proof of the STH's commitment into the master log.
pub fn verify_master_quorum(
    master_root: &Hash,
    items: &[(SignedTreeHead, PublicKey, InclusionProof)],
    m: usize,
) -> Result<bool, SignatifError> {
    let mut witnessed: BTreeMap<String, ()> = BTreeMap::new();
    for (sth, operator, proof) in items {
        sth.verify(operator)?;
        verify_inclusion(&sth.lol_commitment(), proof, master_root)?;
        witnessed.insert(sth.log_id.clone(), ());
    }
    Ok(witnessed.len() >= m)
}

impl TransparencyLog {
    /// Test support: overwrite one entry's commitment (simulates an
    /// in-place tamper by a malicious operator).
    #[doc(hidden)]
    pub fn entries_tamper_for_test(&mut self, seq: u64, commitment: Hash) {
        if let Some(e) = self.entries.get_mut(seq as usize) {
            e.commitment = commitment;
        }
    }

    /// Test support: drop the last entry (simulates truncation).
    #[doc(hidden)]
    pub fn truncate_for_test(&mut self) -> bool {
        self.entries.pop().is_some()
    }

    /// Whether the log's prefix of `sth.tree_size` entries still hashes
    /// to the STH's pinned root. A pinned STH stays valid for its
    /// prefix forever (that is what consistency proofs are for); what
    /// moves on is the current head.
    pub fn verify_size_against(&self, sth: &SignedTreeHead) -> Result<(), SignatifError> {
        let actual = self.root_at_size(sth.tree_size)?;
        if actual == sth.root {
            Ok(())
        } else {
            Err(SignatifError::Transparency(format!(
                "log `{}` prefix of {} hashes to {actual}, STH pins {}",
                self.log_id, sth.tree_size, sth.root
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Suite;

    /// A raw entry commitment.
    fn entry(i: u8) -> Hash {
        sha256(&[&[i]])
    }

    /// Leaf hashes of the first `n` entries.
    fn leaves(n: u8) -> Vec<Hash> {
        (0..n).map(|i| leaf_hash(&entry(i))).collect()
    }

    /// Entry commitments for `n` entries.
    fn entries(n: u8) -> Vec<Hash> {
        (0..n).map(entry).collect()
    }

    #[test]
    fn split_points() {
        assert_eq!(split(2), 1);
        assert_eq!(split(3), 2);
        assert_eq!(split(4), 2);
        assert_eq!(split(5), 4);
        assert_eq!(split(8), 4);
        assert_eq!(split(9), 8);
        assert_eq!(split(1023), 512);
        assert_eq!(split(1024), 512);
        assert_eq!(split(1025), 1024);
    }

    #[test]
    fn hand_computed_small_roots() {
        // n=1: root = the single leaf hash H(0x01 || entry0).
        let l1 = leaves(1);
        assert_eq!(mth(&l1), Some(leaf_hash(&entry(0))));
        // n=2: root = H(0x02 || MTH(l0) || MTH(l1)) with MTH(li)=H(0x01||li).
        let l2 = leaves(2);
        assert_eq!(mth(&l2), Some(node_hash(&l2[0], &l2[1])));
        // n=3: root = H(0x02 || MTH(D[0:2]) || MTH(D[2:3]))
        let l3 = leaves(3);
        assert_eq!(
            mth(&l3),
            Some(node_hash(&mth(&l3[..2]).unwrap(), &mth(&l3[2..]).unwrap()))
        );
    }

    #[test]
    fn inclusion_all_positions_all_sizes() {
        for n in 1..=17u8 {
            let lv = leaves(n);
            let raw = entries(n);
            let root = mth(&lv).unwrap();
            for i in 0..n as u64 {
                let mut path = Vec::new();
                path_recursive(i, &lv, &mut path);
                let proof = InclusionProof {
                    leaf_index: i,
                    tree_size: n as u64,
                    path,
                };
                assert!(
                    verify_inclusion(&raw[i as usize], &proof, &root).is_ok(),
                    "inclusion {i}/{n} must verify"
                );
                // Any other leaf fails.
                if n > 1 {
                    let wrong = raw[((i + 1) % n as u64) as usize];
                    assert!(verify_inclusion(&wrong, &proof, &root).is_err());
                }
            }
        }
    }

    #[test]
    fn inclusion_tamper_detection() {
        let mut log = TransparencyLog::new("tlog");
        for i in 0..9u8 {
            log.append(LogEntry::public(sha256(&[&[i]])));
        }
        let root = log.root().unwrap();
        let proof = log.inclusion_proof(4).unwrap();
        assert!(verify_inclusion(&log.entry(4).unwrap().commitment, &proof, &root).is_ok());
        // Flip one commitment elsewhere in the log: entry 4's proof
        // still reconstructs, but against a DIFFERENT root — the pinned
        // root catches it.
        let mut tampered = log.clone();
        tampered.entries[7].commitment = sha256(&[b"x"]);
        let new_root = tampered.root().unwrap();
        assert_ne!(root, new_root);
        assert!(verify_inclusion(&log.entry(4).unwrap().commitment, &proof, &new_root).is_err());
        // Truncation (dropping the tail) is caught by STH/root pinning.
        let mut truncated = log.clone();
        truncated.entries.pop();
        assert!(verify_inclusion(
            &log.entry(4).unwrap().commitment,
            &truncated.inclusion_proof(4).unwrap(),
            &root
        )
        .is_err());
    }

    #[test]
    fn consistency_all_pairs() {
        for n in 1..=17usize {
            let lv = leaves(n as u8);
            for m in 1..=n {
                let old_root = mth(&lv[..m]).unwrap();
                let new_root = mth(&lv).unwrap();
                let mut path = Vec::new();
                sub_proof(m as u64, &lv, true, &mut path);
                assert!(
                    verify_consistency(m as u64, &old_root, n as u64, &new_root, &path).is_ok(),
                    "consistency {m}->{n} must verify"
                );
                // Corrupt the old root.
                let bad_old = sha256(&[b"nope"]);
                assert!(
                    verify_consistency(m as u64, &bad_old, n as u64, &new_root, &path).is_err()
                );
                // Corrupt the new root.
                assert!(
                    verify_consistency(m as u64, &old_root, n as u64, &bad_old, &path).is_err()
                );
                // Truncate the proof.
                if !path.is_empty() {
                    assert!(verify_consistency(
                        m as u64,
                        &old_root,
                        n as u64,
                        &new_root,
                        &path[..path.len() - 1]
                    )
                    .is_err());
                }
            }
        }
    }

    #[test]
    fn log_level_proofs_match_recursive() {
        let mut log = TransparencyLog::new("t");
        for i in 0..6u8 {
            log.append(LogEntry::public(sha256(&[&[i]])));
        }
        for seq in 0..6u64 {
            let proof = log.inclusion_proof(seq).unwrap();
            assert_eq!(proof.tree_size, 6);
            assert!(verify_inclusion(
                &log.entry(seq).unwrap().commitment,
                &proof,
                &log.root().unwrap()
            )
            .is_ok());
        }
        for old in 1..=6u64 {
            let p = log.consistency_proof(old).unwrap();
            let old_root = log.root_at_size(old).unwrap();
            assert!(verify_consistency(old, &old_root, 6, &log.root().unwrap(), &p.path).is_ok());
        }
        assert!(log.consistency_proof(7).is_err());
        assert!(matches!(
            log.inclusion_proof(6),
            Err(SignatifError::Transparency(_))
        ));
    }

    #[test]
    fn sth_sign_and_verify() {
        let mut log = TransparencyLog::new("t");
        for i in 0..4u8 {
            log.append(LogEntry::public(sha256(&[&[i]])));
        }
        let operator = KeyPair::seeded(Suite::Ed25519, b"op").unwrap();
        let sth = log
            .sign_tree_head(Timestamp::from_secs(1234), &operator)
            .unwrap();
        assert!(sth.verify(operator.public()).is_ok());
        // Different operator.
        let other = KeyPair::seeded(Suite::EcdsaP256, b"op2").unwrap();
        assert!(sth.verify(other.public()).is_err());
        // Tampered root.
        let mut bad = sth.clone();
        bad.root = sha256(&[b"evil"]);
        assert!(bad.verify(operator.public()).is_err());
        // The pinned STH stays valid for its prefix after the log
        // grows (that is what consistency proofs are for)...
        let old_root = sth.root;
        log.append(LogEntry::public(sha256(&[b"extra"])));
        assert!(log.verify_size_against(&sth).is_ok());
        // ...but the current head moves on, and the 4->5 consistency
        // proof ties the pinned root to the new head.
        let new_root = log.root().unwrap();
        assert_ne!(old_root, new_root);
        let sth2 = log
            .sign_tree_head(Timestamp::from_secs(1235), &operator)
            .unwrap();
        assert_eq!(sth2.root, new_root);
        assert_ne!(sth.root, sth2.root);
        let proof = log.consistency_proof(4).unwrap();
        assert!(verify_consistency(4, &old_root, 5, &new_root, &proof.path).is_ok());
    }

    #[test]
    fn log_of_logs_master_quorum() {
        let mk = |id: &str, seed: &[u8]| -> (TransparencyLog, KeyPair) {
            let mut log = TransparencyLog::new(id);
            for i in 0..3u8 {
                log.append(LogEntry::public(sha256(&[id.as_bytes(), &[i]])));
            }
            (log, KeyPair::seeded(Suite::Ed25519, seed).unwrap())
        };
        let (w1, k1) = mk("witness-1", b"w1");
        let (w2, k2) = mk("witness-2", b"w2");
        let (w3, k3) = mk("witness-3", b"w3");
        let at = Timestamp::from_secs(10);
        let sth1 = w1.sign_tree_head(at, &k1).unwrap();
        let sth2 = w2.sign_tree_head(at, &k2).unwrap();
        let sth3 = w3.sign_tree_head(at, &k3).unwrap();

        let mut lol = LogOfLogs::new(2, 3);
        lol.append_witness_sth(&sth1);
        lol.append_witness_sth(&sth2);
        lol.append_witness_sth(&sth3);
        let master_root = lol.root().unwrap();

        let items = vec![
            (
                sth1.clone(),
                *k1.public(),
                lol.witness_proof(&sth1).unwrap(),
            ),
            (
                sth2.clone(),
                *k2.public(),
                lol.witness_proof(&sth2).unwrap(),
            ),
            (
                sth3.clone(),
                *k3.public(),
                lol.witness_proof(&sth3).unwrap(),
            ),
        ];
        assert!(verify_master_quorum(&master_root, &items, 3).unwrap());
        // 2-of-3 holds with one witness dropped.
        assert!(verify_master_quorum(&master_root, &items[..2], 2).unwrap());
        // Not 3-of-2.
        assert!(!verify_master_quorum(&master_root, &items[..2], 3).unwrap());
        // Wrong master root fails.
        let bad_root = sha256(&[b"evil"]);
        assert!(verify_master_quorum(&bad_root, &items, 2).is_err());
        // The same witness attesting twice does not double-count: the
        // distinct-log set is keyed by log id.
        let dupe = vec![
            (
                sth1.clone(),
                *k1.public(),
                lol.witness_proof(&sth1).unwrap(),
            ),
            (
                sth1.clone(),
                *k1.public(),
                lol.witness_proof(&sth1).unwrap(),
            ),
        ];
        assert!(!verify_master_quorum(&master_root, &dupe, 2).unwrap());
    }

    #[test]
    fn salted_commitments_never_expose_facts() {
        let c1 = salted_commitment(b"urn:unidpp:passport:car-42", &[1u8; 32]);
        let c2 = salted_commitment(b"urn:unidpp:passport:car-42", &[2u8; 32]);
        assert_ne!(c1, c2);
        let c3 = salted_commitment(b"urn:unidpp:passport:car-43", &[1u8; 32]);
        assert_ne!(c1, c3);
        // The log stores only the commitment + an opaque salt ref.
        let mut log = TransparencyLog::new("t");
        log.append(LogEntry::salted(c1, 0));
        log.append(LogEntry::salted(c2, 1));
        let json = serde_json::to_string(&log).unwrap();
        assert!(!json.contains("car-42"));
        assert!(json.contains("\"salt_ref\":0"));
    }

    /// A signed tree head for the external-anchoring tests.
    fn sample_sth() -> (SignedTreeHead, KeyPair) {
        let mut log = TransparencyLog::new("t");
        for i in 0..4u8 {
            log.append(LogEntry::public(sha256(&[&[i]])));
        }
        let operator = KeyPair::seeded(Suite::Ed25519, b"anchor-op").unwrap();
        (
            log.sign_tree_head(Timestamp::from_secs(7000), &operator)
                .unwrap(),
            operator,
        )
    }

    #[test]
    fn external_anchor_commits_to_the_head() {
        let (sth, _op) = sample_sth();
        let ots = ExternalAnchorMethod::OtsLite {
            rendezvous: "https://calendar.unidpp.example/anchor".into(),
        };
        let anchor = external_anchor_payload(&sth, &ots);
        // The digest is SHA-256 of the head's canonical bytes.
        assert_eq!(
            anchor.digest,
            sha256(&[&SignedTreeHead::canonical_bytes(
                &sth.log_id,
                sth.tree_size,
                sth.timestamp,
                &sth.root
            )])
        );
        // Deterministic: same head + method, same payload.
        assert_eq!(anchor.payload, external_anchor_payload(&sth, &ots).payload);
        // The method carries its submission target; no network happens.
        assert_eq!(anchor.method.token(), "ots-lite");
        assert_eq!(anchor.method.submission_target(), ots.submission_target());
        assert!(anchor.nonce > 0);
        // Verification: ok against the very head; broken against any
        // mutation of it (size, timestamp, root).
        assert!(verify_external_anchor(&anchor, &sth).is_ok());
        let grown = SignedTreeHead {
            tree_size: sth.tree_size + 1,
            ..sth.clone()
        };
        assert!(verify_external_anchor(&anchor, &grown).is_err());
        let later = SignedTreeHead {
            timestamp: Timestamp::from_secs(sth.timestamp.secs + 1),
            ..sth.clone()
        };
        assert!(verify_external_anchor(&anchor, &later).is_err());
        // A different method commits differently (different payload
        // framing of the same digest).
        let tsa = ExternalAnchorMethod::Rfc3161 {
            tsa_url: "https://tsa.example.org".into(),
        };
        let other = external_anchor_payload(&sth, &tsa);
        assert_eq!(other.digest, anchor.digest);
        assert_ne!(other.payload, anchor.payload);
        // Attaching to the head keeps the operator signature intact
        // and verifies; a head without an anchor reports it.
        let anchored = sth.clone().anchored_externally(ots);
        let operator = KeyPair::seeded(Suite::Ed25519, b"anchor-op").unwrap();
        assert!(anchored.verify(operator.public()).is_ok());
        assert!(anchored.verify_external_anchor().is_ok());
        assert!(sth.verify_external_anchor().is_err());
        // Serde round trip preserves the anchor.
        let json = serde_json::to_string(&anchored).unwrap();
        let back: SignedTreeHead = serde_json::from_str(&json).unwrap();
        assert_eq!(back, anchored);
    }

    #[test]
    fn rfc3161_request_is_well_formed_der() {
        let (sth, _op) = sample_sth();
        let tsa = ExternalAnchorMethod::Rfc3161 {
            tsa_url: "https://tsa.example.org".into(),
        };
        let anchor = external_anchor_payload(&sth, &tsa);
        let p = &anchor.payload;
        // Outer structure: SEQUENCE.
        assert_eq!(p[0], 0x30);
        // Contains the SHA-256 algorithm identifier OID
        // (2.16.840.1.101.3.4.2.1) and the 32-byte digest as the
        // messageImprint OCTET STRING.
        let oid: &[u8] = &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ];
        let oid_pos = p
            .windows(oid.len())
            .position(|w| w == oid)
            .expect("SHA-256 OID must be present");
        let octet_tag = oid_pos + oid.len() + 2; // skip OID TLV + NULL TLV (05 00) + OCTET tag
        assert_eq!(p[octet_tag], 0x04, "hashedMessage must be an OCTET STRING");
        assert_eq!(p[octet_tag + 1], 32, "SHA-256 digest is 32 bytes");
        assert_eq!(
            &p[octet_tag + 2..octet_tag + 2 + 32],
            anchor.digest.as_bytes(),
            "the request carries the committed digest"
        );
        // The nonce is derived from the digest (reproducible).
        assert_eq!(
            anchor.nonce,
            u64::from_be_bytes(anchor.digest.as_bytes()[..8].try_into().unwrap())
        );
        // Structural verification against the head.
        assert!(verify_external_anchor(&anchor, &sth).is_ok());
        // A truncated payload is rejected.
        let mut tampered = anchor.clone();
        tampered.payload.truncate(tampered.payload.len() - 1);
        assert!(verify_external_anchor(&tampered, &sth).is_err());
    }
}
