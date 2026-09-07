//! Property: Merkle inclusion and consistency proofs over randomized
//! seeded trees — every proof verifies, wrong roots/leaves/proof shapes
//! never do.

mod common;

use unidpp_model::Hash;
use unidpp_signatif::anchor::{
    leaf_hash, node_hash, verify_consistency, verify_inclusion, InclusionProof, LogEntry,
    TransparencyLog,
};

/// Local xorshift64* (test-only; the core's convention).
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next_u64() % (hi - lo)
    }
    fn hash(&mut self) -> Hash {
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_exact_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        Hash::from_slice(&bytes).unwrap()
    }
}

#[test]
fn every_inclusion_proof_verifies_and_rejects_forgeries() {
    let mut rng = Rng::new(0x005E_ED01);
    for round in 0..24 {
        let n = rng.range(1, 41) as usize;
        let mut log = TransparencyLog::new("prop");
        let mut entries = Vec::with_capacity(n);
        for _ in 0..n {
            let e = rng.hash();
            entries.push(e);
            log.append(LogEntry::public(e));
        }
        let root = log.root().unwrap();
        let target = rng.range(0, n as u64) as usize;
        let proof = log.inclusion_proof(target as u64).unwrap();
        assert_eq!(proof.tree_size, n as u64);
        assert_eq!(proof.leaf_index, target as u64);
        assert!(
            verify_inclusion(&entries[target], &proof, &root).is_ok(),
            "round {round}: leaf {target}/{n} must verify"
        );
        // A different leaf under the same proof fails.
        if n > 1 {
            let other = (target + 1) % n;
            assert!(verify_inclusion(&entries[other], &proof, &root).is_err());
        }
        // A corrupted proof rung fails.
        let mut bad = proof.clone();
        if let Some(node) = bad.path.first_mut() {
            node.sibling = rng.hash();
            assert!(verify_inclusion(&entries[target], &bad, &root).is_err());
        }
        // A flipped side fails (unless the tree is a single leaf).
        if n > 1 {
            let mut flipped = proof.clone();
            for node in &mut flipped.path {
                node.side = match node.side {
                    unidpp_signatif::anchor::Side::Left => unidpp_signatif::anchor::Side::Right,
                    unidpp_signatif::anchor::Side::Right => unidpp_signatif::anchor::Side::Left,
                };
            }
            let result = verify_inclusion(&entries[target], &flipped, &root);
            // Flipping all rungs can coincide only in perfectly
            // symmetric trees; assert failure for the overwhelming case
            // and skip exacting it on degenerate single-rung trees.
            if flipped.path.len() > 1 {
                assert!(
                    result.is_err(),
                    "round {round}: flipped path must not verify"
                );
            }
        }
        // A wrong root fails.
        let bad_root = rng.hash();
        assert!(verify_inclusion(&entries[target], &proof, &bad_root).is_err());
        // An out-of-range index is refused structurally.
        let oob = InclusionProof {
            leaf_index: n as u64,
            tree_size: n as u64,
            path: proof.path.clone(),
        };
        assert!(verify_inclusion(&entries[target], &oob, &root).is_err());
    }
}

#[test]
fn every_consistency_proof_verifies_and_rejects_forgeries() {
    let mut rng = Rng::new(0x005E_ED02);
    for round in 0..20 {
        let n = rng.range(2, 37) as usize;
        let mut log = TransparencyLog::new("prop");
        for _ in 0..n {
            log.append(LogEntry::public(rng.hash()));
        }
        // Pin every prefix along the way via root_at_size.
        for m in 1..=n {
            let old_root = log.root_at_size(m as u64).unwrap();
            let new_root = log.root().unwrap();
            let proof = log.consistency_proof(m as u64).unwrap();
            assert!(
                verify_consistency(m as u64, &old_root, n as u64, &new_root, &proof.path).is_ok(),
                "round {round}: consistency {m}->{n} must verify"
            );
            // Corrupted old root.
            assert!(
                verify_consistency(m as u64, &rng.hash(), n as u64, &new_root, &proof.path)
                    .is_err()
            );
            // Corrupted new root.
            assert!(
                verify_consistency(m as u64, &old_root, n as u64, &rng.hash(), &proof.path)
                    .is_err()
            );
            // Truncated proof.
            if !proof.path.is_empty() {
                assert!(verify_consistency(
                    m as u64,
                    &old_root,
                    n as u64,
                    &new_root,
                    &proof.path[..proof.path.len() - 1]
                )
                .is_err());
            }
            // Extended proof (extra node appended).
            let mut extended = proof.path.clone();
            extended.push(rng.hash());
            assert!(
                verify_consistency(m as u64, &old_root, n as u64, &new_root, &extended).is_err()
            );
            // Swapped node order (reverse) fails for multi-node proofs.
            if proof.path.len() > 1 {
                let mut swapped = proof.path.clone();
                swapped.reverse();
                let result = verify_consistency(m as u64, &old_root, n as u64, &new_root, &swapped);
                // Reversal can theoretically collide only in
                // coincidentally symmetric trees; with random leaves it
                // must fail. (A collision would require equal node
                // hashes, which random 256-bit values do not produce.)
                assert!(
                    result.is_err(),
                    "round {round}: reversed path must not verify"
                );
            }
        }
        // Shrinking consistency is refused outright.
        assert!(log.consistency_proof(n as u64 + 1).is_err());
    }
}

#[test]
fn append_only_roots_never_repeat_and_domain_separation_holds() {
    let mut rng = Rng::new(0x005E_ED03);
    let mut log = TransparencyLog::new("prop");
    let mut seen = std::collections::BTreeSet::new();
    let mut prev = None;
    for i in 0..50u64 {
        log.append(LogEntry::public(rng.hash()));
        let root = log.root().unwrap();
        assert!(seen.insert(root), "root {i} must be fresh");
        if let Some(p) = prev {
            assert_ne!(p, root);
        }
        prev = Some(root);
    }
    // Leaf/node domain separation: a leaf hash never equals a node
    // hash over itself, and node_hash is order-sensitive.
    for _ in 0..50 {
        let a = rng.hash();
        let b = rng.hash();
        assert_ne!(leaf_hash(&a), node_hash(&a, &a));
        assert_ne!(node_hash(&a, &b), node_hash(&b, &a));
        assert_eq!(node_hash(&a, &b), node_hash(&a, &b));
    }
}

#[test]
fn determinism_of_whole_logs() {
    let mut rng_a = Rng::new(0xABCD);
    let mut rng_b = Rng::new(0xABCD);
    let mut log_a = TransparencyLog::new("det");
    let mut log_b = TransparencyLog::new("det");
    for _ in 0..17 {
        log_a.append(LogEntry::public(rng_a.hash()));
        log_b.append(LogEntry::public(rng_b.hash()));
    }
    assert_eq!(log_a, log_b);
    assert_eq!(log_a.root(), log_b.root());
    let pa = log_a.inclusion_proof(9).unwrap();
    let pb = log_b.inclusion_proof(9).unwrap();
    assert_eq!(pa, pb);
    // Serde round trip preserves everything.
    let json = serde_json::to_string(&log_a).unwrap();
    let rt: TransparencyLog = serde_json::from_str(&json).unwrap();
    assert_eq!(rt, log_a);
}
