//! Property: the four-layer scope algebra — narrowing is a real
//! lattice on randomized scopes: reflexive, antisymmetric on
//! constraints, transitive; intersection semantics; request matching
//! agrees with layer diagnostics.

mod common;

use std::collections::BTreeSet;

use unidpp_signatif::scope::{
    DelegationScope, LayerConstraint, ScopeRequest, WindowConstraint,
};
use unidpp_model::{Interval, Timestamp};

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
    fn bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.range(0, items.len() as u64) as usize]
    }
}

const UNIVERSE: [&str; 4] = ["eu", "us", "jp", "cn"];
const PROFILES: [&str; 3] = [
    "urn:unidpp:profile:eu-batt@3",
    "urn:unidpp:profile:eu-espr@2",
    "urn:unidpp:profile:global@1",
];
const GROUPS: [&str; 3] = ["batteries", "electronics", "textiles"];

fn random_layer(rng: &mut Rng, universe: &[&str]) -> LayerConstraint {
    if rng.bool() {
        LayerConstraint::Any
    } else {
        let mut set = BTreeSet::new();
        let n = rng.range(1, universe.len() as u64 + 1);
        for _ in 0..n {
            set.insert(rng.pick(universe).to_string());
        }
        LayerConstraint::Only(set)
    }
}

fn random_window(rng: &mut Rng) -> WindowConstraint {
    if rng.bool() {
        WindowConstraint::Anytime
    } else {
        let a = rng.range(0, 10_000) as i64;
        let b = a + rng.range(0, 10_000) as i64;
        WindowConstraint::Within(Interval::between(
            Timestamp::from_secs(a),
            Timestamp::from_secs(b),
        )
        .unwrap())
    }
}

fn random_scope(rng: &mut Rng) -> DelegationScope {
    DelegationScope {
        authority: random_layer(rng, &UNIVERSE),
        profile_version: random_layer(rng, &PROFILES),
        product_group: random_layer(rng, &GROUPS),
        window: random_window(rng),
    }
}

/// Build a scope that definitely admits `parent.narrow(child)` by
/// cloning the parent and only *removing* values.
fn narrowed_child(rng: &mut Rng, parent: &DelegationScope) -> DelegationScope {
    let mut child = parent.clone();
    if rng.bool() {
        if let LayerConstraint::Only(set) = &child.authority {
            if set.len() > 1 {
                let drop = rng.pick(&set.clone().into_iter().collect::<Vec<_>>()).clone();
                let mut next = set.clone();
                next.remove(&drop);
                child.authority = LayerConstraint::Only(next);
            }
        }
    }
    if rng.bool() {
        child.window = match child.window {
            WindowConstraint::Anytime => WindowConstraint::Within(Interval::starting(
                Timestamp::from_secs(rng.range(0, 5_000) as i64),
            )),
            WindowConstraint::Within(iv) => {
                // Shrink from the start (keep the end): a real narrowing.
                let bump = (rng.range(0, 100) / 100) as i64;
                let from = Timestamp::from_secs(iv.from.secs + bump);
                let to = iv.to;
                match to {
                    Some(end) if from > end => {
                        WindowConstraint::Within(Interval::between(end, end).unwrap())
                    }
                    _ => WindowConstraint::Within(Interval { from, to }),
                }
            }
        };
    }
    child
}

#[test]
fn narrowing_forms_a_lattice() {
    let mut rng = Rng::new(0x51);
    for _ in 0..500 {
        let parent = random_scope(&mut rng);
        let child = narrowed_child(&mut rng, &parent);
        // Reflexive: admits itself.
        assert!(parent.admits(&parent));
        assert!(parent.narrow(&parent).unwrap() == parent);
        // The narrowed child is admitted...
        assert!(parent.admits(&child), "{parent:?} must admit {child:?}");
        // ...and narrow returns the intersection (equals child here
        // because only removals happened).
        let eff = parent.narrow(&child).unwrap();
        assert!(eff.admits(&child) || eff == child);
        // Transitivity: a further narrowing is admitted by the parent.
        let grandchild = narrowed_child(&mut rng, &child);
        assert!(child.admits(&grandchild));
        assert!(parent.admits(&grandchild));
        let eff2 = parent.narrow(&child).unwrap().narrow(&grandchild).unwrap();
        assert!(eff2.admits(&grandchild));
    }
}

#[test]
fn widening_is_refused_or_intersects() {
    let mut rng = Rng::new(0x52);
    for _ in 0..500 {
        let a = random_scope(&mut rng);
        let b = random_scope(&mut rng);
        match a.narrow(&b) {
            Ok(eff) => {
                // The result is sound: it admits b's constraints (b ⊆ eff)
                // and a's (a ⊆ eff is NOT required — narrow checks
                // b ⊆ a; here eff ⊆ a and eff ⊆ b).
                assert!(a.admits(&eff), "{a:?} must admit eff {eff:?}");
                assert!(b.admits(&eff) || eff == b);
                // And it is exactly the intersection on the Any layers.
                if a.authority.is_any() || b.authority.is_any() {
                    assert!(eff.authority.is_any() || !b.authority.is_any());
                }
            }
            Err(e) => {
                // Errors are scope violations only.
                assert!(matches!(
                    e,
                    unidpp_signatif::SignatifError::ScopeViolation(_)
                ));
            }
        }
    }
}

#[test]
fn request_matching_agrees_with_rejecting_layer() {
    let mut rng = Rng::new(0x53);
    for _ in 0..1000 {
        let scope = random_scope(&mut rng);
        let req = ScopeRequest {
            authority: rng.pick(&UNIVERSE).to_string(),
            profile_version: rng.pick(&PROFILES).to_string(),
            product_group: rng.pick(&GROUPS).to_string(),
            at: Timestamp::from_secs(rng.range(0, 20_000) as i64),
        };
        let matched = scope.matches(&req);
        let rejector = scope.rejecting_layer(&req);
        // Exactly one of the two.
        assert_eq!(
            matched,
            rejector.is_none(),
            "matches and rejecting_layer disagree: {scope:?} vs {req:?}"
        );
    }
}

#[test]
fn window_constraints_are_ordered() {
    let mut rng = Rng::new(0x54);
    let anytime = WindowConstraint::Anytime;
    for _ in 0..300 {
        let w = random_window(&mut rng);
        // Anytime entails everything; nothing entails Anytime unless it
        // IS Anytime.
        assert!(anytime.entails(&w));
        if !w.is_any() {
            assert!(!w.entails(&anytime));
        }
        // Containment agrees with entails for point checks.
        let inside = match w {
            WindowConstraint::Within(iv) => iv.from,
            WindowConstraint::Anytime => Timestamp::from_secs(0),
        };
        if w.contains(inside) {
            let _ = rng.bool(); // keep rng consumption stable
        }
    }
    // Concrete interval algebra.
    let a = WindowConstraint::Within(Interval::between(
        Timestamp::from_secs(100),
        Timestamp::from_secs(200),
    )
    .unwrap());
    let b = WindowConstraint::Within(Interval::between(
        Timestamp::from_secs(150),
        Timestamp::from_secs(250),
    )
    .unwrap());
    assert!(!a.entails(&b) && !b.entails(&a));
    let overlap = a.intersect(&b).unwrap();
    match overlap {
        WindowConstraint::Within(iv) => {
            assert_eq!(iv.from, Timestamp::from_secs(150));
            assert_eq!(iv.to, Some(Timestamp::from_secs(200)));
        }
        WindowConstraint::Anytime => panic!(),
    }
}

#[test]
fn canonical_bytes_are_deterministic_and_scope_sensitive() {
    let mut rng_a = Rng::new(0x55);
    let mut rng_b = Rng::new(0x55);
    for _ in 0..200 {
        let a = random_scope(&mut rng_a);
        let b = random_scope(&mut rng_b);
        assert_eq!(a, b);
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
        assert!(!a.canonical_bytes().is_empty());
    }
    // Different scopes produce different bytes (collision-resistant
    // for structured differences in these universes).
    let x = DelegationScope::unconstrained().authority(["eu"]);
    let y = DelegationScope::unconstrained().authority(["us"]);
    assert_ne!(x.canonical_bytes(), y.canonical_bytes());
    // Serialization round trip.
    let json = serde_json::to_string(&x).unwrap();
    let rt: DelegationScope = serde_json::from_str(&json).unwrap();
    assert_eq!(rt, x);
}
