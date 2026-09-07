//! The four-layer delegation scope and its narrowing algebra.
//!
//! Every delegation edge in the trust graph carries a
//! [`DelegationScope`] constraining *what the delegatee may do* along
//! four orthogonal layers (PLAN.md, trust-registry section; the
//! SIGNATIF four-layer scope enforcement):
//!
//! 1. **authority** — which trust authority's acts are covered;
//! 2. **profile-version** — which (versioned) profile lenses may be
//!    attested under (`<profile-id>@<version>`);
//! 3. **product-group** — which taxonomy groups are covered (a
//!    delegatee scoped to `batteries` cannot attest textiles);
//! 4. **time window** — when the delegation is effective.
//!
//! Along any root-to-key path the scope may only **narrow monotonically**
//! ([`DelegationScope::narrow`] refuses widening and empty
//! intersections); the path's effective scope is the intersection. A
//! concrete [`ScopeRequest`] (an act: authority, profile version,
//! product group, moment) is admitted only if the effective scope
//! matches it on all four layers.

use std::collections::BTreeSet;

use unidpp_model::{CanonicalWriter, Interval, Timestamp};

use crate::SignatifError;

/// Canonical names of the four scope layers, in enforcement order.
pub const SCOPE_LAYERS: [&str; 4] = ["authority", "profile-version", "product-group", "window"];

/// Constraint on one symbolic layer: `Any` (unconstrained) or
/// `Only(values)` (admitted values).
///
/// `Only` with an empty set is a contradiction: it admits nothing. It
/// can only arise from an empty intersection, which
/// [`LayerConstraint::intersect`] reports as an error instead of
/// producing.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LayerConstraint {
    /// Unconstrained (the `Any` wildcard).
    #[default]
    Any,
    /// Constrained to exactly this set of values (empty = contradiction).
    Only(BTreeSet<String>),
}

impl LayerConstraint {
    /// Build an `Only` constraint from an iterator of values.
    pub fn only<I, S>(values: I) -> LayerConstraint
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        LayerConstraint::Only(values.into_iter().map(Into::into).collect())
    }

    /// Whether this admits the given value.
    pub fn contains(&self, value: &str) -> bool {
        match self {
            LayerConstraint::Any => true,
            LayerConstraint::Only(set) => set.contains(value),
        }
    }

    /// Whether this is the `Any` wildcard.
    pub fn is_any(&self) -> bool {
        matches!(self, LayerConstraint::Any)
    }

    /// Whether this is a contradiction (admits nothing).
    pub fn is_contradiction(&self) -> bool {
        matches!(self, LayerConstraint::Only(set) if set.is_empty())
    }

    /// Whether `subset` is entailed by `self` (`subset ⊆ self`).
    pub fn entails(&self, subset: &LayerConstraint) -> bool {
        match (self, subset) {
            (LayerConstraint::Any, _) => true,
            (LayerConstraint::Only(_), LayerConstraint::Any) => false,
            (LayerConstraint::Only(outer), LayerConstraint::Only(inner)) => inner.is_subset(outer),
        }
    }

    /// Set intersection; errors if the result would be empty.
    pub fn intersect(&self, other: &LayerConstraint) -> Result<LayerConstraint, SignatifError> {
        match (self, other) {
            (LayerConstraint::Any, x) | (x, LayerConstraint::Any) => Ok(x.clone()),
            (LayerConstraint::Only(a), LayerConstraint::Only(b)) => {
                let out: BTreeSet<String> = a.intersection(b).cloned().collect();
                if out.is_empty() {
                    return Err(SignatifError::ScopeViolation(
                        "layer intersection is empty (disjoint constraints)".into(),
                    ));
                }
                Ok(LayerConstraint::Only(out))
            }
        }
    }

    fn mismatch_detail(&self, other: &LayerConstraint, layer: &str) -> Option<String> {
        if self.entails(other) {
            None
        } else {
            Some(format!(
                "layer `{layer}` widens or diverges: {self:?} does not entail {other:?}"
            ))
        }
    }
}

/// Time-window constraint: `Anytime` (unbounded) or `Within(interval)`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WindowConstraint {
    /// Unbounded in time.
    #[default]
    Anytime,
    /// Bounded to a closed interval (empty end = ongoing).
    Within(Interval),
}

impl WindowConstraint {
    /// Whether the moment `t` falls inside the constraint.
    pub fn contains(&self, t: Timestamp) -> bool {
        match self {
            WindowConstraint::Anytime => true,
            WindowConstraint::Within(iv) => iv.contains(t),
        }
    }

    /// Whether this is the unbounded wildcard.
    pub fn is_any(&self) -> bool {
        matches!(self, WindowConstraint::Anytime)
    }

    /// Whether `subset` is entailed by `self` (subset interval ⊆ self).
    pub fn entails(&self, subset: &WindowConstraint) -> bool {
        match (self, subset) {
            (WindowConstraint::Anytime, _) => true,
            (WindowConstraint::Within(_), WindowConstraint::Anytime) => false,
            (WindowConstraint::Within(outer), WindowConstraint::Within(inner)) => {
                inner.from >= outer.from
                    && match (outer.to, inner.to) {
                        (None, _) => true,
                        (Some(_), None) => false,
                        (Some(o), Some(i)) => i <= o,
                    }
            }
        }
    }

    /// Interval intersection; errors if disjoint.
    pub fn intersect(&self, other: &WindowConstraint) -> Result<WindowConstraint, SignatifError> {
        match (self, other) {
            (WindowConstraint::Anytime, x) | (x, WindowConstraint::Anytime) => Ok(*x),
            (WindowConstraint::Within(a), WindowConstraint::Within(b)) => {
                let from = a.from.max(b.from);
                let to = match (a.to, b.to) {
                    (None, t) | (t, None) => t,
                    (Some(x), Some(y)) => Some(x.min(y)),
                };
                if let Some(to) = to {
                    if to < from {
                        return Err(SignatifError::ScopeViolation(format!(
                            "window intersection is empty ([{a}] ∩ [{b}])"
                        )));
                    }
                }
                Ok(WindowConstraint::Within(Interval { from, to }))
            }
        }
    }
}

/// The four-layer delegation scope.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DelegationScope {
    /// Layer 1: admitting trust authorities (empty-wildcard semantics via
    /// [`LayerConstraint::Any`]).
    pub authority: LayerConstraint,
    /// Layer 2: admitting `<profile-id>@<version>` tokens.
    pub profile_version: LayerConstraint,
    /// Layer 3: admitting product-taxonomy groups.
    pub product_group: LayerConstraint,
    /// Layer 4: admitting time window.
    pub window: WindowConstraint,
}

impl DelegationScope {
    /// The fully unconstrained scope (all four layers wildcards).
    pub fn unconstrained() -> DelegationScope {
        DelegationScope::default()
    }

    /// Builder: constrain the authority layer.
    pub fn authority<I, S>(mut self, values: I) -> DelegationScope
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.authority = LayerConstraint::only(values);
        self
    }

    /// Builder: constrain the profile-version layer.
    pub fn profile_version<I, S>(mut self, values: I) -> DelegationScope
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.profile_version = LayerConstraint::only(values);
        self
    }

    /// Builder: constrain the product-group layer.
    pub fn product_group<I, S>(mut self, values: I) -> DelegationScope
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.product_group = LayerConstraint::only(values);
        self
    }

    /// Builder: constrain the time-window layer.
    pub fn within(mut self, window: Interval) -> DelegationScope {
        self.window = WindowConstraint::Within(window);
        self
    }

    /// Whether any layer is a contradiction (an empty `Only` set).
    pub fn is_contradiction(&self) -> bool {
        self.authority.is_contradiction()
            || self.profile_version.is_contradiction()
            || self.product_group.is_contradiction()
    }

    /// Whether `child` is a monotonic narrowing of `self`: every layer of
    /// `child` is entailed by the corresponding layer of `self`.
    pub fn admits(&self, child: &DelegationScope) -> bool {
        self.authority.entails(&child.authority)
            && self.profile_version.entails(&child.profile_version)
            && self.product_group.entails(&child.product_group)
            && self.window.entails(&child.window)
    }

    /// The effective scope of a delegation chain `self -> child`:
    /// per-layer intersection. Errors if the child *widens* any layer
    /// (monotonic narrowing is enforced, never silently repaired) or if
    /// an intersection is empty.
    pub fn narrow(&self, child: &DelegationScope) -> Result<DelegationScope, SignatifError> {
        let details = [
            self.authority
                .mismatch_detail(&child.authority, SCOPE_LAYERS[0]),
            self.profile_version
                .mismatch_detail(&child.profile_version, SCOPE_LAYERS[1]),
            self.product_group
                .mismatch_detail(&child.product_group, SCOPE_LAYERS[2]),
            match (self.window.entails(&child.window), ()) {
                (true, ()) => None,
                (false, ()) => Some(format!(
                    "layer `window` widens or diverges: {:?} does not entail {:?}",
                    self.window, child.window
                )),
            },
        ];
        if let Some(detail) = details.into_iter().flatten().next() {
            return Err(SignatifError::ScopeViolation(format!(
                "delegation must narrow monotonically: {detail}"
            )));
        }
        Ok(DelegationScope {
            authority: self.authority.intersect(&child.authority)?,
            profile_version: self.profile_version.intersect(&child.profile_version)?,
            product_group: self.product_group.intersect(&child.product_group)?,
            window: self.window.intersect(&child.window)?,
        })
    }

    /// Whether this scope admits a concrete act ([`ScopeRequest`]) on
    /// all four layers.
    pub fn matches(&self, request: &ScopeRequest) -> bool {
        self.authority.contains(&request.authority)
            && self.profile_version.contains(&request.profile_version)
            && self.product_group.contains(&request.product_group)
            && self.window.contains(request.at)
    }

    /// Deterministic canonical bytes of the scope (length-prefixed
    /// fields via the core's [`CanonicalWriter`]): the bytes a
    /// delegation credential's signature covers.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut w = CanonicalWriter::new();
        write_layer(&mut w, &self.authority);
        write_layer(&mut w, &self.profile_version);
        write_layer(&mut w, &self.product_group);
        write_window(&mut w, &self.window);
        w.into_bytes()
    }

    /// Name of the first layer on which this scope rejects the request
    /// (for diagnostics; `None` when the scope matches).
    pub fn rejecting_layer(&self, request: &ScopeRequest) -> Option<&'static str> {
        if !self.authority.contains(&request.authority) {
            Some(SCOPE_LAYERS[0])
        } else if !self.profile_version.contains(&request.profile_version) {
            Some(SCOPE_LAYERS[1])
        } else if !self.product_group.contains(&request.product_group) {
            Some(SCOPE_LAYERS[2])
        } else if !self.window.contains(request.at) {
            Some(SCOPE_LAYERS[3])
        } else {
            None
        }
    }
}

fn write_layer(w: &mut CanonicalWriter, layer: &LayerConstraint) {
    match layer {
        LayerConstraint::Any => {
            w.write_tag(0);
        }
        LayerConstraint::Only(set) => {
            w.write_tag(1);
            w.write_u32(set.len() as u32);
            for v in set {
                w.write_str(v);
            }
        }
    }
}

fn write_window(w: &mut CanonicalWriter, window: &WindowConstraint) {
    match window {
        WindowConstraint::Anytime => w.write_tag(0),
        WindowConstraint::Within(iv) => {
            w.write_tag(1);
            w.write_i64(iv.from.secs);
            w.write_u32(iv.from.nanos);
            w.write_bool(iv.to.is_some());
            if let Some(to) = iv.to {
                w.write_i64(to.secs);
                w.write_u32(to.nanos);
            }
        }
    }
}

/// A concrete act to be checked against a scope: an authority attesting
/// a profile-version lens for a product group at a moment.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScopeRequest {
    /// Acting authority identifier.
    pub authority: String,
    /// `<profile-id>@<version>` of the lens being attested.
    pub profile_version: String,
    /// Product-taxonomy group of the subject.
    pub product_group: String,
    /// Moment of the act.
    pub at: Timestamp,
}

impl ScopeRequest {
    /// Construct a request for the given act.
    pub fn new(
        authority: &str,
        profile_version: &str,
        product_group: &str,
        at: Timestamp,
    ) -> ScopeRequest {
        ScopeRequest {
            authority: authority.to_string(),
            profile_version: profile_version.to_string(),
            product_group: product_group.to_string(),
            at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs: i64) -> Timestamp {
        Timestamp::from_secs(secs)
    }

    #[test]
    fn narrowing_algebra() {
        let wide = DelegationScope::unconstrained()
            .authority(["eu"])
            .product_group(["batteries", "electronics"]);
        let narrow = wide
            .clone()
            .product_group(["batteries"])
            .within(Interval::between(t(100), t(200)).unwrap());
        assert!(wide.admits(&narrow));
        let eff = wide.narrow(&narrow).unwrap();
        assert_eq!(eff, narrow);
        // Widening the product group is refused.
        let widened = DelegationScope::unconstrained().product_group(["textiles"]);
        assert!(matches!(
            wide.narrow(&widened),
            Err(SignatifError::ScopeViolation(_))
        ));
        // Disjoint product groups make an empty intersection.
        let disjoint = wide
            .clone()
            .product_group(["batteries"])
            .narrow(&DelegationScope::unconstrained().product_group(["textiles"]))
            .unwrap_err();
        assert!(matches!(disjoint, SignatifError::ScopeViolation(_)));
    }

    #[test]
    fn window_intersect_and_entail() {
        let a = WindowConstraint::Within(Interval::between(t(0), t(100)).unwrap());
        let b = WindowConstraint::Within(Interval::between(t(50), t(150)).unwrap());
        assert!(a.entails(&WindowConstraint::Within(
            Interval::between(t(10), t(90)).unwrap()
        )));
        assert!(!a.entails(&b));
        let c = a.intersect(&b).unwrap();
        match c {
            WindowConstraint::Within(iv) => {
                assert_eq!(iv.from, t(50));
                assert_eq!(iv.to, Some(t(100)));
            }
            WindowConstraint::Anytime => panic!("bounded ∩ bounded must be bounded"),
        }
        let disjoint = WindowConstraint::Within(Interval::between(t(200), t(300)).unwrap());
        assert!(matches!(
            a.intersect(&disjoint),
            Err(SignatifError::ScopeViolation(_))
        ));
    }

    #[test]
    fn request_matching_names_rejecting_layer() {
        let scope = DelegationScope::unconstrained()
            .authority(["eu"])
            .profile_version(["urn:unidpp:profile:eu-batt@3"])
            .product_group(["batteries"])
            .within(Interval::between(t(0), t(1000)).unwrap());
        let ok = ScopeRequest::new("eu", "urn:unidpp:profile:eu-batt@3", "batteries", t(500));
        assert!(scope.matches(&ok));
        assert_eq!(scope.rejecting_layer(&ok), None);
        let wrong_group =
            ScopeRequest::new("eu", "urn:unidpp:profile:eu-batt@3", "textiles", t(500));
        assert!(!scope.matches(&wrong_group));
        assert_eq!(scope.rejecting_layer(&wrong_group), Some("product-group"));
        let too_late =
            ScopeRequest::new("eu", "urn:unidpp:profile:eu-batt@3", "batteries", t(5000));
        assert_eq!(scope.rejecting_layer(&too_late), Some("window"));
    }
}
