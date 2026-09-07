//! The four-layer delegation scope, its executable conditions, and the
//! narrowing algebra.
//!
//! Every delegation edge in the trust graph carries a
//! [`DelegationScope`] constraining *what the delegatee may do* along
//! four orthogonal layers (the UniDPP design framework, trust-registry section; the
//! SIGNATIF four-layer scope enforcement):
//!
//! 1. **authority** — which trust authority's acts are covered;
//! 2. **profile-version** — which (versioned) profile lenses may be
//!    attested under (`<profile-id>@<version>`);
//! 3. **product-group** — which taxonomy groups are covered (a
//!    delegatee scoped to `batteries` cannot attest textiles);
//! 4. **time window** — when the delegation is effective.
//!
//! On top of the layers, a scope may carry executable
//! [`ScopeCondition`]s (CC/SIGNATIF §3.6.4) — closed-form constraints
//! (time windows, referenced predicates, attribute allow-lists)
//! evaluated at **verification time** against the concrete
//! [`ScopeRequest`], never at delegation time.
//!
//! Along any root-to-key path the scope may only **narrow monotonically**
//! ([`DelegationScope::narrow`] refuses widening and empty
//! intersections); the path's effective scope is the intersection.
//! Conditions narrow by superset (the child may add conditions; the
//! effective set is the union). A concrete [`ScopeRequest`] (an act:
//! authority, profile version, product group, moment, plus predicate
//! outcomes and attributes) is admitted only if the effective scope
//! matches it on all four layers *and* every condition holds.

use std::collections::{BTreeMap, BTreeSet};

use unidpp_model::{CanonicalWriter, Interval, Timestamp};

use crate::SignatifError;

/// Canonical names of the four scope layers, in enforcement order.
pub const SCOPE_LAYERS: [&str; 4] = ["authority", "profile-version", "product-group", "window"];

/// One executable authorization-scope condition (CC/SIGNATIF §3.6.4,
/// §11 `scope-conditions`): a constraint on a delegation that is
/// *evaluated at verification time* against the concrete
/// [`ScopeRequest`], not baked into the layer constraints.
///
/// The condition language is deliberately tiny and
/// non-Turing-complete — three closed forms only:
///
/// - [`ScopeCondition::TimeWindow`] — the act must fall in
///   `[from, until]` (`until = None` = no upper bound);
/// - [`ScopeCondition::Predicate`] — an externally identified
///   predicate (a reference into a profile's rule base) that must have
///   evaluated `true` for the request; the verifier carries the
///   predicate *outcome* in [`ScopeRequest::predicates`], never the
///   expression itself, so the library never executes foreign code;
/// - [`ScopeCondition::Attribute`] — a named attribute of the act
///   (carried in [`ScopeRequest::attributes`]) must take one of the
///   allowed values.
///
/// Conditions narrow by **superset** (CC/SIGNATIF §11
/// `scope-monotonic-narrowing`): a child delegation may *add*
/// conditions but never drop one of its parent's — the effective
/// conditions along a path are the value-deduplicated union (see
/// [`DelegationScope::narrow`]).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ScopeCondition {
    /// The act must be dated inside `[from, until]`.
    TimeWindow {
        /// Window start (inclusive).
        from: Timestamp,
        /// Window end (inclusive; `None` = open-ended).
        until: Option<Timestamp>,
    },
    /// An externally identified predicate that must hold for the act.
    Predicate {
        /// Reference to the predicate (e.g. a profile rule id); the
        /// verifier supplies its evaluated outcome per request.
        expression_ref: String,
    },
    /// A named attribute of the act must take an allowed value.
    Attribute {
        /// Attribute name (e.g. "battery-chemistry").
        key: String,
        /// The values the condition admits (empty = contradiction).
        allowed_values: BTreeSet<String>,
    },
}

impl ScopeCondition {
    /// Stable condition label (for reports and error details).
    pub fn label(&self) -> &'static str {
        match self {
            ScopeCondition::TimeWindow { .. } => "time-window",
            ScopeCondition::Predicate { .. } => "predicate",
            ScopeCondition::Attribute { .. } => "attribute",
        }
    }

    /// Whether this condition is satisfied by the concrete request.
    ///
    /// Unresolvable inputs (a predicate with no recorded outcome, an
    /// attribute the request does not carry) fail closed: a condition
    /// the verifier cannot evaluate is a condition not met.
    pub fn is_met_by(&self, request: &ScopeRequest) -> bool {
        match self {
            ScopeCondition::TimeWindow { from, until } => {
                request.at >= *from && until.map_or(true, |u| request.at <= u)
            }
            ScopeCondition::Predicate { expression_ref } => {
                request.predicates.get(expression_ref) == Some(&true)
            }
            ScopeCondition::Attribute {
                key,
                allowed_values,
            } => request
                .attributes
                .get(key)
                .is_some_and(|value| allowed_values.contains(value)),
        }
    }

    /// Deterministic canonical bytes (length-prefixed fields; part of
    /// the delegation credential's signed scope bytes).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut w = CanonicalWriter::new();
        self.write(&mut w);
        w.into_bytes()
    }

    fn write(&self, w: &mut CanonicalWriter) {
        match self {
            ScopeCondition::TimeWindow { from, until } => {
                w.write_tag(0);
                w.write_i64(from.secs);
                w.write_u32(from.nanos);
                w.write_bool(until.is_some());
                if let Some(u) = until {
                    w.write_i64(u.secs);
                    w.write_u32(u.nanos);
                }
            }
            ScopeCondition::Predicate { expression_ref } => {
                w.write_tag(1);
                w.write_str(expression_ref);
            }
            ScopeCondition::Attribute {
                key,
                allowed_values,
            } => {
                w.write_tag(2);
                w.write_str(key);
                w.write_u32(allowed_values.len() as u32);
                for v in allowed_values {
                    w.write_str(v);
                }
            }
        }
    }
}

impl std::fmt::Display for ScopeCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScopeCondition::TimeWindow { from, until } => match until {
                Some(u) => write!(f, "time-window[{from}..={u}]"),
                None => write!(f, "time-window[{from}..]"),
            },
            ScopeCondition::Predicate { expression_ref } => {
                write!(f, "predicate`{expression_ref}`")
            }
            ScopeCondition::Attribute {
                key,
                allowed_values,
            } => write!(
                f,
                "attribute`{key}` ∈ {{{}}}",
                allowed_values
                    .iter()
                    .map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

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

/// The four-layer delegation scope plus its executable conditions
/// (CC/SIGNATIF §3.6.1 + §3.6.4).
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
    /// Executable conditions evaluated at verification time against the
    /// concrete [`ScopeRequest`] (CC/SIGNATIF §3.6.4). Empty = the
    /// layer constraints are the whole scope.
    pub conditions: Vec<ScopeCondition>,
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

    /// Builder: append an executable scope condition (conditions
    /// accumulate; see [`ScopeCondition`]).
    pub fn condition(mut self, condition: ScopeCondition) -> DelegationScope {
        self.conditions.push(condition);
        self
    }

    /// Whether any layer is a contradiction (an empty `Only` set) or any
    /// attribute condition admits nothing.
    pub fn is_contradiction(&self) -> bool {
        self.authority.is_contradiction()
            || self.profile_version.is_contradiction()
            || self.product_group.is_contradiction()
            || self
                .conditions
                .iter()
                .any(|c| matches!(c, ScopeCondition::Attribute { allowed_values, .. } if allowed_values.is_empty()))
    }

    /// Whether `child` is a monotonic narrowing of `self`: every layer of
    /// `child` is entailed by the corresponding layer of `self`, and the
    /// child carries at least the parent's conditions (superset
    /// narrowing — the child may add, never drop).
    pub fn admits(&self, child: &DelegationScope) -> bool {
        self.authority.entails(&child.authority)
            && self.profile_version.entails(&child.profile_version)
            && self.product_group.entails(&child.product_group)
            && self.window.entails(&child.window)
            && self.conditions.iter().all(|c| child.conditions.contains(c))
    }

    /// The effective scope of a delegation chain `self -> child`:
    /// per-layer intersection plus **condition union** (superset
    /// narrowing, CC/SIGNATIF §11: the child may add conditions; the
    /// effective set along a path accumulates them all). Errors if the
    /// child *widens* any layer or drops a parent condition (monotonic
    /// narrowing is enforced, never silently repaired) or if an
    /// intersection is empty.
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
            self.conditions.iter().find_map(|c| {
                if child.conditions.contains(c) {
                    None
                } else {
                    Some(format!(
                        "condition `{c}` granted by the parent was dropped by the child"
                    ))
                }
            }),
        ];
        if let Some(detail) = details.into_iter().flatten().next() {
            return Err(SignatifError::ScopeViolation(format!(
                "delegation must narrow monotonically: {detail}"
            )));
        }
        // Effective conditions: the parent's conditions, then the
        // child's additional ones, in order, deduplicated by value.
        let mut conditions = self.conditions.clone();
        for c in &child.conditions {
            if !conditions.contains(c) {
                conditions.push(c.clone());
            }
        }
        Ok(DelegationScope {
            authority: self.authority.intersect(&child.authority)?,
            profile_version: self.profile_version.intersect(&child.profile_version)?,
            product_group: self.product_group.intersect(&child.product_group)?,
            window: self.window.intersect(&child.window)?,
            conditions,
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

    /// The first condition of this scope the request does not satisfy
    /// (`None` when all conditions hold — vacuously when there are
    /// none). Evaluation is closed and deterministic; unresolvable
    /// inputs fail closed (see [`ScopeCondition::is_met_by`]).
    pub fn first_failed_condition(&self, request: &ScopeRequest) -> Option<&ScopeCondition> {
        self.conditions.iter().find(|c| !c.is_met_by(request))
    }

    /// Evaluate all conditions against the request; errors with the
    /// first failed condition (`Ok(())` when the scope carries none).
    pub fn check_conditions(&self, request: &ScopeRequest) -> Result<(), ScopeCondition> {
        match self.first_failed_condition(request) {
            Some(c) => Err(c.clone()),
            None => Ok(()),
        }
    }

    /// Deterministic canonical bytes of the scope (length-prefixed
    /// fields via the core's [`CanonicalWriter`]): the bytes a
    /// delegation credential's signature covers. Conditions are
    /// written after the four layers, in order, deduplicated by value
    /// (they already are, post-[`narrow`](DelegationScope::narrow)).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut w = CanonicalWriter::new();
        write_layer(&mut w, &self.authority);
        write_layer(&mut w, &self.profile_version);
        write_layer(&mut w, &self.product_group);
        write_window(&mut w, &self.window);
        w.write_u32(self.conditions.len() as u32);
        for condition in &self.conditions {
            condition.write(&mut w);
        }
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
/// a profile-version lens for a product group at a moment, plus the
/// inputs its executable conditions ([`ScopeCondition`]) evaluate
/// against — the predicate outcomes and named attributes of the act.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScopeRequest {
    /// Acting authority identifier.
    pub authority: String,
    /// `<profile-id>@<version>` of the lens being attested.
    pub profile_version: String,
    /// Product-taxonomy group of the subject.
    pub product_group: String,
    /// Moment of the act.
    pub at: Timestamp,
    /// Predicate outcomes keyed by `expression_ref` (CC/SIGNATIF §11:
    /// the verifier records what each referenced predicate evaluated
    /// to; absent = failed closed).
    #[serde(default)]
    pub predicates: BTreeMap<String, bool>,
    /// Named attributes of the act keyed by attribute name (inputs for
    /// [`ScopeCondition::Attribute`]).
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

impl ScopeRequest {
    /// Construct a request for the given act (no predicates, no
    /// attributes).
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
            predicates: BTreeMap::new(),
            attributes: BTreeMap::new(),
        }
    }

    /// Builder: record a predicate outcome (keyed by `expression_ref`).
    pub fn with_predicate(mut self, expression_ref: &str, outcome: bool) -> ScopeRequest {
        self.predicates.insert(expression_ref.to_string(), outcome);
        self
    }

    /// Builder: record a named attribute of the act.
    pub fn with_attribute(mut self, key: &str, value: &str) -> ScopeRequest {
        self.attributes.insert(key.to_string(), value.to_string());
        self
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

    #[test]
    fn conditions_narrow_by_superset_union() {
        let chem = ScopeCondition::Attribute {
            key: "battery-chemistry".into(),
            allowed_values: ["lfp", "nmc"].into_iter().map(Into::into).collect(),
        };
        let parent = DelegationScope::unconstrained()
            .authority(["eu"])
            .product_group(["batteries"])
            .condition(chem.clone());
        // Child adds a predicate condition: a valid narrowing; the
        // effective scope carries the union.
        let child = parent.clone().condition(ScopeCondition::Predicate {
            expression_ref: "urn:unidpp:rule:third-party-audit".into(),
        });
        assert!(parent.admits(&child));
        let effective = parent.narrow(&child).unwrap();
        assert_eq!(effective.conditions.len(), 2);
        assert_eq!(effective.conditions[0], chem);
        // Dropping the parent's condition is a widening: refused.
        let dropped = DelegationScope::unconstrained()
            .authority(["eu"])
            .product_group(["batteries"]);
        assert!(!parent.admits(&dropped));
        let err = parent.narrow(&dropped).unwrap_err();
        assert!(matches!(err, SignatifError::ScopeViolation(_)));
        assert!(err.to_string().contains("dropped"), "{err}");
        // Dedup: re-granting the same condition does not duplicate.
        let again = parent.clone().condition(chem.clone());
        assert_eq!(parent.narrow(&again).unwrap().conditions.len(), 1);
    }

    #[test]
    fn condition_evaluation_across_the_three_forms() {
        let scope = DelegationScope::unconstrained()
            .authority(["eu"])
            .condition(ScopeCondition::TimeWindow {
                from: t(100),
                until: Some(t(200)),
            })
            .condition(ScopeCondition::Predicate {
                expression_ref: "rule:audit".into(),
            })
            .condition(ScopeCondition::Attribute {
                key: "chemistry".into(),
                allowed_values: ["lfp"].into_iter().map(Into::into).collect(),
            });
        let ok = ScopeRequest::new("eu", "p@1", "batteries", t(150))
            .with_predicate("rule:audit", true)
            .with_attribute("chemistry", "lfp");
        assert_eq!(scope.first_failed_condition(&ok), None);
        assert!(scope.check_conditions(&ok).is_ok());
        // Time-window violation.
        let late = ScopeRequest::new("eu", "p@1", "batteries", t(300));
        assert!(matches!(
            scope.first_failed_condition(&late),
            Some(ScopeCondition::TimeWindow { .. })
        ));
        // Predicate false, absent, and false-recorded all fail closed.
        for req in [
            ScopeRequest::new("eu", "p@1", "batteries", t(150)),
            ScopeRequest::new("eu", "p@1", "batteries", t(150)).with_predicate("rule:audit", false),
        ] {
            assert!(matches!(
                scope.first_failed_condition(&req),
                Some(ScopeCondition::Predicate { .. })
            ));
        }
        // Attribute not carried / wrong value fails.
        let wrong = ScopeRequest::new("eu", "p@1", "batteries", t(150))
            .with_predicate("rule:audit", true)
            .with_attribute("chemistry", "nmc");
        assert!(matches!(
            scope.first_failed_condition(&wrong),
            Some(ScopeCondition::Attribute { .. })
        ));
        // Conditions are covered by the scope's canonical bytes.
        let bare = DelegationScope::unconstrained().authority(["eu"]);
        assert_ne!(
            bare.canonical_bytes(),
            bare.clone().condition(chem_condition()).canonical_bytes()
        );
        // An empty allowed_values set is a contradiction.
        assert!(DelegationScope::unconstrained()
            .condition(ScopeCondition::Attribute {
                key: "k".into(),
                allowed_values: BTreeSet::new(),
            })
            .is_contradiction());
    }

    fn chem_condition() -> ScopeCondition {
        ScopeCondition::Attribute {
            key: "chemistry".into(),
            allowed_values: ["lfp"].into_iter().map(Into::into).collect(),
        }
    }

    #[test]
    fn condition_labels_and_display() {
        let tw = ScopeCondition::TimeWindow {
            from: t(1),
            until: None,
        };
        assert_eq!(tw.label(), "time-window");
        assert!(tw.to_string().contains("time-window"));
        assert_eq!(
            ScopeCondition::Predicate {
                expression_ref: "r".into()
            }
            .label(),
            "predicate"
        );
        assert_eq!(
            ScopeCondition::Attribute {
                key: "k".into(),
                allowed_values: ["v"].into_iter().map(Into::into).collect(),
            }
            .label(),
            "attribute"
        );
        // Canonical bytes are deterministic.
        let c = ScopeCondition::Predicate {
            expression_ref: "r".into(),
        };
        assert_eq!(c.canonical_bytes(), c.canonical_bytes());
    }
}
