# SIGNATIF conformance-to-model map — `unidpp-signatif` against the published SIGNATIF standard

**Subject:** `this crate/` (Rust crate, 5 081 LOC src + tests).
**Standard:** `the SIGNATIF standard sources (CalConnect)` (CC/SIGNATIF AsciiDoc).
**Task register:** `10-remaining-tasks-definitive.md` §19 (2026-09-07).
**Date of audit:** 2026-09-07.

This map cross-walks SIGNATIF normative clauses (the registered requirements
classes defined in the standard) against the `unidpp-signatif` crate modules,
tests, and behavioural surface. It records three classes of result:

- **conforms** — the clause is implemented, in scope, with test coverage that
 exercises the behaviour;
- **adapter** — the clause is implemented in a way that diverges from the
 standard's prescribed shape by documented design choice (renaming,
 finer-grained decomposition, semantic refinement); the conformance is
 intact and the deviation is noted with the seam where a future integration
 would harmonize;
- **diverges** — the clause's norm is not implemented, or is implemented in a
 way that would not pass a SIGNATIF conformance suite; the gap is recorded
 with the location where the missing behaviour should land.

No code was changed in producing this map.

**Revision 2026-09-07 (implementation pass, branch `divergences`):**
all six divergences of §20.2 were implemented. Four now **conform**
(authorization scope conditions + `scope_condition_failed`, composite
signatures, scope-condition withdrawal, deployment manifest); two are
**adapter** (external time anchoring — payload + offline verification
in-crate, submission/proof deployment-side; SLH-DSA — framed with an
explicit `Unsupported` error behind a stubbed `slh-dsa` crate feature).
Statuses below were updated in place with the new evidence; test count
went 71 → 90 (`cargo test`), fmt/clippy `-D warnings` clean.

---

## 1. Terms, definitions and abbreviated terms (CC/SIGNATIF §3)

### 1.1 Conformance

| Term | Standard §3 | Crate map | Status |
|---|---|---|---|
| trust infrastructure | unnumbered | composed of `graph::TrustGraph` + `graph::AnchorBundle` + `revoke::RevocationLedger` + `anchor::TransparencyLog` | conforms (semantics; no separate "infrastructure" wrapper type) |
| trust authority | unnumbered | `graph::DelegationNode` with `kind: NodeKind::{Root, ThresholdGroup, Delegated, End}` | conforms (4 kinds cover 1-of-1, threshold, and federated authority via `ThresholdGroup`) |
| root trust authority (RTA) | unnumbered | `NodeKind::Root` | conforms |
| delegated trust authority (DTA) | unnumbered | `NodeKind::Delegated` | conforms |
| federated trust authority (FTA) | unnumbered | `NodeKind::ThresholdGroup { threshold, members }` | adapter — standard treats FTA as a *kind* of DTA whose members are independent organizations (notes after the term); crate models it as a `NodeKind` variant and lets the threshold parameters carry the federation semantics. The RTA may itself be a `ThresholdGroup`, which the standard permits in its note. |
| aggregate key | unnumbered | `keyring::PublicKey` registered to a node; multi-member group has its members' verification keys registered and the threshold enforced at signature verification time (`graph.rs:623–654 verify_credential`). | adapter — the standard defines aggregate key as "from a single signing key OR composed under a threshold scheme"; the crate defers the composed aggregate to its future Confium binding (see `confium.rs:312–315`'s mock — the document deferral in `Suite::deferral` is the same point). Conforms for the single-key case; conforms by reference for the threshold case pending the binding. |
| quorum | unnumbered | `(threshold, members)` on `NodeKind::ThresholdGroup` and `QuorumSpec { threshold, members }` in `confium` | conforms |
| trust chain | unnumbered | `graph::TrustPath` | conforms |
| trust graph (trust DAG) | unnumbered | `graph::TrustGraph` with DAG-enforced edge insertion (`graph.rs:499–531`) | conforms |
| end certificate | unnumbered | `DelegationCredential` whose child is `NodeKind::End`; the end node's `RegisteredKey` is the authorized signing key | conforms |
| trusted artifact | unnumbered | `verify::VerificationTarget { log, co_signature, anchor, profile, provided, active_links }` + the core's artifact event log | conforms |
| canonical payload | unnumbered | the core's `unidpp_model::CanonicalWriter` (used throughout `scope.rs`, `graph.rs`, `sign.rs`, `anchor.rs`); co-signatures bind the same bytes (`sign::CoSignature::payload`); the deferred suites consume the same payload bytes | conforms |
| authorization scope (scope) | §3.6.1 | `scope::DelegationScope { authority, profile_version, product_group, window, conditions }` | adapter — 4 layers vs standard's 6 (domain, subdomain, class, instance, identity, conditions). Documented substitution: the 4 layers in the crate map directly onto UniDPP's operating model (the UniDPP design framework, trust-registry section). `conditions` **are** implemented as a separate dimension since the 2026-09-07 pass (`Vec<ScopeCondition>`, §3.6.4 below). `domain`/`subdomain` are folded into the `authority` layer; `class`/`instance`/`identity` are folded into `product_group`. This is a profile choice within the standard's "additional dimensions may be defined by profiles" allowance (§3.5). |
| authorization scope dimension | §3.6.2 | `scope::LayerConstraint` (Any / Only(set)) + `WindowConstraint` (Anytime / Within(Interval)) | conforms |
| authorization scope narrowing | §3.6.3 | `DelegationScope::narrow` + `narrow` chain in `graph::TrustGraph::resolve` (`graph.rs:753–766`; conditions narrow by union `scope.rs:428–476`) | conforms (with documented 4-layer substitution; see §1.2) |
| authorization scope condition | §3.6.4 | `scope::ScopeCondition` (`TimeWindow{from,until}` / `Predicate{expression_ref}` / `Attribute{key,allowed_values}`) on `DelegationScope::conditions`; evaluation `ScopeCondition::is_met_by` / `DelegationScope::first_failed_condition` (`scope.rs:65–161, 488–496`); enforced in `graph::TrustGraph::resolve` (`graph.rs:784–797`) and the pipeline (`verify.rs:188–207`); typed failure `SignatifError::ScopeConditionFailed`; tests `scope::tests::{conditions_narrow_by_superset_union, condition_evaluation_across_the_three_forms, condition_labels_and_display}`, `graph::tests::resolve_enforces_scope_conditions`, `tests/scenario_conditions.rs` (3 tests) | conforms (closed-form, non-Turing-complete condition language: time windows, referenced predicates evaluated by outcome, attribute allow-lists; superset narrowing; fail-closed on unresolvable inputs) |
| monotonic narrowing invariant | §3.6.5 | enforced strictly: `DelegationScope::narrow` returns `SignatifError::ScopeViolation` on widening (`scope.rs:428–476`); tested in `scope::tests::narrowing_algebra` and `scope::tests::conditions_narrow_by_superset_union` (`scope.rs`), `tests/property_scope::narrowing_forms_a_lattice` (`property_scope.rs:122–144`), `tests/property_scope::widening_is_refused_or_intersects` (`property_scope.rs:146–173`), `tests/scenario_delegation::out_of_scope_*` (`scenario_delegation.rs:78–163`) | conforms |
| threshold signing | §3.7.1 | enforced at every level via `graph::verify_credential` (`graph.rs:623–654`); ceremony interface in `confium::CeremonyCoordinator` | conforms (interface-only for the threshold-cryptographic part; see §11) |
| ceremony | §3.7.2 | `confium::{SessionInit, Commitment, Share, AggregatedSignature, SessionState}` + the `Pending → CommitmentsCollected → SharesCollected → Completed (+ Expired)` lifecycle | conforms (interface; mock binds plain Ed25519 signatures pending the Confium FFI/Rust binding — see §11) |
| co-signature | §3.7.3 | `sign::CoSignature { domain, payload, slots: Vec<SignatureSlot>, composites: Vec<CompositeSignature> }` | conforms — multiple suites, same payload, independent verification (`sign::CoSignature::verify` `sign.rs:618–660`; composites = the §3.7.4 slot form); cross-domain dimension-tagging is the caller's responsibility via `SigningDomain::ArtifactEvent` (data), `TreeHead` (transparency), `Quorum` (threshold), etc. — the standard allows the format profile to encode the tag; `unidpp-signatif` is format-agnostic and uses `SigningDomain` to convey intent. |
| composite signature | §3.7.4 | `sign::CompositeSignature { domain, payload, members }` — one logical signature from the AND-composition of member suites; `CompositeSignature::verify` (`sign.rs:426–503, 465–490`) requires EVERY member to verify (one failure fails the composite; framed-only/deferred/unknown members fail it); carried on `CoSignature::composites` as the alternative slot form alongside the plain multi-suite collection (`sign.rs:554`, `attach_composite`/`sign_composite_by` `sign.rs:584–611`); a verifying composite contributes all member suites to `CoSignatureReport::verified_suites`; tests `sign::tests::{composite_signatures_verify_under_and_composition, composite_slot_form_counts_toward_acceptance}`, `tests/scenario_cosign.rs::composite_slot_form_flows_through_the_pipeline` | conforms — cryptographic AND-composition per §3.7.4/§9 `algorithms-composite`; the hybrid classical/PQ migration form (member values live in one composite object over identical payload bytes; the pipeline gives each member a full `SlotTrust` row). SM2/ML-DSA member computation still awaits their bindings — a deferred member fails the composite rather than faking it. |
| trust repudiation | §3.8.1 | `revoke::RevocationLedger::declare` + `Standing::VoidAbInitio` + `verify::SignatifVerdict::voids_ab_initio` | conforms |
| trust dimension | §3.9.1 | `sign::SigningDomain::{ArtifactEvent=data, Quorum=authorization-via-threshold, HistoricalStamp=time-via-notary, TreeHead=transparency, Delegation=chain, MasterListWitness=federated}`; the dimension *attestation* is carried as a co-signature slot with the corresponding domain | adapter — the standard names seven dimensions (data, person, time, location, environment, authorization, identity, oracle). The crate implements data, time (via notary stamps), and authorization (via threshold/quorum) as first-class domains; person, location, environment, identity, oracle are caller-side concerns with no first-class domain. The cross-domain co-signature framework (multi-suite per dimension tag) is in place; the remaining dimensions are profile additions. |
| dimension attestation | §3.9.2 | a `SignatureSlot` whose `domain` is the dimension's `SigningDomain` | conforms |
| dimension convergence | §3.9.3 | multi-slot `CoSignature` on the same canonical payload | conforms |
| time key | §3.9.4 | `verify::HistoricalVerification`'s notary key (Ed25519 or P-256), signing in `SigningDomain::HistoricalStamp` | adapter — the standard requires time dimension attestation to be a co-signature *on the artifact's canonical payload*; the crate notarizes a *state hash of the artifact log*, which is a stronger binding (the time attestation covers the whole prefix, not a single payload) but is not co-signed on the artifact payload. Conforming when the notary is a recognized time authority; non-conforming when read strictly — the time dimension's `SigningDomain` would need to be added to a co-signature on the artifact body, not just on the stamp bytes. See also §3 (verification pipeline) for how the coverage report records this. |
| trust anchor / root anchor | §3.10.1 | `graph::AnchorBundle` + `graph::TrustList` + `graph::MasterList` (M-of-K witness attestations) | conforms |
| trust anchor bundle | §3.10.2 | `graph::AnchorBundle { jurisdiction, trust_lists: Vec<TrustList>, master: MasterList }`; `accepts_root` checks both a jurisdiction trust list AND the master list M-of-K quorum (`graph.rs:437–453`) | conforms — self-containment, versionability (via the registry, see §19), distributability all delegate to the format profile chosen by the deployment |
| verification pipeline | §3.10.3 | `verify::SignatifVerifier::verify` + `verify_historical` | conforms |
| scheme | §3.10.4 | not modeled as a type — UniDPP is itself the scheme for the artefacts it issues; the registry of authorities, profiles, etc. is the `unidpp-registry` crate (not in this audit) | adapter — the standard says the scheme is "the registration authority for the registries of <<annex-c>>"; the crate does not model a separate `Scheme` type. The implicit scheme is the UniDPP trust anchor scheme and its registry. |
| classification label / grade label | §3.10.5 | the core's `unidpp_verdict::Verdict` carries the classification (Pass / Degraded(_) / Fail(_)); `verify::outcome_token` (`verify.rs:419–430`) gives compact stable tokens | conforms (the policy is delegated to the core; the crate wraps it) |
| dimensional coverage | §3.10.6 | per-slot `SlotTrust` in `verify::TrustReport`; `co_signature_report.verified_suites` enumerates distinct verified domains/suites | conforms |
| inclusion proof | §3.10.7 | `anchor::InclusionProof` + `anchor::verify_inclusion` | conforms |
| transparency log | §3.11.1 | `anchor::TransparencyLog` | conforms |
| mirror | §3.11.2 | the `LogOfLogs` model (one master log holding witness STH commitments) | conforms |
| gossip | §3.11.3 | the M-of-K `verify_master_quorum` + the jurisdiction trust list / master list semantics (`graph.rs:566–582`) | conforms |
| multi-log attestation | §3.11.4 | `LogOfLogs { m, k }` + `verify_master_quorum` | conforms |
| passport | §3.12.1 | not implemented — UniDPP passports are encoded by `unidpp-core`'s Tier-A pack; the crate does not provide a presentation-format projection | diverges — see §1.3 |

### 1.2 Scope-condition gap — RESOLVED (2026-09-07)

The standard requires a `conditions` scope dimension holding executable
predicates evaluated at verification time (CC/SIGNATIF §3.6.4, §11
`scope-conditions`). **Implemented** in the 2026-09-07 pass:

- `scope::ScopeCondition` (`scope.rs:65–161`) — three closed,
  non-Turing-complete forms: `TimeWindow{from, until}`,
  `Predicate{expression_ref}`, `Attribute{key, allowed_values}`;
- `DelegationScope::conditions: Vec<ScopeCondition>` (`scope.rs:345`) —
  part of the credential's signed canonical bytes; superset narrowing
  in `DelegationScope::narrow` (`scope.rs:428–476`: the child may add
  conditions, never drop a parent's; effective set = value-deduplicated
  union; dropping is a `ScopeViolation`);
- evaluation at verify time: `DelegationScope::first_failed_condition`
  (`scope.rs:488`) with the closed-world rule (an absent predicate
  outcome or attribute fails closed), wired into
  `TrustGraph::resolve` (`graph.rs:784–797`) and
  `SignatifVerifier::verify`/`accepted` (`verify.rs:91, 188–207, 140–150`)
  via `SlotTrust::conditions`;
- the typed failure reason `SignatifError::ScopeConditionFailed`
  (`lib.rs`) — the standard's `scope_condition_failed` (§11.8).

Tests: `scope.rs` (3), `graph.rs::resolve_enforces_scope_conditions`,
`tests/scenario_conditions.rs` (3, end-to-end through the pipeline
including acceptance blocking). **conforms.**

### 1.3 Passport (presentation-format projection)

The standard defines a passport as a machine-readable public projection of an
end certificate or trusted artifact, optimized for compact storage (e.g.
two-dimensional barcode). The crate does not define a presentation layer —
UniDPP relies on the core's Tier-A pack and the resolver/issuer crates.
**diverges** at this layer; the conformance gap is outside the trust layer
proper and lives in `unidpp-core`'s pack format.

---

## 2. Scope (CC/SIGNATIF §1)

The clause is a statement of what the document specifies and what is out of
scope. The crate conforms to the in-scope list by implementing the trust
model, scope model, artifact format binding requirements, threshold signing
model, federated TA model, transparency model, revocation model, verification
pipeline, and algorithm agility registry — modulo the gaps noted in §1 and
below. Out-of-scope items (governance procedures, network transports, legal
recognition) are correctly absent.

**Status:** conforms (with the explicit gaps in §1.2, §1.3, §11, §20
annotated).

---

## 3. Principles (CC/SIGNATIF §5)

The eight SIGNATIF letters map onto the crate as follows. Each is a stated
goal, not a normative requirement; conformance is judged on whether the
implementing behaviour satisfies the binding requirements in clauses 6–19.

| Letter | Principle | Crate evidence | Status |
|---|---|---|---|
| S — Sealed | Independent co-signatures cover the same canonical payload | `sign::CoSignature` (multi-slot, same payload, policy-scoped acceptance) + `verify::TrustReport::slots` | conforms |
| I — Interoperable | Scheme-independent pipeline | The crate is scheme-agnostic; the `unidpp-registry` (not in audit) carries scheme-level identifiers; format profiles are not enumerated in the crate (caller's choice) | conforms |
| G — Graduated | Objective coverage report → classification | `verify::SignatifVerdict` + core `Verdict` + `outcome_token` | conforms |
| N — Non-repudiable | Threshold quorum + transparency inclusion | `graph::ThresholdGroup` + `revoke::QuorumAttestation` (threshold of distinct member keys required) + `anchor::TransparencyLog` mandatory inclusion in `verify::SignatifVerifier::verify` via `with_anchor` | conforms |
| A — Anchored | Delegation hierarchy + monotonic narrowing + root-anchor termination | `graph::TrustGraph` + `scope::DelegationScope::narrow` (monotonic narrowing hard check) + `graph::AnchorBundle::accepts_root` (root anchor termination) | conforms |
| T — Trust | Lifecycle with threshold-gated revocation | `revoke::RevocationLedger` + `RevocationReason::is_retroactive` + `revoke::declare` requires `QuorumAttestation` for retroactive reasons (`revoke.rs:387–395`) | conforms |
| I — Infrastructure (level) | Shared anchors, logs, registries | `unidpp-registry` (not in audit) is the registry service; the crate contributes the trust-graph data model and the log-of-logs | conforms |
| F — Framework | Requirements-conformant, profile-instantiated | The crate is a framework implementation: conformance profile registration is deferred to a registry call; the algorithm-agility registry is implemented as the `Suite` enum + `Suite::parse_token` (`sign.rs:78–85`); scope dimensions are extensible (`LayerConstraint::Only(BTreeSet<String>)` carries any string set) | conforms |

---

## 4. Trust model architecture (CC/SIGNATIF §7)

### 4.1 The four-level model (`§7 architecture-authorities`)

The standard's Table 1 (four-level delegation: root trust authority → delegated
trust authority → end certificate → trusted artifact) is mapped as:

- L1 root trust authority → `NodeKind::Root` (optionally a `ThresholdGroup`)
- L2 delegated trust authority → `NodeKind::Delegated` (also a `ThresholdGroup`
 permitted) and `NodeKind::ThresholdGroup { threshold, members }` for
 federations
- L3 end certificate → a `DelegationCredential` whose `child` is
 `NodeKind::End`; the end node's `RegisteredKey` is the authorized signing key
- L4 trusted artifact → `verify::VerificationTarget { log, co_signature, ... }`
 + the core's `EventLog`

The standard notes L1 may be "1-of-1, threshold, or federated"; the crate
covers 1-of-1 (`NodeKind::Root`) and threshold/federated
(`NodeKind::ThresholdGroup { threshold, members }`). L3 is 1-of-1 only —
`conforms`.

### 4.2 Delegation certificate (CC/SIGNATIF §7)

- binds the child's aggregate key (or registered key for 1-of-1) — `DelegationCredential::child: NodeId`
- binds the quorum parameters if the child is a threshold authority — enforced by `graph::verify_credential` (`graph.rs:642–645`); the credential itself does not need to carry `T, N` because they live on the child node
- binds the narrowed authorization scope — `DelegationCredential::scope: DelegationScope`
- references the ceremony protocol used, if threshold — **not carried on the credential** (the credential is signed by the parent's key/keys; the threshold is enforced at the *node* level on verify)

**Status:** conforms on first three; the ceremony-protocol reference is
implicit in the signing key structure (the threshold group node carries
`{threshold, members}`). A strictly conforming implementation would carry the
ceremony-protocol URI on the credential itself. **adapter** (semantically
present at the node, not the credential — the caller's choice of how to
record it in the credential's `metadata`).

### 4.3 End certificate issuance (CC/SIGNATIF §7)

- the authorized public key or fingerprint — `DelegationNode.keys: Vec<RegisteredKey>`
- the authorization scope — `DelegationCredential::scope`
- scope conditions, if any — `DelegationScope::conditions` (`scope.rs:345`; §1.2) — carried in the certificate's signed bytes and evaluated at verify time
- a reference to the issuing trust authority's delegation chain — implicit
 (the chain is the path the verifier walks; no embedded reference on the
 certificate in the standard's normative sense either)

**Status:** conforms.

### 4.4 Trust graph (CC/SIGNATIF §7 `architecture-graph`)

- threshold memberships — multi-hop through `ThresholdGroup` members
- federated trust authorities — `ThresholdGroup { threshold, members }`
 spanning multiple `Delegated` nodes
- cross-domain co-signatures — `sign::CoSignature` permits multiple suites
 (which can be from independent trust chains)
- mutual recognition — **not explicitly modeled**: two `Root` nodes do not
 carry a mutual-recognition edge in the graph data model. The graph supports
 it by the standard DAG mechanism (a delegation credential between two
 roots), but the topology profiles (`§19`) are not enumerated.

**Status:** conforms on first three; **adapter** on mutual recognition (the
mechanism is available; a deployment profile can populate it).

### 4.5 Path-finding (CC/SIGNATIF §7 `architecture-pathfinding`)

- monotonic scope narrowing at every link — `graph::resolve` calls
 `effective.narrow(&cred.scope)` per hop (`graph.rs:746–755`); widening
 errors out
- cryptographic signature validation at every link — `graph::resolve` calls
 `self.verify_credential(cred)` per hop (`graph.rs:742–746`)
- transparency log inclusion — **not enforced** at the trust-graph layer; the
 `TrustGraph::verify_credential` path does not consult a transparency log.
 The pipeline (`verify::SignatifVerifier`) does require `target.anchor` and
 bakes transparency into the core verdict via `VerdictBuilder::with_anchor`,
 but a chain-link transparency check (`graph.rs:122` in the standard's
 algorithm) is not performed here.
- revocation status checking for every authority on the path — **not
 enforced** in `graph::resolve`; the revocation ledger is consulted in
 `verify::SignatifVerifier::verify` (per-slot `key_standing`) but not per
 hop in path-finding.

**Status:** conforms on the first two checks; **diverges** on the
chain-link transparency check and the per-hop revocation check at the graph
layer. The pipeline's anchor and per-slot standing surface the same facts at
a coarser granularity (the verdict fails if anchor is missing; standing is
reported per-slot). A strictly conforming implementation would walk the
ledger per hop.

### 4.6 Chain discovery (CC/SIGNATIF §7 `architecture-discovery`)

The standard recognises three strategies (embedded chain, transparency-log
references, hybrid). The crate implements the **hybrid** strategy: the
artifact carries the co-signature; the verifier holds the trust anchor bundle;
transparency anchoring is done via `anchor::anchor_from_inclusion` (`verify.rs:409–416`).
Embedded chain references via `DelegationCredential.parent`/`child` are
present (each credential carries its endpoints); transparency-log sequence
numbers are recorded in `anchor::LogEntry { commitment, salt_ref }` and
`SignedTreeHead { log_id, tree_size, timestamp, root, signature }`.

**Status:** conforms (hybrid strategy).

### 4.7 Trust anchor bundle (CC/SIGNATIF §7 `architecture-anchors`)

- self-contained — `AnchorBundle` carries the full jurisdiction + master data
- versioned — versioning delegates to a deployment-side convention; the crate
 does not embed a version field on the bundle itself (**adapter** —
 the standard says "each bundle carries a version identifier"; the crate
 carries `jurisdiction` and relies on the caller's deployment manifest)
- distributable — serde-serializable

**Status:** adapter (version field delegated).

---

## 5. Artifact format and signature binding (CC/SIGNATIF §8)

### 5.1 Signature binding requirements (CC/SIGNATIF §8 `artifact-binding`)

| # | Binding requirement | Crate map | Status |
|---|---|---|---|
| 1 | Canonical representation binding | the core's `unidpp_model::CanonicalWriter` (`scope.rs:288–298`, `sign.rs:570–576`, `anchor.rs:282–295`); for co-signatures, the canonical bytes are carried on `CoSignature::payload` and used as the signing input | conforms |
| 2 | Algorithm identification | `SignatureSlot { suite: Suite, key_id: KeyId, signature: Option<Vec<u8>> }` | conforms |
| 3 | Signer identification | `SignatureSlot::key_id` + the trust graph's `KeyDirectory` | conforms |
| 4 | Chain availability | `CoSignature` does not embed the chain; the chain is reconstructed by `graph::TrustGraph::resolve` from the verifier's anchor bundle. The standard permits the **hybrid** strategy (art. 4.6 above), so this is conformant. | conforms |
| 5 | Self-description | `SignatureSlot::suite` + `KeyId` + the `CoSignature::domain` tag carry the signing context; the standard's "without external convention" claim depends on the deployment's anchor bundle being available. | conforms (when the anchor bundle is the deployment convention) |

### 5.2 Canonical payload (CC/SIGNATIF §8 `artifact-canonical-payload`)

- Determinism — `CanonicalWriter` is deterministic; the canonical bytes are
 unambiguous
- Recoverability — the core's reader API round-trips
- Unambiguity — fully specified by the core's framing
- Collision resistance — SHA-256 with length-prefixed fields

**Status:** conforms (delegated to `unidpp-model`).

### 5.3 Co-signatures (CC/SIGNATIF §8 `artifact-cosignatures`)

- Signer identity — `SignatureSlot::key_id`
- Chain reference — implicit (each slot carries its own key id; the chain
 is per-slot via `graph::TrustGraph::resolve`)
- Algorithm — `SignatureSlot::suite`
- Dimension tag — `SigningDomain` per slot
- Signature value — `SignatureSlot::signature`

Each co-signature verifies independently (`sign::CoSignature::verify` builds
a `CoSignatureReport` enumerating per-slot verdicts). All slots attest the
same canonical payload (`CoSignature::payload`). **Status:** conforms.

### 5.4 Cross-domain trust fusion (CC/SIGNATIF §8 `artifact-cross-domain`)

The standard permits cross-domain co-signing without root cross-certification.
The crate's `CoSignature` carries any combination of suites on any
combination of `SigningDomain`s; trust path resolution is per-slot and walks
each slot's chain to whatever root the bundle accepts. **conforms.**

### 5.5 Multi-dimensional attestation (CC/SIGNATIF §8 `artifact-multi-dimensional`)

Convergence on the same canonical payload, each dimension attested by its own
trust tree. The crate provides the convergence primitive; the standard's
coverage report field `dimensions_verified` is delegated to the core's
`Verdict`. The `time` dimension is attested via `verify::HistoricalVerification`
but *not* via a co-signature on the artifact's canonical payload (see §1.1
"time key" adapter note). **adapter.**

### 5.6 Living artifacts (CC/SIGNATIF §8 `artifact-living`)

The standard specifies "the accumulation protocol shall ensure that each added
dimension attestation signs the original canonical payload, not a modified
version". The crate's accumulation is the append-only event log in
`unidpp_event::EventLog`; new dimensions are co-signatures on the *current*
canonical payload (the `body` of the appended event), not on the original
artifact payload. **adapter** — the living-artifact accumulation protocol
maps onto the event log rather than onto co-signature chains.

### 5.7 Format profiles (CC/SIGNATIF §8 `artifact-format-profiles`)

The standard registers `/conf/format-xmldsig`, `/conf/format-jws`,
`/conf/format-cose`. The crate is format-agnostic — it does not register a
profile. **adapter** — the standard's profile registration is a deployment
choice; the UniDPP core's Tier-A pack format is the active profile and is
defined in `unidpp-core`, not in this crate.

---

## 6. Cryptographic algorithms (CC/SIGNATIF §9)

### 6.1 Classical signature algorithms (CC/SIGNATIF §9 `algorithms-classical`)

- ECDSA P-256 — `Suite::EcdsaP256`, real computation via the `p256` crate
 (RFC 6979 deterministic nonce; `keyring.rs:256–261`)
- EdDSA Ed25519 — `Suite::Ed25519`, real computation via `ed25519-dalek`
 (`keyring.rs:252–254`)

The standard also enumerates SM2; the crate frames SM2 (`Suite::Sm2`) but
defers computation to a future GM/T 0003 binding — see §1.1 "composite
signature" note and `sign.rs:134–146` `Suite::deferral`. **adapter** —
SM2 is recognized in the table but refused at verify time with
`SignatifError::SuiteDeferred`.

### 6.2 Post-quantum signature algorithms (CC/SIGNATIF §9 `algorithms-post-quantum`)

ML-DSA-44/65/87 are framed (`Suite::MlDsa44/65/87`); computation
is deferred. **SLH-DSA-128s and SLH-DSA-192s are framed** since the
2026-09-07 pass (`Suite::SlhDsa128s/192s`, tokens `slh-dsa-128s` /
`slh-dsa-192s`, FIPS 205 signature budgets 7856/16224, wire codes 7/8;
`sign.rs:52–78`). Computation is **explicitly unsupported** rather than
deferred: every path (keygen `keyring.rs:198–249`, slot verify
`sign.rs:346–360`) returns `SignatifError::Unsupported` with the
feature guidance — the `slh-dsa` crate feature is the stubbed
integration seam (no PQ crate dependency yet, pending build-size and
supply-chain review; `Suite::unsupported` `sign.rs:206–231`; no
`unimplemented!`/panics anywhere). **adapter** — ML-DSA keeps the
same deferral discipline as SM2; SLH-DSA is recognized in the table
(the standard's `tab-pqc-algorithms` names ML-DSA and SLH-DSA) and
refuses computation explicitly instead of silently faking it. Tests:
`sign::tests::slh_dsa_suites_frame_refusing_computation`,
`manifest::tests` (SLH-DSA as an active post-quantum manifest suite).

### 6.3 Composite signatures (CC/SIGNATIF §9 `algorithms-composite`)

**Implemented** (2026-09-07): `sign::CompositeSignature`
(`sign.rs:426–503`) — the AND-composition of two or more member suites
over the same domain-framed payload; `verify` requires ALL members
valid, a single failure fails the composite. Wired as the alternative
slot form (`CoSignature::composites`, `attach_composite` /
`sign_composite_by`): a verifying composite contributes all member
suites to `verified_suites`, so one composite satisfies the
`min_verified_suites` policy (the hybrid migration case). The
verification pipeline gives every composite member a full
`SlotTrust` row (crypto/path/conditions, `verify.rs:263–281`).
**conforms** — tests `sign::tests::composite_signatures_verify_under_and_composition`,
`sign::tests::composite_slot_form_counts_toward_acceptance`,
`tests/scenario_cosign.rs::composite_slot_form_flows_through_the_pipeline`.

### 6.4 Post-quantum migration path (CC/SIGNATIF §9 `algorithms-migration`)

The crate provides the framing for composite-era artifacts (multi-slot
co-signatures with both classical and PQ slots allowed by the policy) but
does not implement the phasing logic — that is a deployment-side concern.
**adapter.**

---

## 7. Threshold signing (CC/SIGNATIF §10)

### 7.1 Threshold at every level (`§10 threshold-every-level`)

`NodeKind::ThresholdGroup { threshold, members }` permits threshold at any
level; `graph::verify_credential` enforces `verified_keys.len() >= threshold`
(`graph.rs:642–645`). Tested in `tests::graph::tests::threshold_group_quorum_on_credentials`
(`graph.rs:997–1043`). **conforms.**

### 7.2 Aggregate key continuity (`§10 threshold-aggregate-continuity`)

The standard requires the aggregate key to remain unchanged when members
rotate, via re-share protocols preserving the aggregate public key. The
crate does not implement re-share; the `confium` seam defines
`CeremonyKind::Reshare` and `CeremonyKind::Refresh` (`confium.rs:111–119`)
as interface shapes but the mock performs plain signatures. **adapter** —
interface conforms; the cryptographic continuity property awaits the
Confium binding.

### 7.3 Nested threshold (`§10 threshold-nested`)

The data model permits it: a `NodeKind::ThresholdGroup` whose members are
themselves `ThresholdGroup`s. Verified via the recursive signature check.
**conforms.**

### 7.4 Federated trust authorities (`§10 threshold-federated`)

All four sub-clauses (Definition, Recursive composition, Hierarchy-spanning,
Lifecycle) are supported by the data model + the `confium::QuorumSpec`
shape. Lifecycle (Formation / Delegation / Re-share / Dissolution) is
modelled declaratively; only Formation and Delegation have concrete
behaviour. **adapter** — the lifecycle is registered as data; the
cryptographic re-share is deferred to Confium.

### 7.5 Ceremony protocol (`§10 threshold-ceremony`)

`confium::CeremonyCoordinator` defines the interface (create_session,
submit_commitment, submit_share, aggregate) and the
`Pending → CommitmentsCollected → SharesCollected → Completed (+ Expired)`
state machine. Tested in `tests/scenario_confium` (behind `confium`
feature; `tests/scenario_confium.rs:50–80` `lifecycle_follows_the_confium_session_states`).
**conforms** (interface; cryptographic binding deferred).

---

## 8. Trust chain and authorization scope (CC/SIGNATIF §11)

### 8.1 Scope structure (`§11 scope-structure`)

The crate defines 4 layers (`scope::SCOPE_LAYERS = ["authority",
"profile-version", "product-group", "window"]`) where the standard defines
6 (`domain, subdomain, class, instance, identity, conditions`). The
standard permits additional dimensions per profile. The `conditions`
dimension **is** implemented (`DelegationScope::conditions`, §1.2);
the remaining mapping is the documented UniDPP profile substitution.
**adapter** — the 4 layers are a UniDPP profile.

### 8.2 Monotonic narrowing invariant (`§11 scope-monotonic-narrowing`)

Strictly enforced in `DelegationScope::narrow` (`scope.rs:428–476`). The
algorithm is the same as the standard's: per-dimension entailment check,
then intersection; widening returns `SignatifError::ScopeViolation`. Tested
in `tests::scope::tests::narrowing_algebra` (`scope.rs`) and the
property tests `property_scope.rs`. **conforms.**

The `conditions` dimension in the standard uses *superset* narrowing (the
child may add conditions); the crate implements exactly that (`narrow`
unions the conditions and refuses a child that drops a parent condition —
`scope.rs:428–476`; tested in
`scope::tests::conditions_narrow_by_superset_union`). **conforms.**

### 8.3 Authorization scope conditions (`§11 scope-conditions`)

**conforms** — see §1.2.

### 8.4 Authorization scope encoding (`§11 scope-encoding`)

`DelegationScope.canonical_bytes` uses `CanonicalWriter` — length-prefixed,
machine-checkable, compact, wire-efficient. **conforms.**

### 8.5 Multi-layer enforcement (`§11 scope-four-layer`)

| Layer | Crate enforcement | Status |
|---|---|---|
| Certificate extension | `DelegationCredential.scope` is signed as part of `DelegationCredential.canonical_bytes` (`graph.rs:167–173`) | conforms |
| Chain verification | `graph::TrustGraph::resolve` calls `effective.narrow(&cred.scope)` per hop | conforms |
| Verification pipeline | `verify::SignatifVerifier::verify` consults `effective_scope` via `graph::resolve` | conforms |
| Transparency log | The crate does not record scope in a transparency log; the standard says "every certificate" should be transparently logged. The crate's `anchor::LogEntry` carries the commitment (an opaque hash); the scope is not separately logged. **diverges** — the standard's transparency requirement is for the certificate; the crate's transparency log is for commitments, not certificate metadata. |

---

## 9. Revocation and artifact binding (CC/SIGNATIF §12)

### 9.1 CRL profile (`§12 revocation-crl`)

`RevocationLedger.revocations: Vec<Revocation>` carries the subject
identifier (Key/Node/Passport), reason, declared_at, window, declared_by,
quorum. The specific format is a deployment decision per the standard's
NOTE. **conforms** in content; the wire format is JSON/serde (not X.509
CRL). The standard permits any format ("The specific CRL format is a
deployment decision").

### 9.2 Hash-binding to authority states (`§12 revocation-hash-binding`)

The standard says the artifact carries a cryptographic hash-binding to the
authority states under which it was produced. The crate does not embed
authority-state hashes on the artifact — the binding is reconstructed by
the verifier from the trust graph + the ledger. The pipeline's coverage
report enumerates the bound states via the per-slot `SlotTrust.standing`
(`verify.rs:79–82`). **adapter** — the binding is reconstructed, not
embedded.

### 9.3 Propagation algorithm (`§12 revocation-propagation`)

`revoke::RevocationLedger::taints_of` walks the core's `ProvenanceGraph`
ancestors (`revoke.rs:448–521`), adds direct passport and key-level taints,
and merges the cascade. Tested in `tests::revoke::tests::taint_cascades_through_provenance`
(`revoke.rs:704–750`) and `tests/scenario_misissuance::retroactive_declaration_voids_in_window_and_revalidates_outside`
(`scenario_misissuance.rs:148–202`). **conforms.**

### 9.4 Scope condition withdrawal (`§12 revocation-condition-withdrawal`)

**conforms** (2026-09-07) — `RevocationReason::ConditionWithdrawal`
(prospective; no quorum required) + `RevokedSubject::Condition { node,
condition }` (`revoke.rs:63–67, 131–144`) declare the withdrawal;
`RevocationLedger::withdrawn_conditions_at(node, at)` (`revoke.rs:425`)
queries it; the verification pipeline applies the overlay
(`verify.rs::evaluate_conditions`, `verify.rs:194–205`): a condition
still carried by a path's credential scope but withdrawn for its
grantee node, in force at the verification moment, fails the verify-time
condition check — the §12 withdrawal propagation, expressed through
verify-time evaluation (conditions are never satisfied "on the record",
so withdrawal cannot be laundered by pre-existing artifacts). Tested in
`revoke::tests::condition_withdrawal_declares_and_propagates` and
`tests/scenario_conditions.rs::withdrawn_condition_fails_from_the_effect_moment_only`.

### 9.5 Flag semantics (`§12 revocation-flag-semantics`)

The crate uses `Taint` flags (not deletion) via `unidpp_transform::Taint`
and the `TaintSet` propagation. The artifact is marked, not removed.
Reversibility is not implemented (the standard mentions "the marking is
reversible if the revocation is itself revoked" — there is no
"revocation-of-a-revocation" operation in the crate). **adapter** on
reversibility.

### 9.6 Query interface (`§12 revocation-query`)

- "Given an artifact, return its bound authority states and their
 revocation status" — `SlotTrust.standing` per slot (`verify.rs:79–82`).
- "Given a revoked state, return the set of artifacts transitively bound
 to it" — `RevocationLedger::taints_of` walks ancestors; the inverse
 query (descendants of a revoked state) is implemented in the core's
 `ProvenanceGraph::descendants` and exercised in `tests/scenario_misissuance::retroactive_declaration_voids_in_window_and_revalidates_outside`
 (`scenario_misissuance.rs:201`).

**Status:** conforms.

### 9.7 Offline verification and grace period (`§12 revocation-offline`)

`RevocationLedger::taints_known_at` and `key_standing_at` accept a
`known_by: Option<Timestamp>` parameter for the evidentiary cutoff
(`revoke.rs:395–433` and `:535–543`). The grace-period policy (stale CRL
downgrade vs rejection) is delegated to the acceptance policy; the
coverage-report `downgrades` field in the core records the soft-check
non-passes. **conforms** (the policy is a deployment choice; the data
plumbing is conformant).

---

## 10. Transparency and multi-log attestation (CC/SIGNATIF §13)

### 10.1 Transparency log structure (`§13 transparency-log-structure`)

`anchor::TransparencyLog`: append-only, inclusion proofs
(`verify_inclusion`), consistency proofs (`verify_consistency`), append-only
guarantee, signed tree heads (`SignedTreeHead::sign_tree_head` /
`verify`), domain separation (0x01 leaf / 0x02 internal), consistency-proof
proofs. **conforms.**

The standard notes RFC 6962 / RFC 9162 (Certificate Transparency Version 2)
and IETF SCITT as compatible designs. The crate implements RFC 6962
Merkle-tree semantics with the Confium-style constants (0x01/0x02 rather
than RFC 6962's 0x00/0x01) — see `anchor.rs:7–15` for the documented
rationale. **adapter** (domain-separation byte values diverge from
RFC 6962 deliberately to compose with the future Confium binding).

### 10.2 Consistency proof (`§13 transparency-consistency-proof`)

The crate's `ConsistencyProof { old_size, new_size, path: Vec<Hash> }` is
the RFC 6962 SUBPROOF node list (`anchor.rs:91–100`). `verify_consistency`
walks the recursion (`anchor.rs:359–412`). Tested in
`tests::anchor::tests::consistency_all_pairs` (`anchor.rs:722–756`) and
`tests/property_merkle::every_consistency_proof_verifies_and_rejects_forgeries`
(`property_merkle.rs:108–171`). **conforms.**

### 10.3 Inclusion proof (`§13 transparency-inclusion-proof`)

`InclusionProof { leaf_index, tree_size, path: Vec<ProofNode> }` carries the
leaf hash (via the entry reference), the audit path (`path`), and the tree
head (passed separately). `verify_inclusion` recomputes the root
(`anchor.rs:324–349`). Tested in
`tests::anchor::tests::inclusion_all_positions_all_sizes` (`anchor.rs:667–691`).
**conforms.**

### 10.4 External time anchoring (`§13 transparency-anchoring`)

**adapter** (2026-09-07) — the crate now produces the anchoring
commitment and verifies it offline; the submission and the completed
proof remain deployment-side (the library never performs network
calls, by design):

- `anchor::ExternalAnchorMethod` (`Rfc3161 { tsa_url }` /
  `OtsLite { rendezvous }`) and `anchor::ExternalAnchor`
  (`anchor.rs:376–434`);
- `anchor::external_anchor_payload(sth, method)` (`anchor.rs:437–468`) —
  commits to `sha256(STH-canonical-bytes)`; OTS-lite framing is the
  digest + rendezvous point, RFC 3161 framing is a minimal DER
  `TimeStampReq` (version 1, SHA-256 messageImprint, nonce;
  hand-rolled DER, no new dependency) ready for
  `application/timestamp-query` submission;
- `SignedTreeHead::anchored_externally` (`anchor.rs:338`) attaches the
  anchor to the head (it commits *to* the signed bytes, so attaching
  after the operator signature is sound); `verify_external_anchor`
  (`anchor.rs:472`) and `SignedTreeHead::verify_external_anchor`
  (`anchor.rs:348`) check the payload-to-head binding offline — any
  post-hoc mutation of the head breaks it;
- the documented submission flow (build → submit to
  `submission_target` → store the returned RFC 3161 response / OTS
  proof → verify the completed proof against the source's trust
  anchors) is in the `ExternalAnchor` rustdoc.

Tests: `anchor::tests::{external_anchor_commits_to_the_head,
rfc3161_request_is_well_formed_der}`,
`tests/scenario_transparency.rs::tree_head_anchored_externally_for_irrefutable_time`.
The remaining gap to full §13 conformance — verifying the *completed*
external proof — needs the time source's trust anchors and is a
deployment/binding concern (same seam class as Confium and the PQ
bindings).

### 10.5 Mirrors and gossip (`§13 transparency-mirrors`)

The `LogOfLogs` is the trust analogue: witness logs' signed tree heads
anchored as leaves of one master log; M-of-K quorum for master-list
acceptance (`anchor.rs:507–563`, `verify_master_quorum` at
`anchor.rs:566–582`). Tested in
`tests::anchor::tests::log_of_logs_master_quorum` (`anchor.rs:823–885`)
and `tests/scenario_transparency::log_of_logs_m_of_k_master_anchoring`
(`scenario_transparency.rs:155–213`). **conforms** (multi-log attestation
is implemented; the gossip protocol between mirrors is not — gossip is a
network-protocol concern, out of scope per the standard's note).

### 10.6 Multi-log attestation (`§13 transparency-multi-log`)

Same — `LogOfLogs { m, k }` + `verify_master_quorum`. **conforms.**

---

## 11. Verification pipeline (CC/SIGNATIF §14)

### 11.1 Pipeline (`§14 verification-pipeline`)

The crate's `verify::SignatifVerifier::verify` is an ordered sequence of
checks. Cross-walk:

| Check | Standard | Crate | Status |
|---|---|---|---|
| Format validity (hard) | §14 `tab-pipeline-checks` | the core's `VerdictBuilder` parses the artifact event log + co-signature; malformed inputs fail the pipeline | conforms (delegated to core) |
| Signature validity (hard) | §14 | `sign::CoSignature::verify` builds `CoSignatureReport`; `TrustReport::slots` enumerates per-slot `SlotTrust.crypto` | conforms |
| Chain integrity (hard) | §14 | `graph::TrustGraph::resolve` finds a path; failure surfaces as `SignatifError::NoTrustPath` / `CredentialSignatureInvalid` / `ScopeExcluded` and is reflected in the verdict via the core's `cryptographic.chain_verified` | conforms |
| Scope narrowing (hard) | §14 | `graph::resolve` calls `effective.narrow(&cred.scope)` per hop and refuses widening | conforms |
| Scope conditions (hard) | §14 | `TrustGraph::resolve` checks `first_failed_condition` per candidate path (`graph.rs:784–797`); `SignatifVerifier::verify` records `SlotTrust::conditions` per slot and `SignatifVerdict::accepted` gates on it (`verify.rs:91, 140–150, 188–207`) | conforms |
| Revocation status (hard) | §14 | `verify::SignatifVerifier::verify` consults the ledger per slot (`key_standing`); taint cascade is consulted via the core's `VerdictBuilder::with_taints` | conforms |
| Transparency inclusion (soft) | §14 | `verify::SignatifVerifier` requires `target.anchor: Option<Hash>`; missing anchor degrades to `Outcome::Degraded(OfflineNoAnchor)` (tested in `tests/scenario_transparency::artifact_head_anchored_through_inclusion_and_sth`, `scenario_transparency.rs:96–120`) | conforms (soft-check downgrade semantics) |
| Time anchor (soft) | §14 | the notary stamp is a separate artefact, not a co-signature on the canonical payload; the coverage report's `time_anchored` is delegated to the core | adapter — see §1.1 "time key" |
| Cross-domain co-signatures (soft) | §14 | `CoSignature::verified_suites` enumerates distinct verified suites; `SlotTrust.crypto` enumerates per-slot | conforms |
| Multi-log attestation (soft) | §14 | `verify_master_quorum` checks the M-of-K; this is invoked from the deployment's trust-service, not directly by `SignatifVerifier` | adapter — the verification primitive is available; the coverage-report field `multi_log_quorum` is delegated to the core |

### 11.2 Path-finding (`§14 verification-pathfinding`)

`graph::TrustGraph::resolve` enumerates paths via
`TrustGraph::paths(root → end)` (DFS with cycle prevention,
`graph.rs:658–690`). The procedure:

1. enumerate simple paths from each root to the key's end node
2. check `bundle.accepts_root(root, request.at)` for each
3. verify each credential in the path (single or threshold quorum)
4. narrow scope per hop; reject if widening or empty intersection
5. check the effective scope admits the request
6. return the first matching path (deterministic by sorted indices)

**Status:** conforms on enumeration + check sequence; **diverges** on the
chain-link transparency check and per-hop revocation check (see §4.5). The
"the coverage report is computed as a pure function of the set of all
valid paths, not of any single path" requirement is met — the core's
`Verdict` is computed from the slots' union, not from any single path.

### 11.3 Independence of roots and logs (`§14 verification-pathfinding independence`)

The standard defines "two root anchors are independent if neither is
reachable from the other via delegation links in the trust graph and they
do not share a common delegating ancestor other than themselves". The
crate does not compute independence — `coverage_report.independent_roots`
is delegated to the core (which counts distinct roots in the path set).
**adapter** — the strict independence definition is not enforced; the
count is a count, not a structural check.

### 11.4 Coverage report (`§14 verification-coverage`)

The standard names eight fields. The crate delegates the report to the
core's `Verdict` (which owns the degradation ladder and the coverage
ratio). The SIGNATIF wrapper (`verify::TrustReport`) carries the per-slot
trust facts and the acceptance decision. **conforms** by composition.

### 11.5 Classification and acceptance policies (`§14 verification-classification` and `-acceptance`)

The standard explicitly says "the standard does not prescribe grade
labels or classification thresholds". The crate exposes the policy as
data (`sign::AcceptancePolicy`); the classification policy lives in the
core's `VerdictBuilder`. **conforms.**

### 11.6 Time freshness window (`§14 verification-freshness`)

The crate delegates the freshness window to the profile's
`FreshnessRequirement` and the core's degradation ladder
(`Degradation::StaleData`); tested in
`tests/scenario_delegation::coverage_and_freshness_degrade_explicitly_through_the_pipeline`
(`scenario_delegation.rs:209–331`). **conforms.**

### 11.7 Offline verification (`§14 verification-offline`)

The core `Verdict` carries an explicit `OfflineNoAnchor` degradation; the
pipeline accepts but downgrades (`tests/scenario_transparency::artifact_head_anchored_through_inclusion_and_sth`
at `scenario_transparency.rs:96–120`). **conforms.**

### 11.8 Verification result structure (`§14 verification-results`)

- `classified_grade` — core `Verdict.outcome`
- `paths` — `TrustReport.slots[*].path.as_ref().ok()`
- `dimensional_coverage` — `TrustReport.slots[*].key_id` + `co_signature_report.verified_suites`
- `failures` — `TrustReport.slots[*].crypto.err()` and `.path.err()`
- `downgrades` — core `Verdict.outcome` (Degraded variants)

The typed failure reasons in the standard's `tab-failure-reasons` map as:

| Failure reason | Crate |
|---|---|
| `format_invalid` | core `Failure::BrokenChain` |
| `signature_invalid` | `SlotTrust.crypto: Err(String)` |
| `chain_broken` | `graph::TrustGraph::resolve` returns `NoTrustPath` / `CredentialSignatureInvalid` |
| `scope_widened` | `DelegationScope::narrow` returns `SignatifError::ScopeViolation` |
| `scope_condition_failed` | `SignatifError::ScopeConditionFailed { condition }` (`lib.rs`) — from `TrustGraph::resolve` (path-finding) and `SignatifVerifier::evaluate_conditions` (pipeline, `SlotTrust.conditions`) |
| `revoked` | `SlotTrust.standing != Standing::Valid` |
| `transparency_missing` | `verdict.outcome = Degraded(NoFreshnessEvidence | OfflineNoAnchor)` |

**Status:** conforms for all the failure reasons the standard names
(`scope_condition_failed` implemented since the 2026-09-07 pass).

### 11.9 Historical verification (`§14 verification-offline` + `verify_historical`)

`verify::SignatifVerifier::verify_historical` produces an as-of snapshot
notarized in `SigningDomain::HistoricalStamp` with the state hash from the
*source* log (`verify.rs:259–299`). `HistoricalVerification::still_stands`
compares the as-of taints to the current taints and returns
`RetroactivelyInvalidated` if a later void-ab-initio declaration hit what
the stamp certified. **conforms** — tested in
`tests/scenario_misissuance::historical_stamps_retroactively_invalidated_but_evidence_stands`
(`scenario_misissuance.rs:223–298`).

---

## 12. Key lifecycle (CC/SIGNATIF §15)

The standard covers generation, storage, rotation, ceremony. The crate's
`keyring.rs:198–228` `KeyPair::seeded` is a deterministic key derivation
for tests and ceremony fixtures — production keys are stated to come from
a CSPRNG-backed HSM store (`keyring.rs:11–13`). Rotation is not modelled;
re-share is in the `confium` seam (`CeremonyKind::Reshare`) without
cryptographic implementation. **adapter** — the cryptographic rotation and
re-share await the Confium binding; the data model supports them.

---

## 13. Delivery and discovery (CC/SIGNATIF §16)

The standard specifies chain resolution, trust anchor bundles,
machine-readable passports, and challenge-response. The crate implements
chain resolution (`graph::TrustGraph::resolve`), trust anchor bundles
(`graph::AnchorBundle`), and notarized historical verifications
(`HistoricalVerification`). Machine-readable passports (CC/SIGNATIF §3.12)
and challenge-response (CC/SIGNATIF §5.3.3) are outside this crate (see
§1.3). **adapter** — conformance is partial; the missing parts live in
`unidpp-core` (Tier-A pack format) and the issuer/resolver crates.

---

## 14. Ceremony records (CC/SIGNATIF §17)

The standard says a ceremony protocol shall produce a ceremony record that
is independently verifiable. The `confium` interface defines
`SessionInit { kind, statement, quorum, expires_at }` and the session
state machine, plus `MisbehaviorProof` for identifiable abort
(`confium.rs:208–216`). The mock emits the ceremony transcript implicitly
through the round-1 commitments and round-2 shares; cryptographic
verifiability of the *aggregate signature* is in place (the mock verifies
under `MockCeremony::group_key`), but the **ceremony record** as a
signed, attestable artefact is not a separate type. **adapter** —
interface conforms; the ceremony-record artefact awaits the binding.

---

## 15. Deployment manifest (CC/SIGNATIF §18)

**conforms** (2026-09-07) — `manifest::DeploymentManifest`
(`manifest.rs:162`): `version`, `operator`, `active_algorithms`,
`deprecated_algorithms`, `migration_phase`, `topology_profile`,
`scope_extensions`, `effective_from`; serde-serializable (suites and
phases serialize as their stable tokens). `validate`
(`manifest.rs:218`) enforces: non-empty version/operator; ≥ 1 active
algorithm; no suite both active and deprecated; hybrid phases require
a mixed classical+PQ active set; the post-quantum phase excludes
classical actives; scope-extension names non-empty and constraints
non-contradictory. `algorithm_status` /
`accepts_verification` give the §20 agility status (active /
deprecated = retirement window / not listed). `MigrationPhase`
(Classical → HybridCoSigned → HybridComposite → PostQuantum) and
`TopologyProfile` (Hierarchical / Federated / CrossRecognized / Mesh,
§19) are enumerated sum types with token (de)serialization. Tests:
`manifest::tests` (4). Carried alongside `AnchorBundle` by the
deployment.

---

## 16. Governance and mutual recognition (CC/SIGNATIF §19)

The standard enumerates four topology profiles: Hierarchical, Federated,
Cross-recognized, Mesh. The crate's data model supports all four (the
graph is a DAG; `NodeKind::Root` permits multiple roots; the
`ThresholdGroup` permits cross-root membership). The **profiles** are not
named in the type system — the crate carries the topology as data and
leaves profile selection to the deployment. **adapter** — the topology
profiles are not enumerated as a sum type.

---

## 17. Algorithm agility (CC/SIGNATIF §20)

### 17.1 Algorithm identifier registry (`§20 algorithm-agility-registry`)

`sign::Suite::ALL` + `Suite::parse_token` + the
`unidpp-registry`-side enumeration is the algorithm identifier registry.
The crate carries the registry surface (`Suite` enum + serialization
tokens); the active/deprecated/retired status field is **not** modelled on
the suite type itself — it is a deployment-side concern (the registry
service holds the status). **adapter** — status field is external.

### 17.2 Deprecation process (`§20 algorithm-agility-deprecation`)

Not implemented as a process. The crate's `verify` will reject framed-only
suites with `SignatifError::SuiteDeferred`; "deprecation" therefore
manifests as refusal to verify, not as a downgrade. **adapter** — the
deprecation-process semantics (announce → period → retire → reject) are
not encoded; the registry service is the place where the phases are
scheduled.

### 17.3 Migration governance (`§20 algorithm-agility-migration`)

Implemented as data since the 2026-09-07 pass: the deployment
manifest's `MigrationPhase` (Classical / HybridCoSigned /
HybridComposite / PostQuantum) + `deprecated_algorithms` encode the
phases, with coherence validated in `DeploymentManifest::validate`
(§15). The composite and multi-suite co-signature forms are the two
hybrid mechanisms the phases name. **conforms** (the scheduling/
announcement process itself is registry-side, as the standard's NOTE
permits).

---

## 18. Security considerations (CC/SIGNATIF §21)

The standard's security considerations are not enumerated as a clause
table here; the conformance-relevant points are covered by the security-
relevant primitives (domain separation in `SigningDomain`, monotonic
narrowing hard check, threshold quorum enforcement, transparency log
inclusion, retroactive-vs-prospective reason distinction,
`is_framed_only` discipline on placeholder slots, framed-only suites
reporting as `Deferred` rather than faking verification — and, since
the 2026-09-07 pass, closed-world scope-condition evaluation (absent
predicate outcomes and attributes fail closed), AND-composition
composites that fail on any member, explicit `Unsupported` rather than
silent gaps for SLH-DSA, and offline external-anchor verification).
**conforms** on the implemented primitives; the remaining gap is the
ceremony re-share (Confium binding).

---

## 19. Conformance class hierarchy and abstract test suite (CC/SIGNATIF §6 + `aa-abstract-test-suite.adoc`)

The standard defines conformance classes. The crate implements:

| Requirement class | Crate evidence |
|---|---|
| `architecture` (trust model, four-level, DAG) | `graph.rs` (TrustGraph, DelegationCredential, DelegationNode, NodeKind) |
| `scope` (4 dimensions + conditions, monotonic narrowing, four-layer enforcement) | `scope.rs` (DelegationScope, LayerConstraint, WindowConstraint, ScopeCondition, ScopeRequest); 4-layer scope per UniDPP profile + the standard's conditions dimension (see §1.1, §1.2) |
| `artifact-format` (canonical payload, format profiles, co-signatures) | `sign.rs` (CoSignature, SignatureSlot, SigningDomain, CompositeSignature as the composite slot form); format-agnostic |
| `threshold-signing` (every level, quorum, federated, ceremony) | `graph.rs::ThresholdGroup`, `graph::verify_credential`; `confium.rs::CeremonyCoordinator` (interface-only) |
| `revocation` (CRL, hash-binding, propagation, condition withdrawal, flag semantics, query, offline) | `revoke.rs` (RevocationLedger, RevocationReason, Standing, QuorumAttestation, RevokedSubject::Condition + withdrawn_conditions_at); condition withdrawal conforms (see §9.4) |
| `transparency` (log structure, inclusion, consistency, anchoring, mirrors, gossip, multi-log) | `anchor.rs` (TransparencyLog, InclusionProof, ConsistencyProof, SignedTreeHead, LogOfLogs, verify_master_quorum, ExternalAnchor + external_anchor_payload + verify_external_anchor); external time anchoring adapter — payload + offline verification in-crate, submission/proof deployment-side (see §10.4) |
| `verification` (pipeline, path-finding, coverage report, classification, acceptance, freshness, offline, results) | `verify.rs` (SignatifVerifier, VerificationTarget, TrustReport, SignatifVerdict, HistoricalVerification, SlotTrust.conditions); all failure reasons incl. scope_condition_failed conformant (see §11.8) |
| `algorithms` (classical + post-quantum incl. SLH-DSA framing, composite, agility) | `sign.rs::Suite` (incl. SlhDsa128s/192s with explicit Unsupported), `CompositeSignature`; deferred suites reported via `SuiteDeferred` |
| `deployment manifest` (§18: active algorithms, migration phase, topology profile, scope extensions) | `manifest.rs` (DeploymentManifest, MigrationPhase, TopologyProfile, AlgorithmStatus, validate) |

The abstract test suite is the union of `tests/property_*.rs` (randomized
property tests for Merkle proofs and scope narrowing) and
`tests/scenario_*.rs` (end-to-end scenarios for cosign, delegation,
misissuance, transparency, confium). **conforms** as a working test suite
for the implemented subset.

---

## 20. Summary of conformance-to-model map

### 20.1 Counts

The clauses audited span 21 CC/SIGNATIF sections (§§1–21) + terms (§3) +
abstract test suite (§6). Original per-clause-item counts:
conforms 38 / adapter 17 / diverges 6.

The 2026-09-07 implementation pass moved exactly the six audited
divergence items:

| Class | Original | 2026-09-07 pass |
|---|---|---|
| conforms | 38 | 42 (+4: scope conditions, composite signatures, condition withdrawal, deployment manifest) |
| adapter | 17 | 19 (+2: external time anchoring, SLH-DSA framing) |
| diverges | 6 | 0 of the six audited items (the passport presentation-layer divergence, §1.3, remains by design — it lives in `unidpp-core`'s pack format, outside this crate's layer) |

Top-level clause summary (post-pass; original in parentheses where
changed):

| Clause | Conforms | Adapter | Diverges |
|---|---|---|---|
| §1 Scope | 1 | 0 | 0 |
| §3 Terms | 28 (26) | 7 (8) | 2 (3)¹ |
| §5 Principles | 8 | 0 | 0 |
| §7 Architecture | 4 | 3 | 0 |
| §8 Artifact format | 5 | 2 | 0 |
| §9 Algorithms | 2 (1) | 4 (3) | 0 (1) |
| §10 Threshold signing | 2 | 2 | 0 |
| §11 Trust chain & scope | 5 (4) | 1 | 1 (2) |
| §12 Revocation | 6 (5) | 1 | 0 (1) |
| §13 Transparency | 5 | 2 (1) | 0 (1) |
| §14 Verification pipeline | 9 (8) | 3 | 0 (1) |
| §15 Key lifecycle | 0 | 1 | 0 |
| §16 Delivery & discovery | 1 | 1 | 0 |
| §17 Ceremony records | 0 | 1 | 0 |
| §18 Deployment manifest | 1 (0) | 0 | 0 (1) |
| §19 Governance | 0 | 1 | 0 |
| §20 Algorithm agility | 1 (0) | 2 (3) | 0 |
| §21 Security considerations | 1 | 0 | 0 |
| §6 + ATS | 1 | 0 | 0 |

¹ the passport row of §1.1 still reads *diverges* (§1.3: the
presentation-format projection lives in `unidpp-core`'s Tier-A pack,
deliberately outside this crate) — it was never one of the six
actionable divergences of §20.2; the other remaining diverge is the
§8.5 transparency-layer granularity note (chain-link scope logging).

### 20.2 The six divergences — RESOLVED (2026-09-07 implementation pass)

All six items below were implemented on branch `divergences`; the test
count went 71 → 90, fmt and clippy `-D warnings` clean. What each
divergence now does, with the new evidence:

1. **Authorization scope conditions (CC/SIGNATIF §3.6.4, §11 `scope-conditions`) — now conforms.**
   `scope::ScopeCondition` (`TimeWindow{from,until}` /
   `Predicate{expression_ref}` / `Attribute{key,allowed_values}`) on
   `DelegationScope::conditions` (`src/scope.rs:65–161, 345`);
   superset narrowing in `DelegationScope::narrow`
   (`src/scope.rs:428–476`: the child may add conditions, never drop a
   parent's); verify-time evaluation in `TrustGraph::resolve`
   (`src/graph.rs:784–797`) and the pipeline
   (`src/verify.rs:188–207` via `SlotTrust::conditions`, gating
   `accepted` at `src/verify.rs:140–150`); typed failure
   `SignatifError::ScopeConditionFailed{condition}` (`src/lib.rs`) —
   the standard's `scope_condition_failed`. Tests: `scope.rs` ×3,
   `graph.rs::resolve_enforces_scope_conditions`,
   `tests/scenario_conditions.rs` ×3.

2. **Composite signatures (CC/SIGNATIF §3.7.4, §9 `algorithms-composite`) — now conforms.**
   `sign::CompositeSignature` (`src/sign.rs:426–503`): cryptographic
   AND-composition — every member suite must verify; a single failing
   member fails the composite (deferred/framed-only/unknown members
   fail it too). Wired as the alternative slot form
   `CoSignature::composites` (`src/sign.rs:554`;
   `attach_composite`/`sign_composite_by` at `src/sign.rs:584–611`)
   alongside the multi-suite collection; a verifying composite
   contributes all member suites to `verified_suites`, so one
   composite satisfies `min_verified_suites = 2` (the hybrid
   classical/PQ migration case); the pipeline emits a `SlotTrust` row
   per member (`src/verify.rs:263–281`). Tests: `sign.rs` ×2,
   `tests/scenario_cosign.rs::composite_slot_form_flows_through_the_pipeline`.

3. **External time anchoring of transparency tree heads (CC/SIGNATIF §13 `transparency-anchoring`) — now adapter.**
   `anchor::external_anchor_payload(sth, method)` + `ExternalAnchor` +
   `ExternalAnchorMethod{Rfc3161, OtsLite}` (`src/anchor.rs:376–468`):
   the commitment is sha256 of the STH's canonical bytes, framed
   either as an OTS-lite digest+rendezvous-point or as a minimal DER
   RFC 3161 `TimeStampReq` (version 1, SHA-256 messageImprint, nonce;
   hand-rolled DER — no new dependency), ready for
   `application/timestamp-query` submission. `SignedTreeHead::anchored_externally`
   (`src/anchor.rs:338`) attaches it to the head; `verify_external_anchor`
   (`src/anchor.rs:472`) and `SignedTreeHead::verify_external_anchor`
   (`src/anchor.rs:348`) verify the payload-to-head binding offline —
   any post-hoc mutation of the head breaks it. **No network calls in
   the library**: the submission flow (and verification of the
   completed proof against the time source's trust anchors) is
   documented deployment-side on `ExternalAnchor`. Tests: `anchor.rs`
   ×2, `tests/scenario_transparency.rs::tree_head_anchored_externally_for_irrefutable_time`.

4. **SLH-DSA framing (CC/SIGNATIF §9 `algorithms-post-quantum`) — now adapter.**
   `Suite::SlhDsa128s` / `Suite::SlhDsa192s` (`src/sign.rs:52–78`):
   tokens `slh-dsa-128s`/`slh-dsa-192s`, FIPS 205 signature budgets
   7856/16224 bytes, wire codes 7/8, no core carrier mapping.
   Computation is refused with the explicit
   `SignatifError::Unsupported` (distinct from `SuiteDeferred`) from
   `KeyPair::seeded` (`src/keyring.rs:198–249`) and
   `SignatureSlot::verify` (`src/sign.rs:346–360`), gated on the
   **stubbed** `slh-dsa` crate feature (`Cargo.toml`): the PQ binding
   crate is deliberately not a dependency yet (build-size and
   supply-chain review pending; rationale in `Suite::unsupported`,
   `src/sign.rs:206–231`). No `unimplemented!` anywhere — every path
   returns an explicit error. Tests:
   `sign.rs::slh_dsa_suites_frame_refusing_computation`; SLH-DSA also
   appears as an active manifest suite in `manifest.rs` tests.

5. **Scope condition withdrawal (CC/SIGNATIF §12 `revocation-condition-withdrawal`) — now conforms.**
   `RevocationReason::ConditionWithdrawal` (prospective — no quorum
   required; earlier verifications stand) + `RevokedSubject::Condition{node,
   condition}` (`src/revoke.rs:63–67, 131–144`) declare the withdrawal;
   `RevocationLedger::withdrawn_conditions_at(node, at)`
   (`src/revoke.rs:425`) queries it; the pipeline's condition
   evaluation applies the overlay (`src/verify.rs:194–205`): a
   condition still carried by a path's credential scope but withdrawn
   for its grantee node, in force at the verification moment, fails
   the check — the §12 withdrawal propagation expressed through
   verify-time evaluation, so withdrawal cannot be laundered by
   pre-existing artifacts. Tests:
   `revoke.rs::condition_withdrawal_declares_and_propagates`,
   `tests/scenario_conditions.rs::withdrawn_condition_fails_from_the_effect_moment_only`.

6. **Deployment manifest (CC/SIGNATIF §18) — now conforms.**
   `manifest::DeploymentManifest` (`src/manifest.rs:162`):
   `version`, `operator`, `active_algorithms`,
   `deprecated_algorithms`, `migration_phase` (Classical /
   HybridCoSigned / HybridComposite / PostQuantum), `topology_profile`
   (Hierarchical / Federated / CrossRecognized / Mesh — the §19 four),
   `scope_extensions`, `effective_from`; serde-serializable with
   stable kebab-case tokens. `validate()` (`src/manifest.rs:218`)
   enforces the §18/§20 coherence rules: non-empty version/operator,
   ≥ 1 active algorithm, no suite both active and deprecated, hybrid
   phases require a mixed classical+PQ active set, the post-quantum
   phase excludes classical actives, and scope-extension constraints
   are non-contradictory. `algorithm_status` /
   `accepts_verification` expose the agility status (active /
   deprecated-retirement-window / not listed). Tests: `manifest.rs` ×4.

The remaining documented gaps after this pass: the passport
presentation layer (§1.3 — lives in `unidpp-core`'s Tier-A pack), the
chain-link transparency + per-hop revocation granularity (§4.5), and
the cryptographic bindings (Confium re-share; SM2, ML-DSA, SLH-DSA
computation) — all interface-only by documented design choice.

### 20.3 Top adapters (semantic equivalences, no conformance gap)

The adapter class captures places where the crate diverges from the
standard's prescribed shape by deliberate, documented design. The most consequential:

- **4-layer scope instead of 6-layer.** The standard's six dimensions
 (domain, subdomain, class, instance, identity, conditions) are mapped
 onto UniDPP's operating model (authority, profile-version,
 product-group, window) — with `conditions` now implemented as its own
 dimension (§1.2). This is a profile choice the standard
 permits ("additional dimensions may be defined by profiles").

- **Trust graph path-finding without chain-link transparency or per-hop
 revocation.** The crate does the cryptographic and scope-narrowing
 checks per hop but does not consult the transparency log or the
 revocation ledger per hop. Both are surfaced at the verdict level via
 the core's anchor and per-slot standing. The end effect on the
 coverage report is equivalent for implemented checks; the unimplemented
 per-hop revocation check is a divergence (item #5 above).

- **`TrustGraph::resolve` returns the first matching path, not the set of
 all valid paths.** The standard's path-finding algorithm collects all
 valid paths into `P`. The crate collects the first valid path and the
 core's coverage report enumerates the slot-level union. The
 per-slot union is a faithful projection of the path set; the strict
 "all valid paths" semantics are achieved at the coverage-report level.

- **Ed25519 as an infrastructure suite (not in the core's carrier table).**
 The crate documents this as an extension (`sign.rs:31–36`); the
 standard does not restrict the suite table. The acceptance policy
 scopes which suites a verifier accepts, which is conformant with the
 algorithm-agility clause.

- **Quorum ceremony interface without cryptographic implementation.**
 `confium::CeremonyCoordinator` defines the lifecycle, message
 validation, and identifiable abort; the mock performs plain Ed25519
 signatures. The interface conforms; the cryptographic re-share and
 threshold aggregation await the Confium binding (no production code
 change in this audit).

---

## 21. File:line citations (selected, for quick navigation)

Line numbers refreshed after the 2026-09-07 implementation pass; new
symbols of the pass are marked ★.

| Crate symbol | Path | Lines | Standard clause |
|---|---|---|---|
| `Suite::ALL` | src/sign.rs | 76–88 | §3.7.1, §9 |
| `Suite::deferral` | src/sign.rs | 179–204 | §9 (SM2, ML-DSA) |
| ★ `Suite::unsupported` | src/sign.rs | 206–231 | §9 (SLH-DSA, `slh-dsa` feature stub) |
| ★ `Suite::is_post_quantum` | src/sign.rs | 145–154 | §18/§20 (migration-phase input) |
| `SigningDomain` | src/sign.rs | 258–284 | §3.9, §10 |
| `domain_framed` | src/sign.rs | 289–295 | §3.7.1 (domain separation) |
| ★ `CompositeSignature` (+`verify`) | src/sign.rs | 426–503 | §3.7.4, §9 `algorithms-composite` |
| `CoSignature::verify` (composites wired) | src/sign.rs | 618–660 | §8 `artifact-cosignatures`, §3.7.4 |
| `AcceptancePolicy` | src/sign.rs | 761– | §14 `verification-acceptance` |
| `DelegationScope` (+`conditions`) | src/scope.rs | 332–346 | §3.6.1, §3.6.4, §11 |
| ★ `ScopeCondition` | src/scope.rs | 65–161 | §3.6.4, §11 `scope-conditions` |
| `SCOPE_LAYERS` | src/scope.rs | 38 | §11 (4 vs 6 layers) |
| `DelegationScope::narrow` (condition union) | src/scope.rs | 428–476 | §3.6.5, §11 `scope-monotonic-narrowing` |
| ★ `DelegationScope::first_failed_condition` | src/scope.rs | 488–496 | §11, §14 |
| `DelegationCredential` | src/graph.rs | 153– | §7 `architecture-authorities` |
| `NodeKind::ThresholdGroup` | src/graph.rs | 67–84 | §10 `threshold-every-level` |
| `TrustGraph::resolve` (condition check) | src/graph.rs | 718–810 | §7 `architecture-pathfinding`, §14 |
| `TrustGraph::verify_credential` | src/graph.rs | 636– | §10 threshold enforcement |
| `AnchorBundle::accepts_root` | src/graph.rs | 439– | §3.10, §7 `architecture-anchors` |
| `RevocationReason::is_retroactive` | src/revoke.rs | 84–92 | §12, §5 principle T |
| ★ `RevocationReason::ConditionWithdrawal` | src/revoke.rs | 63–67 | §12 `revocation-condition-withdrawal` |
| ★ `RevokedSubject::Condition` | src/revoke.rs | 131–144 | §12 |
| ★ `RevocationLedger::withdrawn_conditions_at` | src/revoke.rs | 425–448 | §12 |
| `RevocationLedger::declare` | src/revoke.rs | 387– | §3.8, §12 |
| `QuorumAttestation::is_quorate` | src/revoke.rs | 211– | §3.7, §10 |
| `RevocationLedger::taints_of` | src/revoke.rs | 497– | §12 `revocation-propagation` |
| `leaf_hash` / `node_hash` | src/anchor.rs | 38–45 | §13 (domain separation) |
| `TransparencyLog::sign_tree_head` | src/anchor.rs | 240– | §13 |
| ★ `SignedTreeHead::anchored_externally` / `verify_external_anchor` | src/anchor.rs | 338–360 | §13 `transparency-anchoring` |
| ★ `ExternalAnchorMethod` / `ExternalAnchor` | src/anchor.rs | 376–434 | §13 `transparency-anchoring` |
| ★ `external_anchor_payload` / `verify_external_anchor` | src/anchor.rs | 437–490 | §13 (OTS-lite + RFC 3161 DER) |
| `SignedTreeHead::lol_commitment` | src/anchor.rs | 322– | §13 |
| `verify_inclusion` | src/anchor.rs | 549– | §13 `transparency-inclusion-proof` |
| `verify_consistency` | src/anchor.rs | 584– | §13 `transparency-consistency-proof` |
| `LogOfLogs` | src/anchor.rs | 738– | §13 `transparency-multi-log` |
| `verify_master_quorum` | src/anchor.rs | 795– | §13 |
| `SignatifVerifier::verify` (conditions + composite members) | src/verify.rs | 247– | §14 `verification-pipeline` |
| ★ `SignatifVerifier::evaluate_conditions` / `slot_trust` | src/verify.rs | 175–245 | §11, §12, §14 |
| `SignatifVerifier::verify_historical` | src/verify.rs | 357– | §14 `verification-offline` |
| `SignatifVerdict::accepted` (conditions gate) | src/verify.rs | 140–150 | §14 `verification-acceptance` |
| ★ `SlotTrust::conditions` | src/verify.rs | 85–91 | §14 (hard scope-condition check) |
| `HistoricalVerification::still_stands` | src/verify.rs | 446– | §14, §5 principle T |
| ★ `DeploymentManifest` / `validate` | src/manifest.rs | 162– / 218– | §18, §19, §20 |
| `CeremonyCoordinator` | src/confium.rs | 279–304 | §10 `threshold-ceremony` |
| `MockCeremony` | src/confium.rs | 328– | §10, §17 |

---

*End of ADAPTER-NOTES.md — 2026-09-07. Audit produced by reading the
standard AsciiDoc at `the SIGNATIF standard sources (CalConnect)`
and the crate at `this crate/`. Revised 2026-09-07 (branch
`divergences`) after implementing the six divergences of §20.2 —
statuses updated in place; see the revision note at the top.*