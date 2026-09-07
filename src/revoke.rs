//! Revocation: reason taxonomy (prospective vs retroactive/void-ab-initio),
//! distrust windows with cascading voiding inside the window and
//! re-validation outside it, and propagation to transitively bound
//! artifacts through the core's taint/provenance crates.
//!
//! PLAN.md (the corrected fraud/misissuance retroactivity model):
//! revocation is not one operation — **the reason determines
//! retroactivity**. Prospective reasons (key compromise after time T,
//! cessation, supersession, affiliation change) leave prior as-of
//! verifications valid: timestamping protects them, as in code signing.
//! Retroactive reasons (**misissuance, fraudulent issuance, authority
//! compromised during a window**) void validity **ab initio** (or from
//! window start): timestamping does NOT protect, exactly as browser
//! root-store distrust of a misissuing CA invalidates its timestamped
//! certificates.
//!
//! Distrust declarations carry an explicit **window `[start, end]`**:
//! things *inside* the window are voided, things *outside* it are
//! re-validated. Retroactive declarations are acts of
//! authority-over-authority: they require a quorate body
//! ([`QuorumAttestation`] — a threshold ceremony output), and
//! [`RevocationLedger::declare`] refuses them without one.
//!
//! Graph taint: marking a passport fraudulent is a *graph event*, not
//! just a trust-list event. [`RevocationLedger::taints_of`] traverses
//! the core's `ProvenanceGraph` downstream, so a recycled-content claim
//! built on stolen material collapses with its ancestors.

use std::collections::{BTreeMap, BTreeSet};

use unidpp_model::{Interval, PassportId, Timestamp};
use unidpp_transform::taint::KnownTaint;
use unidpp_transform::{ProvenanceGraph, Taint, TaintKind, TaintSet};

use crate::graph::NodeId;
use crate::keyring::{KeyId, KeyPair};
use crate::sign::{canonical_fields, SignatureSlot, SigningDomain};
use crate::SignatifError;

/// Why a subject is distrusted.
///
/// The taxonomy's decisive property is [`RevocationReason::is_retroactive`]:
/// prospective reasons act forward from a moment; retroactive reasons
/// void from the distrust window's start.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RevocationReason {
    // ---- Prospective: as-of-earlier verifications remain valid ----
    /// The key was compromised; trustworthy before `after`.
    KeyCompromise {
        /// When the compromise is judged to have occurred.
        after: Timestamp,
    },
    /// The authority ceased operating.
    Cessation,
    /// Superseded by another node (rotation).
    Supersession {
        /// Replacing node.
        by: NodeId,
    },
    /// Affiliation change (accreditation moved).
    AffiliationChange,
    // ---- Retroactive: void ab initio / from window start ----
    /// Misissuance: acts inside the window were wrongful from the start.
    Misissuance,
    /// Fraudulent issuance (misconduct, stolen material, forgery).
    FraudulentIssuance,
    /// The authority was compromised throughout a window; everything it
    /// issued inside the window is void.
    AuthorityCompromised {
        /// When compromise was detected (for the evidentiary reading).
        detected_at: Timestamp,
    },
}

impl RevocationReason {
    /// Whether this reason voids validity ab initio (from the distrust
    /// window's start) rather than prospectively.
    pub fn is_retroactive(&self) -> bool {
        matches!(
            self,
            RevocationReason::Misissuance
                | RevocationReason::FraudulentIssuance
                | RevocationReason::AuthorityCompromised { .. }
        )
    }

    /// Taxonomy token (stable for logs and reports).
    pub fn token(&self) -> &'static str {
        match self {
            RevocationReason::KeyCompromise { .. } => "key-compromise",
            RevocationReason::Cessation => "cessation",
            RevocationReason::Supersession { .. } => "supersession",
            RevocationReason::AffiliationChange => "affiliation-change",
            RevocationReason::Misissuance => "misissuance",
            RevocationReason::FraudulentIssuance => "fraudulent-issuance",
            RevocationReason::AuthorityCompromised { .. } => "authority-compromised",
        }
    }

    /// Map to the core's taint kind for propagation.
    pub fn taint_kind(&self) -> TaintKind {
        match self {
            RevocationReason::KeyCompromise { .. } => TaintKind::Known(KnownTaint::Compromised),
            RevocationReason::Cessation
            | RevocationReason::Supersession { .. }
            | RevocationReason::AffiliationChange => TaintKind::Known(KnownTaint::Revoked),
            RevocationReason::Misissuance | RevocationReason::AuthorityCompromised { .. } => {
                TaintKind::Known(KnownTaint::Misissued)
            }
            RevocationReason::FraudulentIssuance => TaintKind::Known(KnownTaint::Fraud),
        }
    }
}

/// What a revocation acts on.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RevokedSubject {
    /// A specific signing key.
    Key(KeyId),
    /// A whole authority node (all its keys and further delegations).
    Node(NodeId),
    /// A specific passport (e.g. a specific fraudulent issuance).
    Passport(PassportId),
}

impl RevokedSubject {
    /// Stable display.
    pub fn label(&self) -> String {
        match self {
            RevokedSubject::Key(k) => format!("key:{k}"),
            RevokedSubject::Node(n) => format!("node:{n}"),
            RevokedSubject::Passport(p) => format!("passport:{p}"),
        }
    }
}

/// A quorum attestation: the threshold-ceremony output that authorizes
/// an act of authority-over-authority (a retroactive distrust
/// declaration, a master-list dispute resolution).
///
/// The canonical signed statement is the quorum node id, threshold, and
/// the statement bytes, in the [`SigningDomain::Quorum`] domain. Slots
/// from `threshold` distinct member keys make the attestation quorate.
/// Member keys resolve through a key directory — the directory is what
/// a [`crate::graph::TrustGraph`] vends.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct QuorumAttestation {
    /// The quorum body (a threshold-group node id).
    pub quorum: NodeId,
    /// Distinct member signatures required.
    pub threshold: usize,
    /// Member signature slots.
    pub signatures: Vec<SignatureSlot>,
}

impl QuorumAttestation {
    /// Canonical bytes covered by the member signatures.
    pub fn canonical_bytes(statement: &[u8], quorum: &NodeId, threshold: usize) -> Vec<u8> {
        let mut fields = canonical_fields(&[quorum.as_str().as_bytes()]);
        let mut tail = Vec::with_capacity(4 + statement.len());
        tail.extend_from_slice(&(threshold as u32).to_le_bytes());
        tail.extend_from_slice(statement);
        fields.extend_from_slice(&tail);
        fields
    }

    /// Assemble an attestation from member keys.
    pub fn mint_sign(
        quorum: &NodeId,
        threshold: usize,
        statement: &[u8],
        member_keys: &[&KeyPair],
    ) -> Result<QuorumAttestation, SignatifError> {
        let payload = QuorumAttestation::canonical_bytes(statement, quorum, threshold);
        let mut signatures = Vec::new();
        for key in member_keys {
            signatures.push(SignatureSlot::sign(key, SigningDomain::Quorum, &payload)?);
        }
        Ok(QuorumAttestation {
            quorum: quorum.clone(),
            threshold,
            signatures,
        })
    }

    /// Whether at least `threshold` distinct member keys' slots verify
    /// (against the directory of registered member keys).
    pub fn is_quorate(
        &self,
        statement: &[u8],
        directory: &crate::graph::KeyDirectory,
    ) -> Result<bool, SignatifError> {
        let payload = QuorumAttestation::canonical_bytes(statement, &self.quorum, self.threshold);
        let mut verified: BTreeSet<&KeyId> = BTreeSet::new();
        for slot in &self.signatures {
            if let Some(public) = directory.resolve(&slot.key_id) {
                if slot.verify(SigningDomain::Quorum, &payload, public).is_ok() {
                    verified.insert(&slot.key_id);
                }
            }
        }
        Ok(verified.len() >= self.threshold)
    }
}

/// A distrust declaration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Revocation {
    /// What is being distrusted.
    pub subject: RevokedSubject,
    /// Why.
    pub reason: RevocationReason,
    /// When the declaration was made (the evidentiary cutoff: verifiers
    /// could not know it earlier).
    pub declared_at: Timestamp,
    /// Distrust window `[start, end]`. For retroactive reasons,
    /// artifacts dated inside the window are void ab initio and
    /// artifacts outside it are re-validated. For prospective reasons
    /// the window starts at the effect moment (key-compromise `after`,
    /// or `declared_at`).
    pub window: Interval,
    /// Declaring authority (superior/quorate body for retroactive acts).
    pub declared_by: NodeId,
    /// Quorum attestation (required for retroactive reasons).
    pub quorum: Option<QuorumAttestation>,
}

impl Revocation {
    /// Canonical statement bytes this revocation's quorum covers.
    pub fn statement_bytes(&self) -> Vec<u8> {
        canonical_fields(&[
            self.subject.label().as_bytes(),
            self.reason.token().as_bytes(),
            self.declared_by.as_str().as_bytes(),
            &self.window.from.secs.to_le_bytes(),
            &self
                .window
                .to
                .map(|t| t.secs)
                .unwrap_or(i64::MAX)
                .to_le_bytes(),
        ])
    }

    /// Whether an act/issuance dated `at` is voided by this revocation:
    /// containment in the distrust window. What the containment
    /// *means* differs by reason class:
    ///
    /// - retroactive reasons void everything dated **inside** the
    ///   window ab initio and re-validate what is outside it;
    /// - prospective reasons use the window as their effect interval
    ///   (`window.from` is the effect moment — the key-compromise
    ///   `after` or `declared_at` — and nothing dated before it is
    ///   voided; an explicit end models a temporary suspension that
    ///   re-validates).
    pub fn voids(&self, at: Timestamp) -> bool {
        self.window.contains(at)
    }

    /// Human-facing summary.
    pub fn summary(&self) -> String {
        format!(
            "{} {} [{}] declared by {} at {} ({})",
            if self.reason.is_retroactive() {
                "RETROACTIVE"
            } else {
                "prospective"
            },
            self.reason.token(),
            self.window,
            self.declared_by,
            self.declared_at,
            self.subject.label()
        )
    }
}

/// Standing of a subject at a moment, given the ledger's declarations.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Standing {
    /// No revocation touches the subject at this moment.
    Valid,
    /// Void from the start of the window (retroactive reason).
    VoidAbInitio {
        /// Why.
        reason: String,
        /// The voiding window.
        window: Interval,
    },
    /// Invalid from a moment onward (prospective reason); acts before
    /// it stand.
    SuspendedFrom {
        /// Why.
        reason: String,
        /// Effect moment.
        from: Timestamp,
    },
}

impl Standing {
    /// Whether the subject may act (or have acted) at the queried
    /// moment.
    pub fn is_valid(&self) -> bool {
        matches!(self, Standing::Valid)
    }

    /// Whether this is the void-ab-initio standing.
    pub fn voids_ab_initio(&self) -> bool {
        matches!(self, Standing::VoidAbInitio { .. })
    }
}

/// Which keys issued which passports (the join the ledger needs to
/// cascade key-level distrust onto artifacts).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IssuanceIndex {
    issuances: BTreeMap<PassportId, (Timestamp, KeyId)>,
}

impl IssuanceIndex {
    /// Empty index.
    pub fn new() -> IssuanceIndex {
        IssuanceIndex::default()
    }

    /// Record that `key_id` signed the issuance of `passport` at `at`.
    pub fn record(&mut self, passport: PassportId, at: Timestamp, key_id: KeyId) {
        self.issuances.insert(passport, (at, key_id));
    }

    /// The (moment, key) of a passport's issuance.
    pub fn issuance_of(&self, passport: &PassportId) -> Option<(Timestamp, &KeyId)> {
        self.issuances
            .get(passport)
            .map(|(t, k)| (*t, k))
    }

    /// All recorded passports.
    pub fn passports(&self) -> impl Iterator<Item = &PassportId> {
        self.issuances.keys()
    }
}

/// The revocation ledger: declarations plus their semantics.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RevocationLedger {
    revocations: Vec<Revocation>,
}

impl RevocationLedger {
    /// Empty ledger.
    pub fn new() -> RevocationLedger {
        RevocationLedger::default()
    }

    /// All declarations.
    pub fn revocations(&self) -> &[Revocation] {
        &self.revocations
    }

    /// Declare. Retroactive reasons require a quorum attestation
    /// (authority-over-authority is a threshold decision) — callers
    /// verify quorum separately with [`QuorumAttestation::is_quorate`]
    /// and pass `None` only when they mean the declaration to be
    /// rejected here.
    pub fn declare(&mut self, revocation: Revocation) -> Result<(), SignatifError> {
        if revocation.reason.is_retroactive() && revocation.quorum.is_none() {
            return Err(SignatifError::QuorumRequired {
                subject: revocation.subject.label(),
            });
        }
        self.revocations.push(revocation);
        Ok(())
    }

    /// Declarations against a subject (key-level declarations match both
    /// `Key` and the `Node` that owns it, via the node map).
    fn against_key<'a>(&'a self, key_id: &'a KeyId) -> impl Iterator<Item = &'a Revocation> {
        self.revocations
            .iter()
            .filter(move |r| match &r.subject {
                RevokedSubject::Key(k) => k == key_id,
                _ => false,
            })
    }

    fn against_passport<'a>(&'a self, passport: &'a PassportId) -> impl Iterator<Item = &'a Revocation> {
        self.revocations
            .iter()
            .filter(move |r| matches!(&r.subject, RevokedSubject::Passport(p) if p == passport))
    }

    /// Standing of a key's acts at `at`, restricted to declarations
    /// made by `known_by` (the evidentiary cutoff; pass `None` for the
    /// current-state reading over all declarations).
    pub fn key_standing_at(&self, key_id: &KeyId, at: Timestamp, known_by: Option<Timestamp>) -> Standing {
        let mut standing = Standing::Valid;
        for r in self.against_key(key_id) {
            if let Some(cutoff) = known_by {
                if r.declared_at > cutoff {
                    continue;
                }
            }
            let next = if r.voids(at) {
                if r.reason.is_retroactive() {
                    Standing::VoidAbInitio {
                        reason: r.reason.token().to_string(),
                        window: r.window,
                    }
                } else {
                    Standing::SuspendedFrom {
                        reason: r.reason.token().to_string(),
                        from: r.window.from,
                    }
                }
            } else {
                // Outside the window: re-validated. A retroactive
                // window does not leak past its end.
                continue;
            };
            // Void ab initio dominates; suspended dominates valid.
            let dominates = matches!(standing, Standing::Valid)
                || (matches!(standing, Standing::SuspendedFrom { .. })
                    && next.voids_ab_initio());
            if dominates {
                standing = next;
            }
        }
        standing
    }

    /// Current-state standing of a key's acts at `at` (all declarations).
    pub fn key_standing(&self, key_id: &KeyId, at: Timestamp) -> Standing {
        self.key_standing_at(key_id, at, None)
    }

    /// Taints effective on `passport` (its own plus ancestors', via the
    /// provenance DAG), restricted to declarations known by `known_by`
    /// (`None` = current state).
    ///
    /// A passport is tainted when its issuing key (or the passport
    /// itself) is voided at the passport's issuance moment: retroactive
    /// windows therefore invalidate timestamped-but-in-window artifacts
    /// and re-validate pre/post-window ones.
    pub fn taints_of(
        &self,
        passport: &PassportId,
        issuers: &IssuanceIndex,
        provenance: &ProvenanceGraph,
        known_by: Option<Timestamp>,
    ) -> TaintSet {
        // Collect direct taints for the subject and every ancestor.
        let mut sources: BTreeSet<PassportId> = provenance.ancestors(passport);
        sources.insert(passport.clone());
        let mut direct: BTreeMap<PassportId, TaintSet> = BTreeMap::new();
        for src in &sources {
            let mut ts = TaintSet::new();
            // Passport-level declarations.
            for r in self.against_passport(src) {
                if let Some(cutoff) = known_by {
                    if r.declared_at > cutoff {
                        continue;
                    }
                }
                let effective_at = issuers
                    .issuance_of(src)
                    .map(|(t, _)| t)
                    .unwrap_or(r.declared_at);
                if r.voids(effective_at) || !r.reason.is_retroactive() {
                    ts.add(Taint {
                        source: src.clone(),
                        kind: r.reason.taint_kind(),
                        reason: r.reason.token().to_string(),
                        at: r.declared_at,
                        window: if r.reason.is_retroactive() {
                            Some(r.window)
                        } else {
                            None
                        },
                    });
                }
            }
            // Key-level declarations against the issuing key.
            if let Some((issued_at, key_id)) = issuers.issuance_of(src) {
                for r in self.against_key(key_id) {
                    if let Some(cutoff) = known_by {
                        if r.declared_at > cutoff {
                            continue;
                        }
                    }
                    if r.voids(issued_at) {
                        ts.add(Taint {
                            source: src.clone(),
                            kind: r.reason.taint_kind(),
                            reason: r.reason.token().to_string(),
                            at: r.declared_at,
                            window: if r.reason.is_retroactive() {
                                Some(r.window)
                            } else {
                                None
                            },
                        });
                    }
                }
            }
            if !ts.is_empty() {
                direct.insert(src.clone(), ts);
            }
        }
        // The core's propagation does the downstream cascade.
        let mut out = TaintSet::new();
        for (src, ts) in &direct {
            if sources.contains(src) {
                out.merge(ts);
            }
        }
        out
    }

    /// Current-state taints (all declarations known).
    pub fn current_taints(
        &self,
        passport: &PassportId,
        issuers: &IssuanceIndex,
        provenance: &ProvenanceGraph,
    ) -> TaintSet {
        self.taints_of(passport, issuers, provenance, None)
    }

    /// Evidentiary taints: only declarations a diligent verifier could
    /// know at `at`.
    pub fn taints_known_at(
        &self,
        passport: &PassportId,
        issuers: &IssuanceIndex,
        provenance: &ProvenanceGraph,
        at: Timestamp,
    ) -> TaintSet {
        self.taints_of(passport, issuers, provenance, Some(at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyring::KeyPair;
    use crate::sign::Suite;

    fn t(secs: i64) -> Timestamp {
        Timestamp::from_secs(secs)
    }

    fn pid(n: u32) -> PassportId {
        PassportId::new(&format!("urn:unidpp:passport:b{n}")).unwrap()
    }

    fn quorum_for(statement: &[u8], n_members: usize) -> (QuorumAttestation, crate::graph::KeyDirectory) {
        let quorum = NodeId::new("super-quorum").unwrap();
        let members: Vec<KeyPair> = (0..n_members)
            .map(|i| KeyPair::seeded(Suite::Ed25519, format!("sq-{i}").as_bytes()).unwrap())
            .collect();
        let mut dir = crate::graph::KeyDirectory::new();
        for m in &members {
            dir.register(m.public());
        }
        let refs: Vec<&KeyPair> = members.iter().collect();
        let att = QuorumAttestation::mint_sign(&quorum, 2, statement, &refs).unwrap();
        (att, dir)
    }

    #[test]
    fn taxonomy_retroactivity() {
        assert!(RevocationReason::Misissuance.is_retroactive());
        assert!(RevocationReason::FraudulentIssuance.is_retroactive());
        assert!(RevocationReason::AuthorityCompromised { detected_at: t(1) }.is_retroactive());
        assert!(!RevocationReason::Cessation.is_retroactive());
        assert!(!RevocationReason::KeyCompromise { after: t(1) }.is_retroactive());
        assert_eq!(
            RevocationReason::FraudulentIssuance.taint_kind(),
            TaintKind::Known(KnownTaint::Fraud)
        );
        assert_eq!(RevocationReason::Misissuance.token(), "misissuance");
    }

    #[test]
    fn declare_requires_quorum_for_retroactive() {
        let mut ledger = RevocationLedger::new();
        let retro = Revocation {
            subject: RevokedSubject::Key(KeyId::new("k-abc").unwrap()),
            reason: RevocationReason::Misissuance,
            declared_at: t(1000),
            window: Interval::between(t(100), t(200)).unwrap(),
            declared_by: NodeId::new("super").unwrap(),
            quorum: None,
        };
        assert!(matches!(
            ledger.declare(retro.clone()),
            Err(SignatifError::QuorumRequired { .. })
        ));
        let statement = retro.statement_bytes();
        let (att, _dir) = quorum_for(&statement, 3);
        let mut retro = retro;
        retro.quorum = Some(att);
        assert!(ledger.declare(retro).is_ok());
        // Prospective needs no quorum.
        let pros = Revocation {
            subject: RevokedSubject::Key(KeyId::new("k-abc").unwrap()),
            reason: RevocationReason::Cessation,
            declared_at: t(1000),
            window: Interval::starting(t(1000)),
            declared_by: NodeId::new("super").unwrap(),
            quorum: None,
        };
        assert!(ledger.declare(pros).is_ok());
    }

    #[test]
    fn quorum_attestation_verifies() {
        let statement = b"declare misissuance".to_vec();
        let (att, dir) = quorum_for(&statement, 3);
        assert!(att.is_quorate(&statement, &dir).unwrap());
        // Tampered statement: not quorate.
        assert!(!att.is_quorate(b"other", &dir).unwrap());
        // Below threshold members.
        let quorum = NodeId::new("super-quorum").unwrap();
        let m0 = KeyPair::seeded(Suite::Ed25519, b"sq-0").unwrap();
        let solo = QuorumAttestation::mint_sign(&quorum, 2, &statement, &[&m0]).unwrap();
        assert!(!solo.is_quorate(&statement, &dir).unwrap());
        // Wrong-key directory.
        let empty = crate::graph::KeyDirectory::new();
        assert!(!att.is_quorate(&statement, &empty).unwrap());
    }

    #[test]
    fn window_voids_inside_revalidates_outside() {
        let mut ledger = RevocationLedger::new();
        let key = KeyId::new("k-abc").unwrap();
        let retro = Revocation {
            subject: RevokedSubject::Key(key.clone()),
            reason: RevocationReason::FraudulentIssuance,
            declared_at: t(1000),
            window: Interval::between(t(100), t(200)).unwrap(),
            declared_by: NodeId::new("super").unwrap(),
            quorum: None,
        };
        ledger.declare(retro).unwrap_err(); // no quorum; use Misissuance w/ quorum below
        let mut retro2 = Revocation {
            subject: RevokedSubject::Key(key.clone()),
            reason: RevocationReason::AuthorityCompromised { detected_at: t(1000) },
            declared_at: t(1000),
            window: Interval::between(t(100), t(200)).unwrap(),
            declared_by: NodeId::new("super").unwrap(),
            quorum: None,
        };
        // Retroactive still needs quorum — bypass for the window test by
        // seeding the ledger's vec directly through declare with quorum.
        let (att, _dir) = quorum_for(&retro2.statement_bytes(), 3);
        retro2.quorum = Some(att);
        ledger.declare(retro2).unwrap();

        // Inside window: void ab initio.
        assert!(ledger.key_standing(&key, t(150)).voids_ab_initio());
        // Before window: valid (re-validated outside).
        assert!(ledger.key_standing(&key, t(50)).is_valid());
        // After window end: valid again (re-validation).
        assert!(ledger.key_standing(&key, t(500)).is_valid());
        // Evidentiary cutoff: at t=150 nothing was declared yet.
        assert!(ledger
            .key_standing_at(&key, t(150), Some(t(999)))
            .is_valid());
    }

    #[test]
    fn prospective_stands_before_effect() {
        let mut ledger = RevocationLedger::new();
        let key = KeyId::new("k-abc").unwrap();
        ledger
            .declare(Revocation {
                subject: RevokedSubject::Key(key.clone()),
                reason: RevocationReason::KeyCompromise { after: t(300) },
                declared_at: t(300),
                window: Interval::starting(t(300)),
                declared_by: NodeId::new("root").unwrap(),
                quorum: None,
            })
            .unwrap();
        assert!(ledger.key_standing(&key, t(299)).is_valid());
        match ledger.key_standing(&key, t(400)) {
            Standing::SuspendedFrom { from, .. } => assert_eq!(from, t(300)),
            other => panic!("expected suspension, got {other:?}"),
        }
        assert!(!ledger.key_standing(&key, t(400)).voids_ab_initio());
    }

    #[test]
    fn taint_cascades_through_provenance() {
        // battery B0 (issued by bad key inside window) -> pack B1 (combine) -> module B2.
        let bad_key = KeyPair::seeded(Suite::EcdsaP256, b"bad-issuer").unwrap();
        let mut issuers = IssuanceIndex::new();
        issuers.record(pid(0), t(150), bad_key.key_id().clone());
        issuers.record(pid(1), t(160), bad_key.key_id().clone()); // clean sibling, same key
        let mut provenance = ProvenanceGraph::new();
        provenance.record_combine(pid(1), &[pid(0)]);

        let mut ledger = RevocationLedger::new();
        let mut retro = Revocation {
            subject: RevokedSubject::Key(bad_key.key_id().clone()),
            reason: RevocationReason::Misissuance,
            declared_at: t(1000),
            window: Interval::between(t(100), t(200)).unwrap(),
            declared_by: NodeId::new("super").unwrap(),
            quorum: None,
        };
        let (att, _dir) = quorum_for(&retro.statement_bytes(), 3);
        retro.quorum = Some(att);
        ledger.declare(retro).unwrap();

        // B0: issued inside window -> void ab initio.
        assert!(ledger.current_taints(&pid(0), &issuers, &provenance).voids_ab_initio());
        // B1: transitively bound to B0 -> cascading void.
        assert!(ledger.current_taints(&pid(1), &issuers, &provenance).voids_ab_initio());
        // Evidentiary: at t(170) nothing was declared.
        assert!(!ledger
            .taints_known_at(&pid(0), &issuers, &provenance, t(170))
            .voids_ab_initio());
        // A passport issued by the same key AFTER the window is re-validated.
        issuers.record(pid(2), t(500), bad_key.key_id().clone());
        assert!(!ledger.current_taints(&pid(2), &issuers, &provenance).voids_ab_initio());
        // ...but if it was built from tainted material, it is tainted
        // anyway (transitive binding).
        provenance.record_combine(pid(3), &[pid(1)]);
        issuers.record(pid(3), t(600), bad_key.key_id().clone());
        assert!(ledger.current_taints(&pid(3), &issuers, &provenance).voids_ab_initio());
    }
}
