//! The delegation trust graph: nodes, scoped edges, jurisdiction trust
//! lists, M-of-K master-list entries, and path-finding from an artifact
//! signature to a verifier's anchor bundle.
//!
//! Node kinds (the UniDPP design framework operating model — "jurisdictional trust
//! authorities (threshold groups, not single keys) → trust lists → a
//! globally multi-witnessed master list"):
//!
//! - [`NodeKind::Root`] — an anchor-bundle root (typically operated by a
//!   threshold/federated group; no single key, no single country);
//! - [`NodeKind::ThresholdGroup`] — an M-of-N group node: its registered
//!   keys are the members' verification keys, and anything signed "by
//!   the group" needs signatures from `threshold` distinct members;
//! - [`NodeKind::Delegated`] — an intermediate authority receiving a
//!   scoped delegation;
//! - [`NodeKind::End`] — a leaf signing key (e.g. an issuer's issuance
//!   key, an artifact signer).
//!
//! Edges are [`DelegationCredential`]s: parent-signed statements whose
//! [`crate::scope::DelegationScope`] may only narrow along a path.
//! Resolution ([`TrustGraph::resolve`]) finds a path from a root the
//! verifier's [`AnchorBundle`] accepts to the node owning a key id,
//! enforcing at every hop: the credential's signature (single or
//! threshold quorum), monotonic scope narrowing, and final scope match
//! against the concrete [`crate::scope::ScopeRequest`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use unidpp_model::Timestamp;

use crate::keyring::{KeyId, KeyPair, PublicKey};
use crate::scope::{DelegationScope, ScopeRequest};
use crate::sign::{canonical_fields, SignatureSlot, SigningDomain};
use crate::SignatifError;

/// A trust-graph node identifier (normalized lowercase slug).
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct NodeId(String);

impl NodeId {
    /// Construct (trim + lowercase + shape check).
    pub fn new(raw: &str) -> Result<NodeId, SignatifError> {
        let n = raw.trim().to_ascii_lowercase();
        if n.is_empty() || n.len() > 128 || !n.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(SignatifError::invalid(format!("bad node id `{raw}`")));
        }
        Ok(NodeId(n))
    }

    /// The id string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Kind of a trust-graph node.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NodeKind {
    /// An anchor-bundle root.
    Root,
    /// An M-of-N group: registered keys are the member verification
    /// keys; group-signed objects need `threshold` distinct member
    /// signatures.
    ThresholdGroup {
        /// Quorum threshold M.
        threshold: usize,
        /// Member node ids (the owners of the registered keys).
        members: BTreeSet<NodeId>,
    },
    /// An intermediate delegated authority.
    Delegated,
    /// A leaf signing key.
    End,
}

impl NodeKind {
    /// Whether this is [`NodeKind::Root`].
    pub fn is_root(&self) -> bool {
        matches!(self, NodeKind::Root)
    }
}

/// A public key registered to a node.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RegisteredKey {
    /// Content-derived key id.
    pub key_id: KeyId,
    /// The public key.
    pub public: PublicKey,
}

impl RegisteredKey {
    /// Register a key pair's public side.
    pub fn of(key: &KeyPair) -> RegisteredKey {
        RegisteredKey {
            key_id: key.key_id().clone(),
            public: *key.public(),
        }
    }
}

/// One trust-graph node.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DelegationNode {
    /// Node id.
    pub id: NodeId,
    /// Kind (root / threshold group / delegated / end).
    pub kind: NodeKind,
    /// Keys registered to this node.
    pub keys: Vec<RegisteredKey>,
    /// The node's party class (TR-1: the role in the world —
    /// regulator, manufacturer, conformity body…), orthogonal to
    /// the structural kind. Absent: undeclared.
    #[serde(default)]
    pub party: Option<crate::party::PartyClass>,
}

impl DelegationNode {
    /// New node of a kind with no keys.
    pub fn new(id: NodeId, kind: NodeKind) -> DelegationNode {
        DelegationNode {
            id,
            kind,
            keys: Vec::new(),
            party: None,
        }
    }

    /// Register a key (idempotent).
    pub fn register(&mut self, key: RegisteredKey) {
        if !self.keys.iter().any(|k| k.key_id == key.key_id) {
            self.keys.push(key);
        }
    }

    /// The registered key with this id, if any.
    pub fn key(&self, key_id: &KeyId) -> Option<&PublicKey> {
        self.keys
            .iter()
            .find(|k| &k.key_id == key_id)
            .map(|k| &k.public)
    }
}

/// A parent-signed scoped delegation statement.
///
/// Canonical signing input: length-prefixed `parent || child ||
/// scope-canonical-bytes`, in the [`SigningDomain::Delegation`] domain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DelegationCredential {
    /// Delegating node.
    pub parent: NodeId,
    /// Receiving node.
    pub child: NodeId,
    /// Scope granted (must narrow the parent's effective scope).
    pub scope: DelegationScope,
    /// Parent's signature slots (one suffices for a non-group parent;
    /// a `ThresholdGroup` parent needs its quorum).
    pub signatures: Vec<SignatureSlot>,
}

impl DelegationCredential {
    /// Canonical bytes covered by the credential's signatures.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_fields(&[
            self.parent.as_str().as_bytes(),
            self.child.as_str().as_bytes(),
            &self.scope.canonical_bytes(),
        ])
    }

    /// Mint a credential and sign it with one parent key.
    pub fn mint_sign(
        parent: &NodeId,
        child: &NodeId,
        scope: DelegationScope,
        parent_key: &KeyPair,
    ) -> Result<DelegationCredential, SignatifError> {
        let mut cred = DelegationCredential {
            parent: parent.clone(),
            child: child.clone(),
            scope,
            signatures: Vec::new(),
        };
        let slot = SignatureSlot::sign(
            parent_key,
            SigningDomain::Delegation,
            &cred.canonical_bytes(),
        )?;
        cred.signatures.push(slot);
        Ok(cred)
    }

    /// Append another parent signature slot (multi-suite co-signed
    /// delegation).
    pub fn co_sign_by(&mut self, parent_key: &KeyPair) -> Result<(), SignatifError> {
        let slot = SignatureSlot::sign(
            parent_key,
            SigningDomain::Delegation,
            &self.canonical_bytes(),
        )?;
        self.signatures.push(slot);
        Ok(())
    }
}

/// Directory of known public keys by key id (vended by the graph, or
/// assembled ad hoc).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KeyDirectory {
    keys: BTreeMap<KeyId, PublicKey>,
}

impl KeyDirectory {
    /// Empty directory.
    pub fn new() -> KeyDirectory {
        KeyDirectory::default()
    }

    /// Register a public key under its derived id.
    pub fn register(&mut self, public: &PublicKey) {
        self.keys.insert(KeyId::of(public), *public);
    }

    /// Resolve a key id to its public key.
    pub fn resolve(&self, key_id: &KeyId) -> Option<&PublicKey> {
        self.keys.get(key_id)
    }

    /// All registered ids.
    pub fn key_ids(&self) -> impl Iterator<Item = &KeyId> {
        self.keys.keys()
    }

    /// Number of registered keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// One entry in a jurisdiction's trust list.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrustListEntry {
    /// The trusted root node.
    pub node: NodeId,
    /// When the entry became effective.
    pub not_before: Timestamp,
    /// When the entry was superseded/withdrawn (None = current).
    pub superseded_at: Option<Timestamp>,
}

impl TrustListEntry {
    /// Whether the entry is in force at `t`.
    pub fn in_force_at(&self, t: Timestamp) -> bool {
        t >= self.not_before && self.superseded_at.map_or(true, |s| t < s)
    }
}

/// A jurisdiction's trust list: which roots that jurisdiction accepts.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrustList {
    /// Owning jurisdiction (e.g. "EU").
    pub jurisdiction: String,
    /// Entries by root node id.
    pub entries: BTreeMap<NodeId, TrustListEntry>,
}

impl TrustList {
    /// Empty list for a jurisdiction.
    pub fn new(jurisdiction: &str) -> TrustList {
        TrustList {
            jurisdiction: jurisdiction.trim().to_ascii_uppercase(),
            entries: BTreeMap::new(),
        }
    }

    /// Trust a root from `not_before`.
    pub fn trust(&mut self, node: NodeId, not_before: Timestamp) {
        let entry = TrustListEntry {
            node: node.clone(),
            not_before,
            superseded_at: None,
        };
        self.entries.insert(node, entry);
    }

    /// Withdraw (supersede) a root as of a moment (legal withdrawal
    /// track: trust-list update with grace handling done by callers).
    pub fn supersede(&mut self, node: &NodeId, at: Timestamp) {
        if let Some(e) = self.entries.get_mut(node) {
            e.superseded_at = Some(at);
        }
    }

    /// Whether the list accepts `node` at `t`.
    pub fn accepts_at(&self, node: &NodeId, t: Timestamp) -> bool {
        self.entries.get(node).is_some_and(|e| e.in_force_at(t))
    }
}

/// A witness's attestation of a master-list entry: a signature over
/// `node-id || at` in the [`SigningDomain::MasterListWitness`] domain,
/// made with the witness's registered key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WitnessAttestation {
    /// Witness node id.
    pub witness: NodeId,
    /// Attestation moment.
    pub at: Timestamp,
    /// The witness's signature slot.
    pub slot: SignatureSlot,
}

impl WitnessAttestation {
    /// Canonical signed bytes.
    pub fn canonical_bytes(node: &NodeId, at: Timestamp) -> Vec<u8> {
        canonical_fields(&[
            node.as_str().as_bytes(),
            &at.secs.to_le_bytes(),
            &at.nanos.to_le_bytes(),
        ])
    }

    /// Mint an attestation for `node` with a witness key.
    pub fn mint_sign(
        witness: &NodeId,
        node: &NodeId,
        at: Timestamp,
        witness_key: &KeyPair,
    ) -> Result<WitnessAttestation, SignatifError> {
        let payload = WitnessAttestation::canonical_bytes(node, at);
        Ok(WitnessAttestation {
            witness: witness.clone(),
            at,
            slot: SignatureSlot::sign(witness_key, SigningDomain::MasterListWitness, &payload)?,
        })
    }
}

/// A master-list entry: independent witnesses attesting a root.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MasterListEntry {
    /// The attested root node.
    pub node: NodeId,
    /// Witness attestations (K possible, M required).
    pub attestations: Vec<WitnessAttestation>,
}

impl MasterListEntry {
    /// Count distinct witnesses whose attestation verifies against the
    /// given witness keys.
    pub fn verified_witnesses(&self, witnesses: &BTreeMap<NodeId, PublicKey>) -> usize {
        let mut verified: BTreeSet<&NodeId> = BTreeSet::new();
        for att in &self.attestations {
            let key = match witnesses.get(&att.witness) {
                Some(k) => k,
                None => continue,
            };
            let payload = WitnessAttestation::canonical_bytes(&self.node, att.at);
            if att
                .slot
                .verify(SigningDomain::MasterListWitness, &payload, key)
                .is_ok()
            {
                verified.insert(&att.witness);
            }
        }
        verified.len()
    }

    /// Whether the entry meets the M-of-K quorum under `witnesses`.
    pub fn accepted(&self, m: usize, witnesses: &BTreeMap<NodeId, PublicKey>) -> bool {
        self.verified_witnesses(witnesses) >= m
    }
}

/// The globally multi-witnessed master list (M-of-K independent
/// witnesses — the log-of-logs' trust analogue).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MasterList {
    /// Required distinct verifying witnesses (M).
    pub m: usize,
    /// Total witnesses (K).
    pub k: usize,
    /// Witness node id → verification key.
    pub witnesses: BTreeMap<NodeId, PublicKey>,
    /// Entries by root node id.
    pub entries: BTreeMap<NodeId, MasterListEntry>,
}

impl MasterList {
    /// New master list over `witnesses` requiring `m` of them.
    pub fn new(m: usize, witnesses: BTreeMap<NodeId, PublicKey>) -> MasterList {
        let k = witnesses.len();
        MasterList {
            m,
            k,
            witnesses,
            entries: BTreeMap::new(),
        }
    }

    /// Insert/replace an entry.
    pub fn upsert(&mut self, entry: MasterListEntry) {
        self.entries.insert(entry.node.clone(), entry);
    }

    /// Whether `node` is quorately attested.
    pub fn accepts(&self, node: &NodeId) -> bool {
        self.entries
            .get(node)
            .is_some_and(|e| e.accepted(self.m, &self.witnesses))
    }
}

/// A verifier's anchor bundle: jurisdiction trust lists plus the master
/// list. Path-finding terminates only at roots this bundle accepts.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AnchorBundle {
    /// The verifier's jurisdiction.
    pub jurisdiction: String,
    /// Trust lists consulted (own jurisdiction first by convention).
    pub trust_lists: Vec<TrustList>,
    /// The multi-witnessed master list.
    pub master: MasterList,
}

impl AnchorBundle {
    /// Whether the bundle anchors `node` at `at`: a trust list in force
    /// AND a quorate master-list entry (M-of-K witnesses).
    pub fn accepts_root(&self, node: &NodeId, at: Timestamp) -> Result<(), SignatifError> {
        let listed = self.trust_lists.iter().any(|l| l.accepts_at(node, at));
        if !listed {
            return Err(SignatifError::Trust(format!(
                "root `{node}` is not in any trust list in force at {at}"
            )));
        }
        if !self.master.accepts(node) {
            return Err(SignatifError::Trust(format!(
                "root `{node}` lacks a {}/{} master-list witness quorum",
                self.master.m, self.master.k
            )));
        }
        Ok(())
    }
}

/// The resolved root-to-key path.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrustPath {
    /// The anchored root the path starts from.
    pub root: NodeId,
    /// The end node reached (owner of the signing key).
    pub end: NodeId,
    /// Credentials in root→end order.
    pub credentials: Vec<DelegationCredential>,
    /// Intersection of all scopes along the path (monotonic narrowing).
    pub effective_scope: DelegationScope,
}

impl TrustPath {
    /// Number of hops.
    pub fn hops(&self) -> usize {
        self.credentials.len()
    }
}

/// A trust graph: nodes plus scoped delegation edges forming a DAG.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrustGraph {
    nodes: BTreeMap<NodeId, DelegationNode>,
    edges: Vec<DelegationCredential>,
}

impl TrustGraph {
    /// Empty graph.
    pub fn new() -> TrustGraph {
        TrustGraph::default()
    }

    /// Insert a node (idempotent on id; a second insert is ignored).
    pub fn add_node(&mut self, node: DelegationNode) {
        self.nodes.entry(node.id.clone()).or_insert(node);
    }

    /// Insert a delegation credential as an edge. Validates endpoints
    /// exist, the child is not an ancestor of the parent (DAG
    /// invariant), and the scope is not a contradiction. Signature
    /// validity is *not* checked here — resolution checks it, so tests
    /// can build graphs with bad credentials.
    pub fn add_edge(&mut self, credential: DelegationCredential) -> Result<(), SignatifError> {
        if !self.nodes.contains_key(&credential.parent) {
            return Err(SignatifError::Unknown {
                kind: "node",
                id: credential.parent.to_string(),
            });
        }
        if !self.nodes.contains_key(&credential.child) {
            return Err(SignatifError::Unknown {
                kind: "node",
                id: credential.child.to_string(),
            });
        }
        if credential.scope.is_contradiction() {
            return Err(SignatifError::ScopeViolation(format!(
                "credential {} -> {} carries a contradictory scope",
                credential.parent, credential.child
            )));
        }
        if credential.signatures.is_empty() {
            return Err(SignatifError::CredentialSignatureInvalid {
                parent: credential.parent.to_string(),
                child: credential.child.to_string(),
            });
        }
        if self.reaches(&credential.child, &credential.parent) {
            return Err(SignatifError::Validation(format!(
                "edge {} -> {} would close a cycle (trust graph must stay a DAG)",
                credential.parent, credential.child
            )));
        }
        self.edges.push(credential);
        Ok(())
    }

    /// The node with this id.
    pub fn node(&self, id: &NodeId) -> Option<&DelegationNode> {
        self.nodes.get(id)
    }

    /// All nodes (in id order).
    pub fn nodes(&self) -> impl Iterator<Item = &DelegationNode> {
        self.nodes.values()
    }

    /// Mutable node lookup (used by services that merge keys onto an
    /// existing node without going through `add_node`, which is
    /// idempotent and ignores subsequent inserts). Returns `None`
    /// when the node does not exist.
    pub fn node_mut(&mut self, id: &NodeId) -> Option<&mut DelegationNode> {
        self.nodes.get_mut(id)
    }

    /// Node count.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Edge count.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// All edges.
    pub fn edges(&self) -> &[DelegationCredential] {
        &self.edges
    }

    /// Ids of edges from `parent`.
    fn edge_ids_from(&self, parent: &NodeId) -> Vec<usize> {
        self.edges
            .iter()
            .enumerate()
            .filter(|(_, e)| &e.parent == parent)
            .map(|(i, _)| i)
            .collect()
    }

    fn reaches(&self, from: &NodeId, to: &NodeId) -> bool {
        let mut seen = BTreeSet::new();
        let mut stack = vec![from.clone()];
        while let Some(n) = stack.pop() {
            if &n == to {
                return true;
            }
            if !seen.insert(n.clone()) {
                continue;
            }
            for e in &self.edges {
                if e.parent == n {
                    stack.push(e.child.clone());
                }
            }
        }
        false
    }

    /// Root nodes in id order.
    pub fn roots(&self) -> Vec<NodeId> {
        self.nodes
            .values()
            .filter(|n| n.kind.is_root())
            .map(|n| n.id.clone())
            .collect()
    }

    /// Test support: drop all but the first `n` edges (simulates a
    /// graph where the anchored path was never granted).
    #[doc(hidden)]
    pub fn truncate_edges_for_test(&mut self, n: usize) {
        self.edges.truncate(n);
    }

    /// The node owning a key id, if any.
    pub fn node_for_key(&self, key_id: &KeyId) -> Option<NodeId> {
        self.nodes
            .values()
            .find(|n| n.key(key_id).is_some())
            .map(|n| n.id.clone())
    }

    /// A key directory over every registered key in the graph.
    pub fn key_directory(&self) -> KeyDirectory {
        let mut dir = KeyDirectory::new();
        for node in self.nodes.values() {
            for key in &node.keys {
                dir.keys.insert(key.key_id.clone(), key.public);
            }
        }
        dir
    }

    /// Verify a credential against its parent node's registration.
    ///
    /// Non-group parents: at least one verifying slot by a registered
    /// parent key. Threshold-group parents: at least `threshold`
    /// *distinct* member keys with verifying slots.
    pub fn verify_credential(&self, cred: &DelegationCredential) -> Result<(), SignatifError> {
        let parent = self
            .node(&cred.parent)
            .ok_or_else(|| SignatifError::Unknown {
                kind: "node",
                id: cred.parent.to_string(),
            })?;
        let payload = cred.canonical_bytes();
        let mut verified_keys: BTreeSet<KeyId> = BTreeSet::new();
        for slot in &cred.signatures {
            if let Some(public) = parent.key(&slot.key_id) {
                if slot
                    .verify(SigningDomain::Delegation, &payload, public)
                    .is_ok()
                {
                    verified_keys.insert(slot.key_id.clone());
                }
            }
        }
        let ok = match &parent.kind {
            NodeKind::ThresholdGroup { threshold, .. } => verified_keys.len() >= *threshold,
            _ => !verified_keys.is_empty(),
        };
        if ok {
            Ok(())
        } else {
            Err(SignatifError::CredentialSignatureInvalid {
                parent: cred.parent.to_string(),
                child: cred.child.to_string(),
            })
        }
    }

    /// Enumerate simple paths `from → to`, as edge indices in walk
    /// order, deterministically sorted by (length, indices).
    pub fn paths(&self, from: &NodeId, to: &NodeId) -> Vec<Vec<usize>> {
        let mut found = Vec::new();
        let mut current: Vec<usize> = Vec::new();
        let mut visited: BTreeSet<NodeId> = BTreeSet::from([from.clone()]);
        self.dfs(from, to, &mut current, &mut visited, &mut found);
        found.sort();
        found
    }

    fn dfs(
        &self,
        at: &NodeId,
        to: &NodeId,
        current: &mut Vec<usize>,
        visited: &mut BTreeSet<NodeId>,
        found: &mut Vec<Vec<usize>>,
    ) {
        if at == to {
            found.push(current.clone());
            return;
        }
        for i in self.edge_ids_from(at) {
            let child = self.edges[i].child.clone();
            if visited.contains(&child) {
                continue;
            }
            visited.insert(child.clone());
            current.push(i);
            self.dfs(&child, to, current, visited, found);
            current.pop();
            visited.remove(&child);
        }
    }

    /// Resolve a signing key to a trust path from an anchored root.
    ///
    /// Checks, per candidate path (deterministic order): every
    /// credential verifies against its parent node (single or threshold
    /// quorum); scopes narrow monotonically (layers intersect,
    /// conditions union); the effective scope admits `request` on all
    /// four layers **and** every executable condition holds for the
    /// request; the start root is accepted by `bundle` at
    /// `request.at`.
    ///
    /// Errors distinguish the failure classes (no path, scope
    /// exclusion, scope condition, credential signature) so callers can
    /// grade the result.
    pub fn resolve(
        &self,
        key_id: &KeyId,
        request: &ScopeRequest,
        bundle: &AnchorBundle,
    ) -> Result<TrustPath, SignatifError> {
        let end = self
            .node_for_key(key_id)
            .ok_or_else(|| SignatifError::NoTrustPath {
                key_id: key_id.to_string(),
            })?;

        let mut best_failure: Option<SignatifError> = None;
        let note = |err: SignatifError, best: &mut Option<SignatifError>| {
            let rank = |e: &SignatifError| match e {
                SignatifError::ScopeExcluded { .. }
                | SignatifError::ScopeConditionFailed { .. } => 3,
                SignatifError::CredentialSignatureInvalid { .. } => 2,
                SignatifError::ScopeViolation(_) => 1,
                _ => 0,
            };
            let replace = match best {
                None => true,
                Some(b) => rank(&err) > rank(b),
            };
            if replace {
                *best = Some(err);
            }
        };

        for root in self.roots() {
            for path in self.paths(&root, &end) {
                if let Err(e) = bundle.accepts_root(&root, request.at) {
                    note(e, &mut best_failure);
                    continue;
                }
                let mut effective = DelegationScope::unconstrained();
                let mut sig_ok = true;
                for &i in &path {
                    let cred = &self.edges[i];
                    if let Err(e) = self.verify_credential(cred) {
                        note(e, &mut best_failure);
                        sig_ok = false;
                        break;
                    }
                    match effective.narrow(&cred.scope) {
                        Ok(next) => effective = next,
                        Err(e) => {
                            note(e, &mut best_failure);
                            sig_ok = false;
                            break;
                        }
                    }
                }
                if !sig_ok {
                    continue;
                }
                if let Some(layer) = effective.rejecting_layer(request) {
                    note(
                        SignatifError::ScopeExcluded {
                            key_id: key_id.to_string(),
                            detail: format!(
                                "effective scope rejects the `{layer}` layer of the request"
                            ),
                        },
                        &mut best_failure,
                    );
                    continue;
                }
                // Hard check: the effective scope's executable
                // conditions must hold for this request (CC/SIGNATIF
                // §14 `tab-pipeline-checks` — evaluated at
                // verification time, with the typed
                // `scope_condition_failed` reason).
                if let Some(condition) = effective.first_failed_condition(request) {
                    note(
                        SignatifError::ScopeConditionFailed {
                            condition: condition.clone(),
                        },
                        &mut best_failure,
                    );
                    continue;
                }
                return Ok(TrustPath {
                    root,
                    end,
                    credentials: path.iter().map(|&i| self.edges[i].clone()).collect(),
                    effective_scope: effective,
                });
            }
        }
        Err(best_failure.unwrap_or(SignatifError::NoTrustPath {
            key_id: key_id.to_string(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::DelegationScope;
    use crate::sign::Suite;
    use unidpp_model::Interval;

    fn t(secs: i64) -> Timestamp {
        Timestamp::from_secs(secs)
    }

    struct Fixture {
        graph: TrustGraph,
        root: NodeId,
        mid: NodeId,
        end: NodeId,
        root_key: KeyPair,
        mid_key: KeyPair,
        end_key: KeyPair,
    }

    fn fixture() -> Fixture {
        let root = NodeId::new("eu-root").unwrap();
        let mid = NodeId::new("eu-notified").unwrap();
        let end = NodeId::new("issuer-key-a").unwrap();
        let root_key = KeyPair::seeded(Suite::Ed25519, b"root").unwrap();
        let mid_key = KeyPair::seeded(Suite::EcdsaP256, b"mid").unwrap();
        let end_key = KeyPair::seeded(Suite::Ed25519, b"end").unwrap();

        let mut graph = TrustGraph::new();
        let mut root_node = DelegationNode::new(root.clone(), NodeKind::Root);
        root_node.register(RegisteredKey::of(&root_key));
        graph.add_node(root_node);
        let mut mid_node = DelegationNode::new(mid.clone(), NodeKind::Delegated);
        mid_node.register(RegisteredKey::of(&mid_key));
        graph.add_node(mid_node);
        let mut end_node = DelegationNode::new(end.clone(), NodeKind::End);
        end_node.register(RegisteredKey::of(&end_key));
        graph.add_node(end_node);

        let wide = DelegationScope::unconstrained()
            .authority(["eu"])
            .product_group(["batteries", "electronics"]);
        let narrow = DelegationScope::unconstrained()
            .authority(["eu"])
            .product_group(["batteries"]);
        let e1 = DelegationCredential::mint_sign(&root, &mid, wide, &root_key).unwrap();
        let e2 = DelegationCredential::mint_sign(&mid, &end, narrow, &mid_key).unwrap();
        graph.add_edge(e1).unwrap();
        graph.add_edge(e2).unwrap();
        Fixture {
            graph,
            root,
            mid,
            end,
            root_key,
            mid_key,
            end_key,
        }
    }

    fn bundle(fx: &Fixture) -> AnchorBundle {
        let mut list = TrustList::new("EU");
        list.trust(fx.root.clone(), t(0));
        let w1 = NodeId::new("witness-1").unwrap();
        let w2 = NodeId::new("witness-2").unwrap();
        let w3 = NodeId::new("witness-3").unwrap();
        let k1 = KeyPair::seeded(Suite::Ed25519, b"w1").unwrap();
        let k2 = KeyPair::seeded(Suite::Ed25519, b"w2").unwrap();
        let k3 = KeyPair::seeded(Suite::Ed25519, b"w3").unwrap();
        let mut witnesses = BTreeMap::new();
        witnesses.insert(w1.clone(), *k1.public());
        witnesses.insert(w2.clone(), *k2.public());
        witnesses.insert(w3.clone(), *k3.public());
        let mut master = MasterList::new(2, witnesses);
        let mut entry = MasterListEntry {
            node: fx.root.clone(),
            attestations: vec![
                WitnessAttestation::mint_sign(&w1, &fx.root, t(0), &k1).unwrap(),
                WitnessAttestation::mint_sign(&w2, &fx.root, t(0), &k2).unwrap(),
            ],
        };
        // A third attestation with the wrong key must not count.
        entry
            .attestations
            .push(WitnessAttestation::mint_sign(&w3, &fx.root, t(0), &k1).unwrap());
        master.upsert(entry);
        AnchorBundle {
            jurisdiction: "EU".into(),
            trust_lists: vec![list],
            master,
        }
    }

    #[test]
    fn resolve_in_scope_path() {
        let fx = fixture();
        let b = bundle(&fx);
        let req = ScopeRequest::new("eu", "urn:unidpp:profile:eu-batt@3", "batteries", t(500));
        let path = fx.graph.resolve(fx.end_key.key_id(), &req, &b).unwrap();
        assert_eq!(path.root, fx.root);
        assert_eq!(path.end, fx.end);
        assert_eq!(path.hops(), 2);
        assert!(path.effective_scope.matches(&req));
        // The wider grant survives in the first credential, narrowed by
        // the second.
        assert_eq!(
            path.credentials[0].scope.product_group,
            crate::scope::LayerConstraint::only(["batteries", "electronics"])
        );
    }

    #[test]
    fn resolve_out_of_scope_product_group_fails() {
        let fx = fixture();
        let b = bundle(&fx);
        let req = ScopeRequest::new("eu", "urn:unidpp:profile:eu-batt@3", "textiles", t(500));
        let err = fx.graph.resolve(fx.end_key.key_id(), &req, &b).unwrap_err();
        match err {
            SignatifError::ScopeExcluded { key_id, detail } => {
                assert_eq!(key_id, fx.end_key.key_id().to_string());
                assert!(detail.contains("product-group"), "{detail}");
            }
            other => panic!("expected ScopeExcluded, got {other:?}"),
        }
    }

    #[test]
    fn resolve_rejects_forged_credential() {
        let fx = fixture();
        let b = bundle(&fx);
        // Replace the mid->end credential with one signed by a rogue key.
        let rogue = KeyPair::seeded(Suite::EcdsaP256, b"rogue").unwrap();
        let forged = DelegationCredential::mint_sign(
            &fx.mid,
            &fx.end,
            DelegationScope::unconstrained()
                .authority(["eu"])
                .product_group(["batteries"]),
            &rogue,
        )
        .unwrap();
        let mut g = fx.graph.clone();
        g.edges.clear();
        g.add_edge(fx.graph.edges()[0].clone()).unwrap();
        g.add_edge(forged).unwrap();
        let req = ScopeRequest::new("eu", "urn:unidpp:profile:eu-batt@3", "batteries", t(500));
        let err = g.resolve(fx.end_key.key_id(), &req, &b).unwrap_err();
        assert!(matches!(
            err,
            SignatifError::CredentialSignatureInvalid { .. }
        ));
        // The direct-path variant must also fail when the *first* hop
        // is forged.
        let rogue2 = KeyPair::seeded(Suite::Ed25519, b"rogue2").unwrap();
        let mut g2 = fx.graph.clone();
        g2.edges.clear();
        let forged2 = DelegationCredential::mint_sign(
            &fx.root,
            &fx.mid,
            DelegationScope::unconstrained()
                .authority(["eu"])
                .product_group(["batteries", "electronics"]),
            &rogue2,
        )
        .unwrap();
        g2.add_edge(forged2).unwrap();
        g2.add_edge(fx.graph.edges()[1].clone()).unwrap();
        assert!(matches!(
            g2.resolve(fx.end_key.key_id(), &req, &b),
            Err(SignatifError::CredentialSignatureInvalid { .. })
        ));
    }

    #[test]
    fn dag_enforced_and_unknown_nodes_rejected() {
        let fx = fixture();
        let mut g = fx.graph.clone();
        // end -> mid would close a cycle.
        let back = DelegationCredential::mint_sign(
            &fx.end,
            &fx.mid,
            DelegationScope::unconstrained(),
            &fx.end_key,
        )
        .unwrap();
        assert!(matches!(
            g.add_edge(back),
            Err(SignatifError::Validation(_))
        ));
        let ghost = NodeId::new("ghost").unwrap();
        let e = DelegationCredential::mint_sign(
            &ghost,
            &fx.mid,
            DelegationScope::unconstrained(),
            &fx.root_key,
        )
        .unwrap();
        assert!(matches!(g.add_edge(e), Err(SignatifError::Unknown { .. })));
        let unsig = DelegationCredential {
            parent: fx.root.clone(),
            child: fx.mid.clone(),
            scope: DelegationScope::unconstrained(),
            signatures: vec![],
        };
        assert!(matches!(
            g.add_edge(unsig),
            Err(SignatifError::CredentialSignatureInvalid { .. })
        ));
    }

    #[test]
    fn threshold_group_quorum_on_credentials() {
        let group = NodeId::new("root-group").unwrap();
        let child = NodeId::new("child").unwrap();
        let m1 = KeyPair::seeded(Suite::EcdsaP256, b"m1").unwrap();
        let m2 = KeyPair::seeded(Suite::EcdsaP256, b"m2").unwrap();
        let m3 = KeyPair::seeded(Suite::EcdsaP256, b"m3").unwrap();
        let mut gnode = DelegationNode::new(
            group.clone(),
            NodeKind::ThresholdGroup {
                threshold: 2,
                members: BTreeSet::from([NodeId::new("m1").unwrap(), NodeId::new("m2").unwrap()]),
            },
        );
        gnode.register(RegisteredKey::of(&m1));
        gnode.register(RegisteredKey::of(&m2));
        gnode.register(RegisteredKey::of(&m3));
        let mut graph = TrustGraph::new();
        graph.add_node(gnode);
        let mut cnode = DelegationNode::new(child.clone(), NodeKind::Delegated);
        let ckey = KeyPair::seeded(Suite::Ed25519, b"ck").unwrap();
        cnode.register(RegisteredKey::of(&ckey));
        graph.add_node(cnode);

        // One member signature: below quorum.
        let one = DelegationCredential::mint_sign(
            &group,
            &child,
            DelegationScope::unconstrained().authority(["eu"]),
            &m1,
        )
        .unwrap();
        assert!(matches!(
            graph.verify_credential(&one),
            Err(SignatifError::CredentialSignatureInvalid { .. })
        ));
        // Two distinct members: quorate (even multi-suite).
        let mut two = one.clone();
        two.co_sign_by(&m3).unwrap();
        assert!(graph.verify_credential(&two).is_ok());
        // Same member signing twice does not reach quorum.
        let mut twice = one.clone();
        twice.co_sign_by(&m1).unwrap();
        assert!(matches!(
            graph.verify_credential(&twice),
            Err(SignatifError::CredentialSignatureInvalid { .. })
        ));
    }

    #[test]
    fn master_list_quorum_and_trust_list_timing() {
        let fx = fixture();
        let mut b = bundle(&fx);
        // Two verifying witnesses: accepted (m=2).
        assert!(b.accepts_root(&fx.root, t(10)).is_ok());
        // Drop two attestations (the third was signed with the wrong
        // key and never counted): below quorum.
        b.master
            .entries
            .get_mut(&fx.root)
            .unwrap()
            .attestations
            .pop();
        b.master
            .entries
            .get_mut(&fx.root)
            .unwrap()
            .attestations
            .pop();
        assert!(matches!(
            b.accepts_root(&fx.root, t(10)),
            Err(SignatifError::Trust(_))
        ));
        // Trust list superseded: not in force past the moment.
        let mut b2 = bundle(&fx);
        b2.trust_lists[0].supersede(&fx.root, t(1000));
        assert!(matches!(
            b2.accepts_root(&fx.root, t(2000)),
            Err(SignatifError::Trust(_))
        ));
        assert!(b2.accepts_root(&fx.root, t(999)).is_ok());
        // Unknown root.
        let ghost = NodeId::new("ghost-root").unwrap();
        assert!(matches!(
            b2.accepts_root(&ghost, t(1)),
            Err(SignatifError::Trust(_))
        ));
    }

    #[test]
    fn key_directory_and_node_for_key() {
        let fx = fixture();
        let dir = fx.graph.key_directory();
        assert_eq!(dir.len(), 3);
        assert!(dir.resolve(fx.end_key.key_id()).is_some());
        assert_eq!(
            fx.graph.node_for_key(fx.mid_key.key_id()),
            Some(fx.mid.clone())
        );
        let unknown = KeyId::new("k-0000000000000000").unwrap();
        assert!(fx.graph.node_for_key(&unknown).is_none());
        assert!(matches!(
            fx.graph.resolve(
                &unknown,
                &ScopeRequest::new("eu", "p@1", "batteries", t(1)),
                &bundle(&fx)
            ),
            Err(SignatifError::NoTrustPath { .. })
        ));
    }

    #[test]
    fn window_scope_narrows_on_path() {
        let fx = fixture();
        let mut g = fx.graph.clone();
        // Re-issue mid->end with a bounded window.
        let scoped = DelegationScope::unconstrained()
            .authority(["eu"])
            .product_group(["batteries"])
            .within(Interval::between(t(100), t(200)).unwrap());
        let cred = DelegationCredential::mint_sign(&fx.mid, &fx.end, scoped, &fx.mid_key).unwrap();
        g.edges.clear();
        g.add_edge(fx.graph.edges()[0].clone()).unwrap();
        g.add_edge(cred).unwrap();
        let b = bundle(&fx);
        let inside = ScopeRequest::new("eu", "p@1", "batteries", t(150));
        assert!(g.resolve(fx.end_key.key_id(), &inside, &b).is_ok());
        let outside = ScopeRequest::new("eu", "p@1", "batteries", t(500));
        let err = g.resolve(fx.end_key.key_id(), &outside, &b).unwrap_err();
        assert!(matches!(err, SignatifError::ScopeExcluded { .. }));
    }

    #[test]
    fn resolve_enforces_scope_conditions() {
        use crate::scope::ScopeCondition;
        let fx = fixture();
        let mut g = fx.graph.clone();
        // Re-issue mid->end with an executable attribute condition: the
        // delegation only covers LFP batteries.
        let scoped = DelegationScope::unconstrained()
            .authority(["eu"])
            .product_group(["batteries"])
            .condition(ScopeCondition::Attribute {
                key: "battery-chemistry".into(),
                allowed_values: ["lfp"].into_iter().map(Into::into).collect(),
            });
        let cred = DelegationCredential::mint_sign(&fx.mid, &fx.end, scoped, &fx.mid_key).unwrap();
        g.edges.clear();
        g.add_edge(fx.graph.edges()[0].clone()).unwrap();
        g.add_edge(cred).unwrap();
        let b = bundle(&fx);

        // Condition met (attribute recorded, allowed value): path resolves
        // and the effective scope carries the condition.
        let ok = ScopeRequest::new("eu", "p@1", "batteries", t(500))
            .with_attribute("battery-chemistry", "lfp");
        let path = g.resolve(fx.end_key.key_id(), &ok, &b).unwrap();
        assert_eq!(path.effective_scope.conditions.len(), 1);

        // Condition failed (wrong value): the typed failure reason.
        let wrong = ScopeRequest::new("eu", "p@1", "batteries", t(500))
            .with_attribute("battery-chemistry", "nmc");
        match g.resolve(fx.end_key.key_id(), &wrong, &b).unwrap_err() {
            SignatifError::ScopeConditionFailed { condition } => {
                assert!(matches!(condition, ScopeCondition::Attribute { .. }));
            }
            other => panic!("expected ScopeConditionFailed, got {other:?}"),
        }

        // Condition unresolvable (attribute not carried): fails closed.
        let bare = ScopeRequest::new("eu", "p@1", "batteries", t(500));
        assert!(matches!(
            g.resolve(fx.end_key.key_id(), &bare, &b).unwrap_err(),
            SignatifError::ScopeConditionFailed { .. }
        ));

        // Predicate conditions consult the request's recorded outcomes.
        let mut g2 = fx.graph.clone();
        let scoped_pred = DelegationScope::unconstrained()
            .authority(["eu"])
            .product_group(["batteries"])
            .condition(ScopeCondition::Predicate {
                expression_ref: "urn:rule:audit".into(),
            });
        let cred2 =
            DelegationCredential::mint_sign(&fx.mid, &fx.end, scoped_pred, &fx.mid_key).unwrap();
        g2.edges.clear();
        g2.add_edge(fx.graph.edges()[0].clone()).unwrap();
        g2.add_edge(cred2).unwrap();
        assert!(g2
            .resolve(
                fx.end_key.key_id(),
                &ScopeRequest::new("eu", "p@1", "batteries", t(500))
                    .with_predicate("urn:rule:audit", true),
                &b
            )
            .is_ok());
        assert!(matches!(
            g2.resolve(
                fx.end_key.key_id(),
                &ScopeRequest::new("eu", "p@1", "batteries", t(500))
                    .with_predicate("urn:rule:audit", false),
                &b
            )
            .unwrap_err(),
            SignatifError::ScopeConditionFailed { .. }
        ));
    }
}
