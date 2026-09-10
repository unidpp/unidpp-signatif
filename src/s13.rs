//! The S13 signed envelopes + the choreography journal (XB-6, SG-8).
//!
//! Core's s13 crate is the pure model (canonical bytes, the policy
//! evaluation, the four outcomes); this module is the trust layer:
//! the verifier SIGNS its request, the custodian SIGNS its answer —
//! both in the S13-MESSAGE domain — and both sides journal the
//! signed objects. The choreography replays from the journal alone:
//! every entry verifies under the trust graph, every answer binds to
//! a journaled request's digest, and the decisions come back in
//! sequence. Policy evaluation stays a pure, versioned function of
//! (request, policy version) — SG-8 — so a replayed journal
//! reproduces the custodian's decisions byte for byte.

use crate::graph::{NodeId, TrustGraph};
use crate::keyring::KeyPair;
use crate::sign::{SignatureSlot, SigningDomain};
use crate::SignatifError;
use unidpp_s13::{S13Request, S13Response};

/// The verifier's signed request (what the asking side sends and
/// journals).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SignedS13Request {
    /// The request (its canonical bytes are what is signed).
    pub request: S13Request,
    /// The requesting node (trust-graph id; signs the request).
    pub requester: String,
    /// The requester's signature in the S13-MESSAGE domain.
    pub signature: SignatureSlot,
}

impl SignedS13Request {
    /// The verifier signs the request's canonical bytes.
    pub fn issue(
        request: S13Request,
        requester: &str,
        key: &KeyPair,
    ) -> Result<SignedS13Request, SignatifError> {
        let signature =
            SignatureSlot::sign(key, SigningDomain::S13Message, &request.canonical_bytes())?;
        Ok(SignedS13Request {
            request,
            requester: requester.to_string(),
            signature,
        })
    }

    /// Verify under the graph: the signature must resolve to the
    /// DECLARED requester's key — a valid signature from any other
    /// node is not this request.
    pub fn verify(&self, graph: &TrustGraph) -> Result<(), SignatifError> {
        let node = NodeId::new(&self.requester)
            .map_err(|e| SignatifError::crypto(format!("s13 requester: {e}")))?;
        let public = graph
            .node(&node)
            .and_then(|n| n.key(&self.signature.key_id))
            .ok_or_else(|| {
                SignatifError::crypto(format!(
                    "s13 requester `{}` has no such key",
                    self.requester
                ))
            })?;
        self.signature.verify(
            SigningDomain::S13Message,
            &self.request.canonical_bytes(),
            public,
        )
    }
}

/// The custodian's signed answer (what the answering side sends and
/// journals).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SignedS13Response {
    /// The response (its canonical bytes are what is signed).
    pub response: S13Response,
    /// The custodian's signature in the S13-MESSAGE domain.
    pub signature: SignatureSlot,
}

impl SignedS13Response {
    /// The custodian signs the response's canonical bytes (the
    /// response names its custodian).
    pub fn issue(response: S13Response, key: &KeyPair) -> Result<SignedS13Response, SignatifError> {
        let signature =
            SignatureSlot::sign(key, SigningDomain::S13Message, &response.canonical_bytes())?;
        Ok(SignedS13Response {
            response,
            signature,
        })
    }

    /// Verify under the graph: the key must be the DECLARED
    /// custodian's.
    pub fn verify(&self, graph: &TrustGraph) -> Result<(), SignatifError> {
        let node = NodeId::new(&self.response.custodian)
            .map_err(|e| SignatifError::crypto(format!("s13 custodian: {e}")))?;
        let public = graph
            .node(&node)
            .and_then(|n| n.key(&self.signature.key_id))
            .ok_or_else(|| {
                SignatifError::crypto(format!(
                    "s13 custodian `{}` has no such key",
                    self.response.custodian
                ))
            })?;
        self.signature.verify(
            SigningDomain::S13Message,
            &self.response.canonical_bytes(),
            public,
        )
    }
}

/// One journaled S13 message.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum S13JournalEntry {
    /// The verifier's signed request.
    Request(SignedS13Request),
    /// The custodian's signed response.
    Response(SignedS13Response),
    /// A non-repudiable response (the authority counter-signed:
    /// offers and refusals — XB-7).
    Countersigned(NonRepudiableResponse),
}

/// The non-repudiable response (XB-7): the custodian EXECUTES the
/// policy; the AUTHORITY answers for it. Offers and refusals carry
/// the policy authority's counter-signature over the response
/// digest and the response's place in the per-(subject, segment)
/// sequence — a dispute is decided from the record: who answered,
/// under which policy, at which point in the sequence.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct NonRepudiableResponse {
    /// The custodian's signed response (the offer or refusal).
    pub signed: SignedS13Response,
    /// The policy authority (the governing policy's authority).
    pub authority: String,
    /// The authority's counter-signature over (response digest ||
    /// sequence || policy id || version).
    pub authority_signature: SignatureSlot,
    /// Monotone per (subject, segment); a replayed offer carries a
    /// stale sequence and fails.
    pub sequence: u64,
}

impl NonRepudiableResponse {
    /// What the authority signs: the answer's identity and place.
    fn authority_payload_for(response: &S13Response, sequence: u64) -> Vec<u8> {
        let mut w = unidpp_model::CanonicalWriter::new();
        w.write_bytes(&response.request_digest);
        w.write_bytes(&sequence.to_le_bytes());
        w.write_bytes(response.governing_policy.as_bytes());
        w.write_bytes(&response.governing_policy_version.to_le_bytes());
        w.into_bytes()
    }

    /// Issue: the authority counter-signs the custodian's answer.
    pub fn issue(
        signed: SignedS13Response,
        authority: &str,
        authority_key: &KeyPair,
        sequence: u64,
    ) -> Result<NonRepudiableResponse, SignatifError> {
        let payload = Self::authority_payload_for(&signed.response, sequence);
        let authority_signature =
            SignatureSlot::sign(authority_key, SigningDomain::S13Message, &payload)?;
        Ok(NonRepudiableResponse {
            signed,
            authority: authority.into(),
            authority_signature,
            sequence,
        })
    }

    /// Verify under the graph: the custodian's signature AND the
    /// authority's counter-signature (the key must be the DECLARED
    /// authority's), at the expected sequence (a stale sequence is a
    /// replay).
    pub fn verify(&self, graph: &TrustGraph, expected_sequence: u64) -> Result<(), SignatifError> {
        self.signed.verify(graph)?;
        if self.sequence != expected_sequence {
            return Err(SignatifError::crypto(format!(
                "s13 non-repudiation: stale sequence {} (expected {}) — a replayed answer",
                self.sequence, expected_sequence
            )));
        }
        let node = NodeId::new(&self.authority)
            .map_err(|e| SignatifError::crypto(format!("s13 authority: {e}")))?;
        let public = graph
            .node(&node)
            .and_then(|n| n.key(&self.authority_signature.key_id))
            .ok_or_else(|| {
                SignatifError::crypto(format!(
                    "s13 authority `{}` has no such key",
                    self.authority
                ))
            })?;
        let payload = Self::authority_payload_for(&self.signed.response, self.sequence);
        self.authority_signature
            .verify(SigningDomain::S13Message, &payload, public)
    }
}

/// Which side's journal this is (both sides journal the exchange).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum S13Side {
    /// The asking side (its requests, and the answers it received).
    Verifier,
    /// The answering side (the requests it received, its answers).
    Custodian,
}

/// A decision reconstructed by journal replay.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct S13Decision {
    /// The request this decision answers (digest).
    pub request_digest: [u8; 32],
    /// The outcome token (permit / permit-paired / attestation-offer
    /// / escalation / deny).
    pub outcome: String,
    /// The governing policy the custodian evaluated under.
    pub governing_policy: String,
    /// The governing policy's version.
    pub governing_policy_version: u64,
}

/// The append-only choreography journal: signed requests and
/// responses, in sequence. Replay reconstructs the exchange from the
/// journal alone (XB-6) — nothing else is consulted.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct S13Journal {
    /// Which side's journal this is.
    pub side: S13Side,
    /// The signed messages, in sequence.
    pub entries: Vec<S13JournalEntry>,
}

impl S13Journal {
    /// An empty journal for one side.
    pub fn new(side: S13Side) -> S13Journal {
        S13Journal {
            side,
            entries: Vec::new(),
        }
    }

    /// Append in sequence, returning the new length (the journal is
    /// append-only by construction; reorderings are tampering and
    /// fail replay).
    pub fn append(&mut self, entry: S13JournalEntry) -> usize {
        self.entries.push(entry);
        self.entries.len()
    }

    /// The number of journaled messages.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is journaled yet.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Replay the choreography from the journal alone: every entry
    /// verifies under the graph; every response binds to a
    /// journaled request's digest. Returns the decisions in journal
    /// sequence.
    pub fn replay(&self, graph: &TrustGraph) -> Result<Vec<S13Decision>, SignatifError> {
        let mut decisions = Vec::new();
        let mut seen_requests: Vec<[u8; 32]> = Vec::new();
        let mut sequences: std::collections::BTreeMap<(String, String), u64> =
            std::collections::BTreeMap::new();
        for entry in &self.entries {
            match entry {
                S13JournalEntry::Request(signed) => {
                    signed.verify(graph)?;
                    seen_requests.push(signed.request.digest());
                }
                S13JournalEntry::Response(signed) => {
                    signed.verify(graph)?;
                    if !seen_requests.contains(&signed.response.request_digest) {
                        return Err(SignatifError::crypto(
                            "journal replay: an answer is bound to no journaled request"
                                .to_string(),
                        ));
                    }
                    decisions.push(decision_of(&signed.response));
                }
                S13JournalEntry::Countersigned(nr) => {
                    if !seen_requests.contains(&nr.signed.response.request_digest) {
                        return Err(SignatifError::crypto(
                            "journal replay: an answer is bound to no journaled request"
                                .to_string(),
                        ));
                    }
                    // The answer's place in the per-(subject, custodian)
                    // sequence: the authority counter-signs each place;
                    // a rewind is a replay (XB-7).
                    let subject = subject_of(&self.entries, &nr.signed.response.request_digest);
                    let key = (subject, nr.signed.response.custodian.clone());
                    let expected = sequences.get(&key).map_or(1, |last| last + 1);
                    nr.verify(graph, expected)
                        .map_err(|e| SignatifError::crypto(format!("journal replay: {e}")))?;
                    sequences.insert(key, nr.sequence);
                    decisions.push(decision_of(&nr.signed.response));
                }
            }
        }
        Ok(decisions)
    }
}

/// A decision reconstructed from one response.
fn decision_of(response: &S13Response) -> S13Decision {
    S13Decision {
        request_digest: response.request_digest,
        outcome: response.outcome.token().to_string(),
        governing_policy: response.governing_policy.clone(),
        governing_policy_version: response.governing_policy_version,
    }
}

/// The subject of a journaled request (by digest).
fn subject_of(entries: &[S13JournalEntry], digest: &[u8; 32]) -> String {
    for entry in entries {
        if let S13JournalEntry::Request(signed) = entry {
            if &signed.request.digest() == digest {
                return signed.request.subject.clone();
            }
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{DelegationNode, NodeKind, RegisteredKey};
    use crate::keyring::KeyId;
    use crate::sign::Suite;
    use unidpp_grid::{PolicyObject, RevealClass};

    fn graph_with(nodes: &[(&str, &KeyPair)]) -> TrustGraph {
        let mut graph = TrustGraph::new();
        for (id, key) in nodes {
            let mut node = DelegationNode::new(NodeId::new(id).unwrap(), NodeKind::Delegated);
            node.register(RegisteredKey {
                key_id: KeyId::of(key.public()),
                public: *key.public(),
            });
            graph.add_node(node);
        }
        graph
    }

    fn policy(reveal: RevealClass) -> PolicyObject {
        PolicyObject {
            policy_id: "p-test".into(),
            version: 1,
            authority: "cn-samr".into(),
            readers: vec![],
            verifiers: vec!["any-verifier".into()],
            writers: vec![],
            reveal,
            suites: vec!["sm2".into()],
            valid_from: "2027-01-01T00:00:00Z".into(),
            valid_to: None,
            superseded_by: None,
        }
    }

    fn request(at: &str) -> S13Request {
        S13Request {
            verifier: "de-zoll".into(),
            subject: "urn:unidpp:passport:pack-0001".into(),
            profile: "urn:unidpp:profile:eu-battery".into(),
            segment: "cn-dynamic".into(),
            at: at.into(),
        }
    }

    fn exchange(
        req: S13Request,
        pol: &PolicyObject,
        verifier_key: &KeyPair,
        custodian_key: &KeyPair,
    ) -> (S13JournalEntry, S13JournalEntry) {
        let signed_req =
            SignedS13Request::issue(req, "de-zoll", verifier_key).expect("sign request");
        let resp = S13Response::evaluate(&signed_req.request, pol, "weilian-shenzhen");
        let signed_resp = SignedS13Response::issue(resp, custodian_key).expect("sign response");
        (
            S13JournalEntry::Request(signed_req),
            S13JournalEntry::Response(signed_resp),
        )
    }

    fn cast() -> (TrustGraph, KeyPair, KeyPair) {
        let verifier = KeyPair::seeded(Suite::Ed25519, b"s13/de-zoll").unwrap();
        let custodian = KeyPair::seeded(Suite::Ed25519, b"s13/weilian").unwrap();
        let graph = graph_with(&[
            ("de-zoll", &verifier),
            ("weilian-shenzhen", &custodian),
            (
                "cn-samr",
                &KeyPair::seeded(Suite::Ed25519, b"s13/cn-samr").unwrap(),
            ),
        ]);
        (graph, verifier, custodian)
    }

    fn authority_key() -> KeyPair {
        KeyPair::seeded(Suite::Ed25519, b"s13/cn-samr").unwrap()
    }

    // XB-6's verify: all four outcomes (plus the stated denial)
    // replay from the journals alone — both sides' journals.
    #[test]
    fn all_outcomes_replay_from_the_journal_alone() {
        let (graph, vkey, ckey) = cast();
        let cases = [
            (RevealClass::Open, "permit"),
            (RevealClass::PairingGated, "permit-paired"),
            (RevealClass::OriginSealed, "attestation-offer"),
            (RevealClass::Escrowed, "escalation"),
        ];
        let mut verifier_journal = S13Journal::new(S13Side::Verifier);
        let mut custodian_journal = S13Journal::new(S13Side::Custodian);
        for (i, (reveal, _token)) in cases.iter().enumerate() {
            let (q, a) = exchange(
                request(&format!("2030-06-01T08:0{i}:00Z")),
                &policy(*reveal),
                &vkey,
                &ckey,
            );
            verifier_journal.append(q.clone());
            verifier_journal.append(a.clone());
            custodian_journal.append(q);
            custodian_journal.append(a);
        }
        // Plus a stated denial for an unlisted verifier.
        let mut closed = policy(RevealClass::Open);
        closed.verifiers = vec!["cn-customs".into()];
        let (q, a) = exchange(request("2030-06-01T08:05:00Z"), &closed, &vkey, &ckey);
        verifier_journal.append(q.clone());
        verifier_journal.append(a.clone());
        custodian_journal.append(q);
        custodian_journal.append(a);

        for journal in [&verifier_journal, &custodian_journal] {
            let decisions = journal.replay(&graph).expect("replay");
            assert_eq!(decisions.len(), 5, "{:?}", journal.side);
            let tokens: Vec<&str> = decisions.iter().map(|d| d.outcome.as_str()).collect();
            assert_eq!(
                tokens,
                [
                    "permit",
                    "permit-paired",
                    "attestation-offer",
                    "escalation",
                    "deny"
                ],
                "{:?}",
                journal.side
            );
            for d in &decisions {
                assert_eq!(d.governing_policy, "p-test");
                assert_eq!(d.governing_policy_version, 1);
            }
        }
    }

    // SG-8: the decision is a versioned function of (request,
    // policy version) — same inputs, same canonical answer bytes,
    // and the journal replay reproduces the live decision.
    #[test]
    fn decisions_are_deterministic_and_replayable() {
        let (graph, vkey, ckey) = cast();
        let pol = policy(RevealClass::OriginSealed);
        let req = request("2030-06-01T08:00:00Z");
        let live1 = S13Response::evaluate(&req, &pol, "weilian-shenzhen");
        let live2 = S13Response::evaluate(&req, &pol, "weilian-shenzhen");
        assert_eq!(live1.canonical_bytes(), live2.canonical_bytes());
        let (q, a) = exchange(req, &pol, &vkey, &ckey);
        let mut journal = S13Journal::new(S13Side::Custodian);
        journal.append(q);
        journal.append(a);
        let decisions = journal.replay(&graph).expect("replay");
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].outcome, live1.outcome.token());
        assert_eq!(decisions[0].governing_policy, live1.governing_policy);
    }

    // Tampering fails replay loudly: a swapped policy version under
    // the custodian's signature.
    #[test]
    fn tampered_journal_entries_fail_replay() {
        let (graph, vkey, ckey) = cast();
        let (q, a) = exchange(
            request("2030-06-01T08:00:00Z"),
            &policy(RevealClass::Open),
            &vkey,
            &ckey,
        );
        let S13JournalEntry::Response(mut signed) = a else {
            unreachable!()
        };
        signed.response.governing_policy_version = 2;
        let mut journal = S13Journal::new(S13Side::Custodian);
        journal.append(q);
        journal.append(S13JournalEntry::Response(signed));
        assert!(journal.replay(&graph).is_err());
    }

    // XB-7: offers and refusals carry the policy AUTHORITY's
    // counter-signature; a dispute is decided from the record.
    #[test]
    fn offers_carry_the_authoritys_signature_and_replay_from_the_record() {
        let (graph, vkey, ckey) = cast();
        let pol = policy(RevealClass::OriginSealed);
        let req = request("2030-06-01T08:00:00Z");
        let signed_req = SignedS13Request::issue(req, "de-zoll", &vkey).unwrap();
        let resp = S13Response::evaluate(&signed_req.request, &pol, "weilian-shenzhen");
        let signed_resp = SignedS13Response::issue(resp, &ckey).unwrap();
        let nr = NonRepudiableResponse::issue(signed_resp, "cn-samr", &authority_key(), 1).unwrap();
        assert!(nr.verify(&graph, 1).is_ok());

        // The dispute is decided from the record: the journal
        // replays the countersigned exchange, both signatures
        // verified, the decision and its governing policy named.
        let mut journal = S13Journal::new(S13Side::Custodian);
        journal.append(S13JournalEntry::Request(signed_req));
        journal.append(S13JournalEntry::Countersigned(nr));
        let decisions = journal.replay(&graph).expect("replay");
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].outcome, "attestation-offer");
        assert_eq!(decisions[0].governing_policy, "p-test");
    }

    // XB-7's verify: a forged offer (the custodian's key pretending
    // to the authority's counter-signature) fails.
    #[test]
    fn forged_offers_fail_signature() {
        let (graph, vkey, ckey) = cast();
        let pol = policy(RevealClass::OriginSealed);
        let req = request("2030-06-01T08:00:00Z");
        let signed_req = SignedS13Request::issue(req, "de-zoll", &vkey).unwrap();
        let resp = S13Response::evaluate(&signed_req.request, &pol, "weilian-shenzhen");
        let signed_resp = SignedS13Response::issue(resp, &ckey).unwrap();
        let forged = NonRepudiableResponse::issue(signed_resp, "cn-samr", &ckey, 1).unwrap();
        assert!(forged.verify(&graph, 1).is_err());
    }

    // XB-7's verify: a replayed offer fails the sequence.
    #[test]
    fn replayed_offers_fail_sequence() {
        let (graph, vkey, ckey) = cast();
        let pol = policy(RevealClass::OriginSealed);
        let req = request("2030-06-01T08:00:00Z");
        let signed_req = SignedS13Request::issue(req, "de-zoll", &vkey).unwrap();
        let resp = S13Response::evaluate(&signed_req.request, &pol, "weilian-shenzhen");
        let signed_resp = SignedS13Response::issue(resp, &ckey).unwrap();
        let nr = NonRepudiableResponse::issue(signed_resp, "cn-samr", &authority_key(), 1).unwrap();

        // Direct: stale sequence is a replay.
        assert!(nr.verify(&graph, 2).is_err());

        // Through the journal: the same countersigned answer twice.
        let mut journal = S13Journal::new(S13Side::Custodian);
        journal.append(S13JournalEntry::Request(signed_req));
        journal.append(S13JournalEntry::Countersigned(nr.clone()));
        journal.append(S13JournalEntry::Countersigned(nr));
        assert!(journal.replay(&graph).is_err());
    }

    // An answer bound to no journaled request is rejected at replay.
    #[test]
    fn unbound_answers_fail_replay() {
        let (graph, vkey, ckey) = cast();
        let (_, a) = exchange(
            request("2030-06-01T08:00:00Z"),
            &policy(RevealClass::Open),
            &vkey,
            &ckey,
        );
        let mut journal = S13Journal::new(S13Side::Custodian);
        journal.append(a);
        assert!(journal.replay(&graph).is_err());
    }
}
