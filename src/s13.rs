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
    pub request: S13Request,
    /// The requesting node (trust-graph id; signs the request).
    pub requester: String,
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
        self.signature
            .verify(SigningDomain::S13Message, &self.request.canonical_bytes(), public)
    }
}

/// The custodian's signed answer (what the answering side sends and
/// journals).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SignedS13Response {
    pub response: S13Response,
    pub signature: SignatureSlot,
}

impl SignedS13Response {
    /// The custodian signs the response's canonical bytes (the
    /// response names its custodian).
    pub fn issue(
        response: S13Response,
        key: &KeyPair,
    ) -> Result<SignedS13Response, SignatifError> {
        let signature =
            SignatureSlot::sign(key, SigningDomain::S13Message, &response.canonical_bytes())?;
        Ok(SignedS13Response { response, signature })
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
    Request(SignedS13Request),
    Response(SignedS13Response),
}

/// Which side's journal this is (both sides journal the exchange).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum S13Side {
    Verifier,
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
    pub governing_policy_version: u64,
}

/// The append-only choreography journal: signed requests and
/// responses, in sequence. Replay reconstructs the exchange from the
/// journal alone (XB-6) — nothing else is consulted.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct S13Journal {
    pub side: S13Side,
    pub entries: Vec<S13JournalEntry>,
}

impl S13Journal {
    pub fn new(side: S13Side) -> S13Journal {
        S13Journal {
            side,
            entries: Vec::new(),
        }
    }

    /// Append in sequence (the journal is append-only by
    /// construction; reorderings are tampering and fail replay).
    pub fn append(&mut self, entry: S13JournalEntry) -> usize {
        self.entries.push(entry);
        self.entries.len()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

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
        for entry in &self.entries {
            match entry {
                S13JournalEntry::Request(signed) => {
                    signed.verify(graph)?;
                    seen_requests.push(signed.request.digest());
                }
                S13JournalEntry::Response(signed) => {
                    signed.verify(graph)?;
                    if !seen_requests.contains(&signed.response.request_digest) {
                        return Err(SignatifError::crypto(format!(
                            "journal replay: an answer is bound to no journaled request"
                        )));
                    }
                    decisions.push(S13Decision {
                        request_digest: signed.response.request_digest,
                        outcome: signed
                            .response
                            .outcome
                            .token()
                            .to_string(),
                        governing_policy: signed.response.governing_policy.clone(),
                        governing_policy_version: signed.response.governing_policy_version,
                    });
                }
            }
        }
        Ok(decisions)
    }
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
        let graph = graph_with(&[("de-zoll", &verifier), ("weilian-shenzhen", &custodian)]);
        (graph, verifier, custodian)
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
                ["permit", "permit-paired", "attestation-offer", "escalation", "deny"],
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
        let S13JournalEntry::Response(mut signed) = a else { unreachable!() };
        signed.response.governing_policy_version = 2;
        let mut journal = S13Journal::new(S13Side::Custodian);
        journal.append(q);
        journal.append(S13JournalEntry::Response(signed));
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
