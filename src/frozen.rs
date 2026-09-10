//! Frozen views (SI-1): self-describing evidence bundles — the F1
//! object.
//!
//! A frozen view is what a publisher hands a foreign verifier: the
//! rendered payload, its five-axis descriptor (T forced
//! point-in-time — freeze turns continuous into point-in-time), the
//! lens metadata (profile reference + transform chain with
//! provenance + the committed inputs), the verification bundle (the
//! dossier), and reader instructions (the checks, in order). A
//! foreign verifier ingests the view ALONE, verifies it under its
//! own anchors, and re-executes the lens over the committed inputs —
//! matching the issuer-side render byte for byte. Air-gapped;
//! replayable; the publication act that makes a scheme F1.

use crate::dossier::Dossier;
use crate::SignatifError;
use unidpp_grid::Segment;
use unidpp_model::{sha256, CanonicalWriter, ProjectionDescriptor, TemporalAxis};

/// One step in the lens's transform chain (registered, versioned,
/// cited — the provenance a foreign re-execution follows).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TransformStep {
    /// The registered transform reference.
    pub reference: String,
    /// The step's version.
    pub version: u64,
}

/// The lens: which profile, which transforms, over which inputs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LensMetadata {
    /// The profile the projection renders under.
    pub profile: String,
    /// The transform chain, in application order.
    pub transforms: Vec<TransformStep>,
    /// The input channels (name → segment whose commitment pins it).
    pub input_segments: Vec<(String, String)>,
}

/// A committed input: the OPEN-class bytes the lens consumes. Its
/// commitment is checked against the bundle's spine — the payload's
/// inputs are spine-proved, not asserted.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FrozenInput {
    /// The input channel name (matches the lens's input_segments).
    pub name: String,
    /// The segment whose state commitment pins these bytes.
    pub segment: String,
    /// The bytes themselves (publication act; open classes only).
    pub bytes: Vec<u8>,
}

/// The frozen view (SI-1).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FrozenView {
    /// The subject.
    pub subject: String,
    /// The rendered payload (what the verifier re-derives).
    pub payload: Vec<u8>,
    /// The five-axis descriptor (T: point-in-time — enforced).
    pub descriptor: ProjectionDescriptor,
    /// The lens that produced the payload.
    pub lens: LensMetadata,
    /// The committed inputs (open classes; spine-checked).
    pub inputs: Vec<FrozenInput>,
    /// The verification bundle (dossier: policies, spine, proofs,
    /// attestations, journal, receipt).
    pub bundle: Dossier,
    /// Reader instructions: the verification checks, in order.
    pub instructions: Vec<String>,
    /// The freeze moment (RFC 3339).
    pub notarized_at: String,
}

impl FrozenView {
    /// Freeze: turn a rendered projection into a self-describing
    /// point-in-time view. A continuous descriptor is refused —
    /// freezing IS the point-in-time act.
    #[allow(clippy::too_many_arguments)] // the parts ARE the calculus's axes
    pub fn freeze(
        subject: &str,
        payload: Vec<u8>,
        descriptor: ProjectionDescriptor,
        lens: LensMetadata,
        inputs: Vec<FrozenInput>,
        bundle: Dossier,
        instructions: Vec<String>,
        notarized_at: &str,
    ) -> Result<FrozenView, SignatifError> {
        if descriptor.temporal != TemporalAxis::PointInTime {
            return Err(SignatifError::Validation(
                "freeze refused: the descriptor is continuous — freezing is the \
                 point-in-time act (declare point-in-time)"
                    .into(),
            ));
        }
        if instructions.is_empty() {
            return Err(SignatifError::Validation(
                "freeze refused: reader instructions are required (self-describing \
                 means describing how to verify)"
                    .to_string(),
            ));
        }
        Ok(FrozenView {
            subject: subject.into(),
            payload,
            descriptor,
            lens,
            inputs,
            bundle,
            instructions,
            notarized_at: notarized_at.into(),
        })
    }

    /// The canonical, signable form (CN-1): subject, descriptor
    /// token, lens (profile + steps + input channels), payload, each
    /// input's commitment, instructions, freeze moment, and the
    /// bundle's spine digest (binding view to bundle).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut w = CanonicalWriter::new();
        w.write_bytes(self.subject.as_bytes());
        w.write_bytes(self.descriptor.token().as_bytes());
        w.write_bytes(self.lens.profile.as_bytes());
        for step in &self.lens.transforms {
            w.write_bytes(step.reference.as_bytes());
            w.write_bytes(&step.version.to_le_bytes());
        }
        for (name, segment) in &self.lens.input_segments {
            w.write_bytes(name.as_bytes());
            w.write_bytes(segment.as_bytes());
        }
        w.write_bytes(&self.payload);
        for input in &self.inputs {
            w.write_bytes(input.name.as_bytes());
            w.write_bytes(&Segment::commit_state(&input.bytes));
        }
        for i in &self.instructions {
            w.write_bytes(i.as_bytes());
        }
        w.write_bytes(self.notarized_at.as_bytes());
        w.write_bytes(&self.bundle.spine.spine.digest());
        w.into_bytes()
    }

    /// The view's digest (sha256 over the canonical bytes).
    pub fn digest(&self) -> [u8; 32] {
        sha256(&[&self.canonical_bytes()]).0
    }

    /// Verify OFFLINE under the verifier's own anchors: the bundle
    /// verifies; every input's commitment matches the segment it
    /// names in the bundle's spine (the inputs are spine-proved, not
    /// asserted); the lens names every input channel.
    pub fn verify(
        &self,
        graph: &crate::graph::TrustGraph,
    ) -> Result<crate::dossier::DossierCheck, SignatifError> {
        let check = self.bundle.verify(graph)?;
        for input in &self.inputs {
            let expected = self
                .bundle
                .spine
                .spine
                .commitments
                .get(&input.segment)
                .ok_or_else(|| {
                    SignatifError::crypto(format!(
                        "frozen view: input `{}` names segment `{}` which the \
                         bundle's spine does not carry",
                        input.name, input.segment
                    ))
                })?;
            let actual = Segment::commit_state(&input.bytes);
            if &actual != expected {
                return Err(SignatifError::crypto(format!(
                    "frozen view: input `{}` does not match its segment `{}` \
                     commitment — the bytes are not what was committed",
                    input.name, input.segment
                )));
            }
            let named = self
                .lens
                .input_segments
                .iter()
                .any(|(n, s)| n == &input.name && s == &input.segment);
            if !named {
                return Err(SignatifError::crypto(format!(
                    "frozen view: input `{}` is not a lens input channel — \
                     unexplained inputs are refused",
                    input.name
                )));
            }
        }
        Ok(check)
    }

    /// Re-execute the lens over the committed inputs and compare
    /// with the issuer-side render: the air-gapped equality check
    /// (SI-1's verify clause).
    pub fn re_executes(&self, render: impl Fn(&[FrozenInput]) -> Vec<u8>) -> bool {
        render(&self.inputs) == self.payload
    }
}

/// The battery-case example view (shared by unit tests and the
/// CN-2 fixture harness — the spec's worked example).
#[doc(hidden)]
pub mod example {
    use super::*;
    /// The static state bytes (the worked example's open input).
    pub const STATIC_STATE: &[u8] = b"cell_model=H-2231,capacity_Ah=52,chemistry=LFP";
    use crate::graph::{DelegationNode, NodeId, NodeKind, RegisteredKey, TrustGraph};

    use crate::keyring::{KeyId, KeyPair};
    use crate::s13::{S13Journal, S13JournalEntry, S13Side, SignedS13Request, SignedS13Response};
    use crate::sign::Suite;
    use crate::sovereign::{AttestationStatement, ClaimClass};
    use std::collections::BTreeMap;
    use unidpp_grid::{PolicyObject, RevealClass, Spine};
    use unidpp_model::BATTERY_FROZEN;
    use unidpp_s13::S13Request;

    // The battery lens: the deterministic render a foreign verifier
    // re-executes from the view's committed inputs (here: select the
    // cell model; the conformity reading rides the attestation in
    // the bundle — this test's lens uses the static input alone and
    // the fixed conformity token).
    pub fn battery_lens(inputs: &[FrozenInput]) -> Vec<u8> {
        let static_input = inputs
            .iter()
            .find(|i| i.name == "static")
            .expect("static input");
        let text = std::str::from_utf8(&static_input.bytes).unwrap();
        let cell_model = text
            .split(',')
            .find(|f| f.starts_with("cell_model="))
            .expect("cell model");
        format!("battery-view: {cell_model}, conformity=pass").into_bytes()
    }

    pub fn battery_view() -> (FrozenView, TrustGraph) {
        let authority = KeyPair::seeded(Suite::Ed25519, b"frozen/cn-samr").unwrap();
        let custodian = KeyPair::seeded(Suite::Ed25519, b"frozen/weilian").unwrap();
        let verifier = KeyPair::seeded(Suite::Ed25519, b"frozen/de-zoll").unwrap();
        let service = KeyPair::seeded(Suite::Ed25519, b"frozen/cn-attest").unwrap();
        let quorum = [
            KeyPair::seeded(Suite::Ed25519, b"frozen/quorum-a").unwrap(),
            KeyPair::seeded(Suite::Ed25519, b"frozen/quorum-b").unwrap(),
        ];
        let mut graph = TrustGraph::new();
        for (id, key) in [
            ("cn-samr", &authority),
            ("weilian-shenzhen", &custodian),
            ("de-zoll", &verifier),
            ("cn-attestation-service", &service),
            ("cn-quorum-a", &quorum[0]),
            ("cn-quorum-b", &quorum[1]),
        ] {
            let mut node = DelegationNode::new(NodeId::new(id).unwrap(), NodeKind::Delegated);
            node.register(RegisteredKey {
                key_id: KeyId::of(key.public()),
                public: *key.public(),
            });
            graph.add_node(node);
        }

        let open_policy = crate::grid::SignedPolicy::issue(
            PolicyObject {
                policy_id: "eu-static-open".into(),
                version: 1,
                authority: "cn-samr".into(),
                readers: vec!["any-verifier".into()],
                verifiers: vec!["any-verifier".into()],
                writers: vec!["weilian-shenzhen".into()],
                reveal: RevealClass::Open,
                suites: vec!["ecdsa-p256".into()],
                valid_from: "2027-01-01T00:00:00Z".into(),
                valid_to: None,
                superseded_by: None,
            },
            &authority,
        )
        .unwrap();
        let sealed_policy = crate::grid::SignedPolicy::issue(
            PolicyObject {
                policy_id: "cn-dynamic-bms".into(),
                version: 1,
                authority: "cn-samr".into(),
                readers: vec!["cn-customs".into()],
                verifiers: vec!["cn-customs".into(), "de-zoll".into()],
                writers: vec!["weilian-shenzhen".into()],
                reveal: RevealClass::OriginSealed,
                suites: vec!["sm2".into()],
                valid_from: "2027-01-01T00:00:00Z".into(),
                valid_to: None,
                superseded_by: None,
            },
            &authority,
        )
        .unwrap();

        let mut commitments = BTreeMap::new();
        commitments.insert("eu-static".to_string(), Segment::commit_state(STATIC_STATE));
        commitments.insert(
            "cn-dynamic".to_string(),
            Segment::commit_state(b"cycle_count=412"),
        );
        let spine = Spine::over(1, commitments.clone());
        let signed_spine =
            crate::grid::SignedSpine::issue(spine.clone(), "weilian-shenzhen", &custodian).unwrap();

        let statement = AttestationStatement {
            segment: "cn-dynamic".into(),
            state_commitment: commitments["cn-dynamic"],
            claim: ClaimClass::Conformity,
            value: "pass".into(),
            as_of: "2030-06-01T08:00:00Z".into(),
            governing_policy: "cn-dynamic-bms".into(),
            governing_policy_version: 1,
            subject: "urn:unidpp:passport:pack-0001".into(),
        };
        let quorum_id = NodeId::new("cn-attestation-quorum").unwrap();
        let attestation = crate::sovereign::SovereignAttestation::issue(
            statement,
            "cn-attestation-service",
            &service,
            Some((&quorum_id, 2, &[&quorum[0], &quorum[1]])),
        )
        .unwrap();

        let request = S13Request {
            verifier: "de-zoll".into(),
            subject: "urn:unidpp:passport:pack-0001".into(),
            profile: "urn:unidpp:profile:eu-battery".into(),
            segment: "cn-dynamic".into(),
            at: "2030-06-01T08:00:00Z".into(),
        };
        let signed_request = SignedS13Request::issue(request, "de-zoll", &verifier).unwrap();
        let response = unidpp_s13::S13Response::evaluate(
            &signed_request.request,
            &sealed_policy.policy,
            "weilian-shenzhen",
        );
        let signed_response = SignedS13Response::issue(response, &custodian).unwrap();
        let mut journal = S13Journal::new(S13Side::Custodian);
        journal.append(S13JournalEntry::Request(signed_request));
        journal.append(S13JournalEntry::Response(signed_response));

        let dossier = Dossier {
            subject: "urn:unidpp:passport:pack-0001".into(),
            policies: vec![open_policy, sealed_policy],
            spine: signed_spine,
            proofs: vec![spine.proof("eu-static").unwrap()],
            attestations: vec![attestation],
            journal,
            receipt: None,
        };

        let inputs = vec![FrozenInput {
            name: "static".into(),
            segment: "eu-static".into(),
            bytes: STATIC_STATE.to_vec(),
        }];
        let lens = LensMetadata {
            profile: "urn:unidpp:profile:eu-battery".into(),
            transforms: vec![TransformStep {
                reference: "urn:unidpp:transform:battery-view".into(),
                version: 1,
            }],
            input_segments: vec![("static".into(), "eu-static".into())],
        };
        let view = FrozenView::freeze(
            "urn:unidpp:passport:pack-0001",
            example::battery_lens(&inputs),
            BATTERY_FROZEN,
            lens,
            inputs,
            dossier,
            vec![
                "verify the bundle under your own anchors".into(),
                "check each input against its spine commitment".into(),
                "re-execute the lens over the inputs".into(),
            ],
            "2030-06-01T08:00:00Z",
        )
        .unwrap();
        (view, graph)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SI-1's verify: air-gapped ingest + verify + re-execution
    // matches the issuer-side render; tampering fails loudly.
    #[test]
    fn air_gapped_re_execution_matches_the_issuer_side_render() {
        let (view, graph) = example::battery_view();
        // Air-gapped: the view alone crosses the border.
        let json = serde_json::to_string(&view).unwrap();
        let back: FrozenView = serde_json::from_str(&json).unwrap();
        assert_eq!(back, view);

        let check = back.verify(&graph).unwrap();
        assert_eq!(check.policies_ok, 2);
        assert!(back.re_executes(example::battery_lens));

        // Tampered payload: re-execution catches it.
        let mut tampered = back.clone();
        tampered.payload = b"battery-view: cell_model=FORGED, conformity=pass".to_vec();
        assert!(!tampered.re_executes(example::battery_lens));

        // Swapped input bytes: the spine commitment catches it.
        let mut swapped = back.clone();
        swapped.inputs[0].bytes = b"cell_model=FORGED,capacity_Ah=52".to_vec();
        assert!(swapped.verify(&graph).is_err());

        // The digest is stable across the round trip (CN-1).
        assert_eq!(back.digest(), view.digest());
    }

    // The freeze contract: continuous descriptors are refused.
    #[test]
    fn freeze_refuses_continuous_descriptors() {
        let (view, _graph) = example::battery_view();
        let err = FrozenView::freeze(
            &view.subject,
            view.payload.clone(),
            unidpp_model::SERVED_VIEW, // continuous
            view.lens.clone(),
            view.inputs.clone(),
            view.bundle.clone(),
            view.instructions.clone(),
            "2030-06-01T08:00:00Z",
        );
        assert!(err.is_err());
    }
}
