use serde_json::json;

pub(crate) fn test_gateway_service_resolution()
-> arkret_models_identity::AuthenticatedServiceResolution {
    use arkret_models_identity::{
        DidBindingEvidenceKind, DidBindingEvidenceReceipt, DidDocument,
        ResolutionMethodEvidenceBoundary, ResolutionMethodHistoryEvidence,
    };

    let did = arkret_wire::Did::new("did:web:push.example.com").unwrap();
    let document: DidDocument = serde_json::from_value(json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [{
            "id": "did:web:push.example.com#receipt",
            "controller": "did:web:push.example.com",
            "type": "Multikey",
            "publicKeyMultibase": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
        }],
        "authentication": ["did:web:push.example.com#receipt"],
        "assertionMethod": ["did:web:push.example.com#receipt"],
        "service": [{
            "id": "did:web:push.example.com#gateway",
            "type": "ArkretService",
            "service_kind": "push_gateway",
            "serviceEndpoint": "https://push.example.com/"
        }]
    }))
    .unwrap();
    let digest = arkret_models_identity::normalized_did_document_digest(&document).unwrap();
    let version = format!(
        "synthetic-jcs-sha256:{}",
        digest.as_str().trim_start_matches("sha256:")
    );
    arkret_models_identity::AuthenticatedServiceResolution {
        service_id: arkret_wire::project_did_to_core_id(&did).unwrap(),
        service_kind: arkret_wire::ServiceKind::PushGateway.as_str().to_owned(),
        method_history_evidence: ResolutionMethodHistoryEvidence::DidWebDocument {
            boundary: ResolutionMethodEvidenceBoundary {
                from_method_history_head: digest.to_string(),
                from_version_id: version.clone(),
                to_method_history_head: digest.to_string(),
                to_version_id: version,
            },
            evidence: DidBindingEvidenceReceipt {
                kind: DidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "web".to_owned(),
                document_digest: digest,
                method_proofs: Vec::new(),
            },
        },
        normalized_did_document: document,
    }
}
