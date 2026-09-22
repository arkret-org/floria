use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::*;
use crate::config::{NotifyServicePrincipalConfig, RegistrationHandoffConfig};
use crate::registration_handoff::RegistrationHandoffStore;

fn handoff_test_service() -> Service {
    let registry = PushkinRegistry::new(HashMap::new());
    Service::new(build_router(Arc::new(AppState::new(Arc::new(registry)))))
}

fn body() -> Value {
    json!({
        "registration_id": "registration_0123456789abcdef",
        "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
        "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
        "state": "active",
        "push_key": "provider-secret",
        "app_id": "org.arkret.fixture",
        "visible_notification_opt_in": false
    })
}

fn sign_handoff_request(seed: [u8; 32], target_uri: &str, body: &[u8]) -> (String, String, String) {
    let signing_key = SigningKey::from_bytes(&seed);
    let digest = format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(body))
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let components = "(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \"source-service-id\" \"destination-service-id\" \"arkret-operation\" \"idempotency-key\")";
    let parameters = format!(
        "{components};created={now};expires={};keyid=\"did:web:sync.example.com#push\";alg=\"ed25519\"",
        now + 300
    );
    let signature_input = format!("sig1={parameters}");
    let signing_string = [
        "\"@method\": POST".to_owned(),
        format!("\"@target-uri\": {target_uri}"),
        "\"@authority\": 127.0.0.1".to_owned(),
        format!("\"content-digest\": {digest}"),
        "\"source-service-id\": ak:did_core:web:sync.example.com".to_owned(),
        "\"destination-service-id\": ak:did_core:web:push.example.com".to_owned(),
        "\"arkret-operation\": ak.edge.push.command.apply_registration.v1".to_owned(),
        "\"idempotency-key\": handoff-fixture".to_owned(),
        format!("\"@signature-params\": {parameters}"),
    ]
    .join("\n");
    let signature = signing_key.sign(signing_string.as_bytes());
    (
        digest,
        signature_input,
        format!(
            "sig1=:{}:",
            base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
        ),
    )
}

async fn configured_handoff_test_service(postgres_url: String) -> Service {
    let gateway_did = arkret_wire::Did::new("did:web:push.example.com").unwrap();
    let gateway_id = arkret_wire::project_did_to_core_id(&gateway_did).unwrap();
    let receipt_seed = [7_u8; 32];
    let mut handoff = RegistrationHandoffConfig::default();
    handoff.postgres_url = Some(postgres_url);
    handoff.encryption_key_hex = Some(hex::encode([11_u8; 32]));
    handoff.receipt_signing_key_seed_hex = Some(hex::encode(receipt_seed));
    handoff.receipt_verification_method = Some("did:web:push.example.com#receipt".to_owned());

    let request_seed = [1_u8; 32];
    let mut principal = NotifyServicePrincipalConfig::default();
    principal.signature_verification_method = Some("did:web:sync.example.com#push".to_owned());
    principal.signature_public_key_hex = Some(hex::encode(
        SigningKey::from_bytes(&request_seed)
            .verifying_key()
            .to_bytes(),
    ));
    let mut auth = NotifyAuthConfig::default();
    auth.gateway_service_did = Some(gateway_did.as_str().to_owned());
    auth.require_message_signatures = true;
    auth.replay_window_seconds = 300;
    auth.service_principals =
        HashMap::from([("ak:did_core:web:sync.example.com".to_owned(), principal)]);

    let mut state = AppState::new(Arc::new(PushkinRegistry::new(HashMap::new())));
    state.notify_auth = auth;
    state.notify_nonce_store = Some(Arc::new(crate::nonce_store::NonceStore::memory(
        Duration::from_secs(300),
    )));
    let store = RegistrationHandoffStore::from_config(&handoff, gateway_id)
        .await
        .unwrap()
        .map(Arc::new)
        .unwrap();
    state.registration_handoff = Some(store.clone());
    Service::new(build_router(Arc::new(state)))
}

#[tokio::test]
async fn configured_handoff_accepts_signed_apply_and_advertises_generated_bundle() {
    let Ok(postgres_url) = std::env::var("FLORIA_HANDOFF_TEST_DATABASE_URL") else {
        return;
    };
    let service = configured_handoff_test_service(postgres_url).await;
    let mut request_body = body();
    request_body["registration_id"] =
        json!(format!("registration_{}", uuid::Uuid::new_v4().simple()));
    let body_bytes = serde_json::to_vec(&request_body).unwrap();
    let target_uri = "http://127.0.0.1/_arkret/edge/push/registrations:apply";
    let (content_digest, signature_input, signature) =
        sign_handoff_request([1_u8; 32], target_uri, &body_bytes);
    let mut response = TestClient::post(target_uri)
        .add_header("Idempotency-Key", "handoff-fixture", true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_APPLY_REGISTRATION_V1,
            true,
        )
        .add_header("host", "127.0.0.1", true)
        .add_header("content-digest", content_digest, true)
        .add_header("signature-input", signature_input, true)
        .add_header("signature", signature, true)
        .add_header(
            SOURCE_SERVICE_ID_HEADER,
            "ak:did_core:web:sync.example.com",
            true,
        )
        .add_header(
            DESTINATION_SERVICE_ID_HEADER,
            "ak:did_core:web:push.example.com",
            true,
        )
        .json(&request_body)
        .send(&service)
        .await;
    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let outcome = response.take_json::<Value>().await.unwrap();
    assert_eq!(
        outcome["receipt"]["source_station_id"],
        json!("ak:did_core:web:sync.example.com")
    );

    let mut describe = TestClient::get("http://127.0.0.1/_arkret/describe")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SERVER_READ_DESCRIBE_V1,
            true,
        )
        .send(&service)
        .await;
    assert_eq!(describe.status_code.unwrap(), StatusCode::OK);
    let describe = describe.take_json::<Value>().await.unwrap();
    assert!(
        describe["supported_operation_bundles"]
            .as_array()
            .unwrap()
            .contains(&json!(
                super::super::server_describe::REGISTRATION_HANDOFF_BUNDLE_ID
            ))
    );
}

#[tokio::test]
async fn handoff_requires_its_registered_operation_selector() {
    let service = handoff_test_service();
    let mut response = TestClient::post("http://127.0.0.1/_arkret/edge/push/registrations:apply")
        .json(&body())
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let problem = response.take_json::<Value>().await.unwrap();
    assert!(
        problem.to_string().contains("operation_selector_required"),
        "unexpected problem body: {problem}"
    );
}

#[tokio::test]
async fn handoff_never_accepts_an_unsigned_request() {
    let service = handoff_test_service();
    let mut response = TestClient::post("http://127.0.0.1/_arkret/edge/push/registrations:apply")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_APPLY_REGISTRATION_V1,
            true,
        )
        .add_header(
            SOURCE_SERVICE_ID_HEADER,
            "ak:did_core:web:station.example",
            true,
        )
        .add_header(
            DESTINATION_SERVICE_ID_HEADER,
            "ak:did_core:web:push.example",
            true,
        )
        .json(&body())
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let problem = response.take_json::<Value>().await.unwrap();
    assert!(
        problem.to_string().contains("unauthenticated"),
        "unexpected problem body: {problem}"
    );
}
