use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::helpers::{signature_public_key_hex, unix_now_secs};
use super::{DESTINATION_SERVICE_DID_HEADER, ORIGIN_SERVICE_DID_HEADER, redact_url_credentials};
use crate::AppState;
use crate::config::{NotifyAuthConfig, NotifyServicePrincipalConfig};
use crate::pushkin::{Pushkin, PushkinRegistry};
use crate::service::build_router;

struct NoopPushkin;

#[async_trait::async_trait]
impl Pushkin for NoopPushkin {
    fn name(&self) -> &str {
        "noop"
    }

    fn kind(&self) -> &'static str {
        "noop"
    }

    fn handles_appid(&self, appid: &str) -> bool {
        appid == "com.example.app"
    }

    async fn dispatch_notification(
        &self,
        _notification: &crate::models::Notification,
        _device: &crate::models::Device,
        _context: &crate::models::NotificationContext,
    ) -> Result<Vec<String>, crate::error::DispatchError> {
        Ok(vec![])
    }
}

fn test_service_with_principal(principal: NotifyServicePrincipalConfig) -> salvo::Service {
    let registry = PushkinRegistry::new(HashMap::from([(
        "com.example.app".to_owned(),
        Arc::new(NoopPushkin) as Arc<dyn Pushkin>,
    )]));
    let mut state = AppState::new(Arc::new(registry));
    let mut notify_auth = NotifyAuthConfig::default();
    notify_auth.gateway_service_did = Some("did:web:push.example.com".to_owned());
    notify_auth.require_message_signatures = true;
    notify_auth.service_principals =
        HashMap::from([("did:web:sync.example.com".to_owned(), principal)]);
    state.notify_auth = notify_auth;
    salvo::Service::new(build_router(Arc::new(state)))
}

fn sign_request(
    seed_hex: &str,
    method: &str,
    target_uri: &str,
    authority: &str,
    body: &[u8],
) -> (String, String, String) {
    let seed = hex::decode(seed_hex).unwrap();
    let seed: [u8; 32] = seed.try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&seed);

    let mut hasher = Sha256::new();
    hasher.update(body);
    let digest = format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
    );
    let now = unix_now_secs();
    let signature_input = format!(
        "sig1=(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \"x-cokret-origin-service-did\" \"x-cokret-destination-service-did\");created={};expires={};keyid=\"did:web:sync.example.com#push\";alg=\"ed25519\"",
        now - 1,
        now + 300
    );
    let signing_string = [
        format!("\"@method\": {}", method.to_ascii_lowercase()),
        format!("\"@target-uri\": {target_uri}"),
        format!("\"@authority\": {authority}"),
        format!("\"content-digest\": {digest}"),
        "\"x-cokret-origin-service-did\": did:web:sync.example.com".to_owned(),
        "\"x-cokret-destination-service-did\": did:web:push.example.com".to_owned(),
        format!(
            "\"@signature-params\": (\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \"x-cokret-origin-service-did\" \"x-cokret-destination-service-did\");created={};expires={};keyid=\"did:web:sync.example.com#push\";alg=\"ed25519\"",
            now - 1,
            now + 300
        ),
    ]
    .join("\n");
    let signature = signing_key.sign(signing_string.as_bytes());
    let signature = format!(
        "sig1=:{}:",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    );
    (digest, signature_input, signature)
}

#[tokio::test]
async fn http_message_signature_authenticates_notify_request() {
    let seed_hex = "0101010101010101010101010101010101010101010101010101010101010101";
    let public_key_hex = signature_public_key_hex(seed_hex).unwrap();
    let mut principal = NotifyServicePrincipalConfig::default();
    principal.signature_key_id = Some("did:web:sync.example.com#push".to_owned());
    principal.signature_public_key_hex = Some(public_key_hex);
    let service = test_service_with_principal(principal);
    let body = json!({
        "notification": {
            "event_id": "ck:event:01JS0EV000000000000000000",
            "message_id": "ck:message:01JS0MSG0000000000000000",
            "strand_id": "ck:strand:019640f9-8000-7000-8000-000000000000",
            "routing_metadata": {
                "realm_id": "ck:realm:01JS0SP000000000000000000"
            },
            "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
            "wakeup_kind": "message",
            "push_hint": "new_message",
            "devices": [{
                "app_id": "com.example.app",
                "push_key": "accept"
            }]
        }
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let (content_digest, signature_input, signature) = sign_request(
        seed_hex,
        "POST",
        "http://127.0.0.1/_cokret/edge/push/notify",
        "127.0.0.1",
        &body_bytes,
    );

    let response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
        .add_header("host", "127.0.0.1", true)
        .add_header("content-digest", content_digest, true)
        .add_header("signature-input", signature_input, true)
        .add_header("signature", signature, true)
        .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
        .add_header(
            DESTINATION_SERVICE_DID_HEADER,
            "did:web:push.example.com",
            true,
        )
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
}

#[tokio::test]
async fn mtls_profile_authenticates_notify_request() {
    let seed_hex = "0202020202020202020202020202020202020202020202020202020202020202";
    let public_key_hex = signature_public_key_hex(seed_hex).unwrap();
    let mut principal = NotifyServicePrincipalConfig::default();
    principal.signature_key_id = Some("did:web:sync.example.com#push".to_owned());
    principal.signature_public_key_hex = Some(public_key_hex);
    principal.require_mtls = true;
    principal.mtls_cert_fingerprints = vec!["aa:bb:cc".to_owned()];
    let service = test_service_with_principal(principal);
    let body = json!({
        "notification": {
            "event_id": "ck:event:01JS0EV000000000000000000",
            "message_id": "ck:message:01JS0MSG0000000000000000",
            "strand_id": "ck:strand:019640f9-8000-7000-8000-000000000000",
            "routing_metadata": {
                "realm_id": "ck:realm:01JS0SP000000000000000000"
            },
            "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
            "wakeup_kind": "message",
            "push_hint": "new_message",
            "devices": [{
                "app_id": "com.example.app",
                "push_key": "accept"
            }]
        }
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let (content_digest, signature_input, signature) = sign_request(
        seed_hex,
        "POST",
        "http://127.0.0.1/_cokret/edge/push/notify",
        "127.0.0.1",
        &body_bytes,
    );

    let response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
        .add_header("host", "127.0.0.1", true)
        .add_header("content-digest", content_digest, true)
        .add_header("signature-input", signature_input, true)
        .add_header("signature", signature, true)
        .add_header("x-client-certificate-verified", "true", true)
        .add_header("x-client-certificate-sha256", "aa:bb:cc", true)
        .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
        .add_header(
            DESTINATION_SERVICE_DID_HEADER,
            "did:web:push.example.com",
            true,
        )
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
}

#[tokio::test]
async fn mtls_profile_rejects_missing_verified_client_certificate() {
    let seed_hex = "0303030303030303030303030303030303030303030303030303030303030303";
    let public_key_hex = signature_public_key_hex(seed_hex).unwrap();
    let mut principal = NotifyServicePrincipalConfig::default();
    principal.signature_key_id = Some("did:web:sync.example.com#push".to_owned());
    principal.signature_public_key_hex = Some(public_key_hex);
    principal.require_mtls = true;
    let service = test_service_with_principal(principal);
    let body = json!({
        "notification": {
            "event_id": "ck:event:01JS0EV000000000000000000",
            "message_id": "ck:message:01JS0MSG0000000000000000",
            "strand_id": "ck:strand:019640f9-8000-7000-8000-000000000000",
            "routing_metadata": {
                "realm_id": "ck:realm:01JS0SP000000000000000000"
            },
            "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
            "wakeup_kind": "message",
            "push_hint": "new_message",
            "devices": [{
                "app_id": "com.example.app",
                "push_key": "accept"
            }]
        }
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let (content_digest, signature_input, signature) = sign_request(
        seed_hex,
        "POST",
        "http://127.0.0.1/_cokret/edge/push/notify",
        "127.0.0.1",
        &body_bytes,
    );

    let mut response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
        .add_header("host", "127.0.0.1", true)
        .add_header("content-digest", content_digest, true)
        .add_header("signature-input", signature_input, true)
        .add_header("signature", signature, true)
        .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
        .add_header(
            DESTINATION_SERVICE_DID_HEADER,
            "did:web:push.example.com",
            true,
        )
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let body = response.take_string().await.unwrap();
    assert!(body.contains("verified mTLS client certificate is required"));
}

#[test]
fn redacts_proxy_credentials() {
    assert_eq!(
        redact_url_credentials("http://alice:secret@proxy.example.com:8080"),
        "http://***:***@proxy.example.com:8080/"
    );
}

// Pin the verifier's rejection set so a future SDK bump can't
// silently loosen which inputs floria refuses.

#[tokio::test]
async fn rejects_tampered_body() {
    let seed_hex = "0404040404040404040404040404040404040404040404040404040404040404";
    let public_key_hex = signature_public_key_hex(seed_hex).unwrap();
    let mut principal = NotifyServicePrincipalConfig::default();
    principal.signature_key_id = Some("did:web:sync.example.com#push".to_owned());
    principal.signature_public_key_hex = Some(public_key_hex);
    let service = test_service_with_principal(principal);
    let body = json!({
        "notification": {
            "event_id": "ck:event:01JS0EV000000000000000000",
            "message_id": "ck:message:01JS0MSG0000000000000000",
            "strand_id": "ck:strand:019640f9-8000-7000-8000-000000000000",
            "routing_metadata": {
                "realm_id": "ck:realm:01JS0SP000000000000000000"
            },
            "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
            "wakeup_kind": "message",
            "push_hint": "new_message",
            "devices": [{"app_id": "com.example.app", "push_key": "accept"}]
        }
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    // Sign one body, send a *different* body — content-digest
    // recomputation must reject this.
    let (content_digest, signature_input, signature) = sign_request(
        seed_hex,
        "POST",
        "http://127.0.0.1/_cokret/edge/push/notify",
        "127.0.0.1",
        &body_bytes,
    );
    let tampered_body = json!({"hello": "world"});

    let mut response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
        .add_header("host", "127.0.0.1", true)
        .add_header("content-digest", content_digest, true)
        .add_header("signature-input", signature_input, true)
        .add_header("signature", signature, true)
        .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
        .add_header(
            DESTINATION_SERVICE_DID_HEADER,
            "did:web:push.example.com",
            true,
        )
        .json(&tampered_body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let resp_body = response.take_string().await.unwrap();
    assert!(
        resp_body.contains("Content-Digest does not match request body"),
        "expected body-mismatch rejection, got: {resp_body}"
    );
}

#[tokio::test]
async fn rejects_signature_missing_required_components() {
    let seed_hex = "0505050505050505050505050505050505050505050505050505050505050505";
    let public_key_hex = signature_public_key_hex(seed_hex).unwrap();
    let mut principal = NotifyServicePrincipalConfig::default();
    principal.signature_key_id = Some("did:web:sync.example.com#push".to_owned());
    principal.signature_public_key_hex = Some(public_key_hex);
    let service = test_service_with_principal(principal);
    let body = json!({"operation_id": "ck.edge.push.command.notify"});
    let body_bytes = serde_json::to_vec(&body).unwrap();

    let seed = hex::decode(seed_hex).unwrap();
    let seed: [u8; 32] = seed.try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&seed);

    let mut hasher = Sha256::new();
    hasher.update(&body_bytes);
    let digest = format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
    );
    let now = unix_now_secs();
    // Intentionally omit `@authority` from the covered components —
    // floria's required-component policy must still trip this.
    let signature_input = format!(
        "sig1=(\"@method\" \"@target-uri\" \"content-digest\" \"x-cokret-origin-service-did\" \"x-cokret-destination-service-did\");created={};expires={};keyid=\"did:web:sync.example.com#push\";alg=\"ed25519\"",
        now - 1,
        now + 300
    );
    let signing_string = [
        "\"@method\": post".to_owned(),
        "\"@target-uri\": http://127.0.0.1/_cokret/edge/push/notify".to_owned(),
        format!("\"content-digest\": {digest}"),
        "\"x-cokret-origin-service-did\": did:web:sync.example.com".to_owned(),
        "\"x-cokret-destination-service-did\": did:web:push.example.com".to_owned(),
        format!(
            "\"@signature-params\": (\"@method\" \"@target-uri\" \"content-digest\" \"x-cokret-origin-service-did\" \"x-cokret-destination-service-did\");created={};expires={};keyid=\"did:web:sync.example.com#push\";alg=\"ed25519\"",
            now - 1,
            now + 300
        ),
    ]
    .join("\n");
    let signature = signing_key.sign(signing_string.as_bytes());
    let signature = format!(
        "sig1=:{}:",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    );

    let mut response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
        .add_header("host", "127.0.0.1", true)
        .add_header("content-digest", digest, true)
        .add_header("signature-input", signature_input, true)
        .add_header("signature", signature, true)
        .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
        .add_header(
            DESTINATION_SERVICE_DID_HEADER,
            "did:web:push.example.com",
            true,
        )
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let resp_body = response.take_string().await.unwrap();
    assert!(
        resp_body.contains("missing required covered components"),
        "expected required-components rejection, got: {resp_body}"
    );
}
