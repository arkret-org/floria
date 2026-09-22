//! Durable Station-to-public-Gateway push registration handoff.

use std::fmt::Write as _;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use arkret_models_integration::{
    PushRegistrationHandoffOutcome, PushRegistrationHandoffRequestBody,
    PushRegistrationHandoffState, PushRegistrationInstallationReceipt, PushRegistrationRecord,
};
use arkret_wire::{Audience, DidCoreId, DidUrl, Hash, PayloadProof, proof_kind};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chrono::Utc;
use hkdf::Hkdf;
use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::config::RegistrationHandoffConfig;
use crate::postgres_support::{PostgresPool, SqlTableName};

const ROUTE_AAD_PREFIX: &[u8] = b"floria:push-registration-route:v1\0";
const NONCE_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum ApplyRegistrationError {
    #[error("registration handoff conflicts with durable state")]
    Conflict,
    #[error("registration handoff storage failed: {0}")]
    Storage(#[from] anyhow::Error),
}

#[derive(Clone)]
pub struct RegistrationHandoffStore {
    pool: PostgresPool,
    table: SqlTableName,
    gateway_id: DidCoreId,
    verification_method: DidUrl,
    signing_key: Arc<ed25519_dalek::SigningKey>,
    encryption_master_key: [u8; 32],
}

impl std::fmt::Debug for RegistrationHandoffStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegistrationHandoffStore")
            .field("table", &self.table)
            .field("gateway_id", &self.gateway_id)
            .field("verification_method", &self.verification_method)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptedProviderRoute {
    push_key: arkret_models_integration::PushKey,
    platform: Option<String>,
    app_id: Option<String>,
    visible_notification_opt_in: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    expires_at: Option<chrono::DateTime<Utc>>,
}

struct ExistingRegistration {
    request_digest: String,
    state: String,
    push_target_id: String,
    device_id: String,
    receipt_json: String,
    successor_registration_id: Option<String>,
}

impl RegistrationHandoffStore {
    pub fn from_config(
        config: &RegistrationHandoffConfig,
        gateway_id: DidCoreId,
    ) -> Result<Option<Self>> {
        if !config.enabled() {
            return Ok(None);
        }
        config.validate(Some(&gateway_id))?;
        let verification_method = DidUrl::new(
            config
                .receipt_verification_method
                .clone()
                .expect("validated handoff verification method"),
        )
        .map_err(anyhow::Error::msg)?;
        let store = Self {
            pool: PostgresPool::new(
                config.postgres_url().expect("enabled handoff URL"),
                "public push registration handoff store",
            )?,
            table: SqlTableName::parse(config.table(), "http.registration_handoff.table")?,
            gateway_id,
            verification_method,
            signing_key: Arc::new(ed25519_dalek::SigningKey::from_bytes(
                &config.receipt_signing_seed()?,
            )),
            encryption_master_key: config.encryption_key()?,
        };
        store.ensure_schema()?;
        Ok(Some(store))
    }

    fn ensure_schema(&self) -> Result<()> {
        let statement = format!(
            "CREATE TABLE IF NOT EXISTS {table} (\
                source_station_id TEXT NOT NULL,\
                registration_id TEXT NOT NULL,\
                request_digest TEXT NOT NULL,\
                state TEXT NOT NULL CHECK (state IN ('active', 'revoked')),\
                push_target_id TEXT NOT NULL,\
                device_id TEXT NOT NULL,\
                route_ciphertext TEXT NULL,\
                receipt_json TEXT NOT NULL,\
                successor_registration_id TEXT NULL,\
                stored_at TEXT NOT NULL,\
                PRIMARY KEY (source_station_id, registration_id)\
            )",
            table = self.table.as_sql(),
        );
        self.pool.with_client(|client| {
            client
                .batch_execute(&statement)
                .context("failed to initialize registration handoff table")
        })
    }

    pub async fn apply(
        &self,
        source: DidCoreId,
        destination: DidCoreId,
        request: PushRegistrationHandoffRequestBody,
    ) -> Result<PushRegistrationHandoffOutcome, ApplyRegistrationError> {
        if destination != self.gateway_id {
            return Err(ApplyRegistrationError::Conflict);
        }
        request.validate().map_err(|error| {
            ApplyRegistrationError::Storage(anyhow::anyhow!("invalid handoff request: {error}"))
        })?;
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.apply_blocking(&source, &request))
            .await
            .context("registration handoff task failed")?
    }

    pub async fn resolve(
        &self,
        source: &DidCoreId,
        target: &arkret_wire::PushTargetId,
        device: &arkret_wire::DeviceId,
        gateway_url: &str,
    ) -> Result<Option<PushRegistrationRecord>> {
        let store = self.clone();
        let source = source.clone();
        let target = target.clone();
        let device = device.clone();
        let gateway_url = gateway_url.to_owned();
        tokio::task::spawn_blocking(move || {
            store.resolve_blocking(&source, &target, &device, &gateway_url)
        })
        .await
        .context("registration handoff lookup task failed")?
    }

    /// Permanently suppress a provider route that the provider has rejected.
    ///
    /// The Station may subsequently submit the canonical revoked handoff to
    /// obtain its signed receipt.  Until then the retained active receipt is
    /// only historical evidence: the ciphertext is gone and an active replay
    /// cannot restore it.
    pub async fn terminalize_provider_invalidation(
        &self,
        source: &DidCoreId,
        registration: &PushRegistrationRecord,
    ) -> Result<()> {
        let store = self.clone();
        let source = source.clone();
        let registration_id = registration.registration_id.as_str().to_owned();
        let target = registration.push_target_id.clone();
        let device = registration.device_id.clone();
        tokio::task::spawn_blocking(move || {
            store.terminalize_provider_invalidation_blocking(
                &source,
                &registration_id,
                &target,
                &device,
            )
        })
        .await
        .context("registration invalidation task failed")?
    }

    fn resolve_blocking(
        &self,
        source: &DidCoreId,
        target: &arkret_wire::PushTargetId,
        device: &arkret_wire::DeviceId,
        gateway_url: &str,
    ) -> Result<Option<PushRegistrationRecord>> {
        self.pool.with_client(|client| {
            let mut transaction = client
                .build_transaction()
                .isolation_level(postgres::IsolationLevel::Serializable)
                .start()?;
            let rows = transaction.query(
                &format!(
                    "SELECT registration_id,route_ciphertext FROM {table} WHERE source_station_id=$1 AND state='active' AND push_target_id=$2 AND device_id=$3 AND successor_registration_id IS NULL FOR UPDATE",
                    table = self.table.as_sql(),
                ),
                &[&source.as_str(), &target.as_str(), &device.as_str()],
            )?;
            let at = Utc::now();
            let mut selected = None;
            for row in rows {
                let registration_id: String = row.get(0);
                let ciphertext: Option<String> = row.get(1);
                let ciphertext = ciphertext
                    .ok_or_else(|| anyhow::anyhow!("active handoff has no provider route"))?;
                let route = self.open_route(source, &registration_id, &ciphertext)?;
                if route.expires_at.is_some_and(|expires_at| at >= expires_at) {
                    tombstone_route(
                        &mut transaction,
                        self.table.as_sql(),
                        source,
                        &registration_id,
                        target,
                        device,
                        at,
                    )?;
                    continue;
                }
                let registration = PushRegistrationRecord {
                    registration_id: arkret_wire::OpaqueLocalId::new(registration_id)
                        .map_err(anyhow::Error::msg)?,
                    // This transient adapter value exists only because provider
                    // drivers currently consume the shared-deployment record.
                    // It is never persisted and carries no user Account authority.
                    account_id: arkret_wire::AccountId::new(source.clone(), source.clone()),
                    device_id: device.clone(),
                    push_gateway: gateway_url.to_owned(),
                    push_key: route.push_key,
                    platform: route.platform,
                    app_id: route.app_id.clone(),
                    visible_notification_opt_in: route.visible_notification_opt_in,
                    push_route_id: route.app_id.unwrap_or_default(),
                    push_target_id: target.clone(),
                    salt_epoch_id: "public-gateway-handoff-v1".to_owned(),
                    expires_at: route.expires_at,
                    retained_push_targets: Vec::new(),
                };
                if selected.replace(registration).is_some() {
                    bail!("ambiguous active handoff for push target/device");
                }
            }
            transaction.commit()?;
            Ok(selected)
        })
    }

    fn terminalize_provider_invalidation_blocking(
        &self,
        source: &DidCoreId,
        registration_id: &str,
        target: &arkret_wire::PushTargetId,
        device: &arkret_wire::DeviceId,
    ) -> Result<()> {
        self.pool.with_client(|client| {
            let mut transaction = client
                .build_transaction()
                .isolation_level(postgres::IsolationLevel::Serializable)
                .start()?;
            tombstone_route(
                &mut transaction,
                self.table.as_sql(),
                source,
                registration_id,
                target,
                device,
                Utc::now(),
            )?;
            transaction.commit()?;
            Ok(())
        })
    }

    fn apply_blocking(
        &self,
        source: &DidCoreId,
        request: &PushRegistrationHandoffRequestBody,
    ) -> Result<PushRegistrationHandoffOutcome, ApplyRegistrationError> {
        let request_digest = request.request_digest().map_err(|error| {
            ApplyRegistrationError::Storage(anyhow::anyhow!("failed to digest handoff: {error}"))
        })?;
        self.pool
            .with_client(|client| {
                let mut transaction = client
                    .build_transaction()
                    .isolation_level(postgres::IsolationLevel::Serializable)
                    .start()?;
                let route_lock_key = advisory_lock_key(
                    "route",
                    [
                        source.as_str(),
                        request.push_target_id().as_str(),
                        request.device_id().as_str(),
                    ],
                );
                transaction.query_one(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                    &[&route_lock_key],
                )?;
                let mut lock_ids = vec![request.registration_id().as_str()];
                if let PushRegistrationHandoffRequestBody::Active {
                    supersedes_registration_id: Some(predecessor_id),
                    ..
                } = request
                {
                    lock_ids.push(predecessor_id.as_str());
                }
                lock_ids.sort_unstable();
                for registration_id in lock_ids {
                    let lock_key = advisory_lock_key(
                        "registration",
                        [source.as_str(), registration_id],
                    );
                    transaction.query_one(
                        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                        &[&lock_key],
                    )?;
                }
                let existing = load_existing(
                    &mut transaction,
                    self.table.as_sql(),
                    source,
                    request.registration_id().as_str(),
                )?;
                if let Some(existing) = existing {
                    if existing.request_digest == request_digest.as_str()
                        && existing.state == request.state().as_str()
                    {
                        let receipt = serde_json::from_str(&existing.receipt_json)
                            .context("invalid durable registration receipt")?;
                        transaction.commit()?;
                        return Ok(PushRegistrationHandoffOutcome { receipt });
                    }
                    if !matches!(request, PushRegistrationHandoffRequestBody::Revoked { .. })
                        || (existing.state != PushRegistrationHandoffState::Active.as_str()
                            && existing.state != PushRegistrationHandoffState::Revoked.as_str())
                        || existing.push_target_id != request.push_target_id().as_str()
                        || existing.device_id != request.device_id().as_str()
                        || existing.successor_registration_id.is_some()
                    {
                        bail!(ConflictMarker);
                    }
                    let receipt = self.build_receipt(source, request, request_digest.clone())?;
                    let receipt_json = serde_json::to_string(&receipt)?;
                    transaction.execute(
                        &format!(
                            "UPDATE {table} SET request_digest=$3,state='revoked',route_ciphertext=NULL,receipt_json=$4,stored_at=$5 WHERE source_station_id=$1 AND registration_id=$2",
                            table = self.table.as_sql(),
                        ),
                        &[
                            &source.as_str(),
                            &request.registration_id().as_str(),
                            &request_digest.as_str(),
                            &receipt_json,
                            &arkret_canonical::format_timestamp_canonical(receipt.stored_at),
                        ],
                    )?;
                    transaction.commit()?;
                    return Ok(PushRegistrationHandoffOutcome { receipt });
                }

                let route_ciphertext = match request {
                    PushRegistrationHandoffRequestBody::Active {
                        push_key,
                        platform,
                        app_id,
                        visible_notification_opt_in,
                        expires_at,
                        supersedes_registration_id,
                        ..
                    } => {
                        let active_registration_ids = transaction
                            .query(
                                &format!(
                                    "SELECT registration_id FROM {table} WHERE source_station_id=$1 AND state='active' AND push_target_id=$2 AND device_id=$3 FOR UPDATE",
                                    table = self.table.as_sql(),
                                ),
                                &[
                                    &source.as_str(),
                                    &request.push_target_id().as_str(),
                                    &request.device_id().as_str(),
                                ],
                            )?
                            .into_iter()
                            .map(|row| row.get::<_, String>(0))
                            .collect::<Vec<_>>();
                        if let Some(predecessor_id) = supersedes_registration_id {
                            if active_registration_ids.as_slice()
                                != [predecessor_id.as_str()]
                            {
                                bail!(ConflictMarker);
                            }
                            let predecessor = load_existing(
                                &mut transaction,
                                self.table.as_sql(),
                                source,
                                predecessor_id.as_str(),
                            )?
                            .ok_or(ConflictMarker)?;
                            if predecessor.state != PushRegistrationHandoffState::Active.as_str()
                                || predecessor.device_id != request.device_id().as_str()
                                || predecessor.push_target_id != request.push_target_id().as_str()
                                || predecessor.successor_registration_id.is_some()
                            {
                                bail!(ConflictMarker);
                            }
                            transaction.execute(
                                &format!(
                                    "UPDATE {table} SET state='revoked',route_ciphertext=NULL,successor_registration_id=$3 WHERE source_station_id=$1 AND registration_id=$2",
                                    table = self.table.as_sql(),
                                ),
                                &[
                                    &source.as_str(),
                                    &predecessor_id.as_str(),
                                    &request.registration_id().as_str(),
                                ],
                            )?;
                        } else if !active_registration_ids.is_empty() {
                            bail!(ConflictMarker);
                        }
                        let route = EncryptedProviderRoute {
                            push_key: push_key.clone(),
                            platform: platform.clone(),
                            app_id: app_id.clone(),
                            visible_notification_opt_in: *visible_notification_opt_in,
                            expires_at: *expires_at,
                        };
                        Some(self.seal_route(source, request.registration_id().as_str(), &route)?)
                    }
                    PushRegistrationHandoffRequestBody::Revoked { .. } => None,
                };
                let receipt = self.build_receipt(source, request, request_digest.clone())?;
                let receipt_json = serde_json::to_string(&receipt)?;
                transaction.execute(
                    &format!(
                        "INSERT INTO {table} (source_station_id,registration_id,request_digest,state,push_target_id,device_id,route_ciphertext,receipt_json,stored_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
                        table = self.table.as_sql(),
                    ),
                    &[
                        &source.as_str(),
                        &request.registration_id().as_str(),
                        &request_digest.as_str(),
                        &request.state().as_str(),
                        &request.push_target_id().as_str(),
                        &request.device_id().as_str(),
                        &route_ciphertext,
                        &receipt_json,
                        &arkret_canonical::format_timestamp_canonical(receipt.stored_at),
                    ],
                )?;
                transaction.commit()?;
                Ok(PushRegistrationHandoffOutcome { receipt })
            })
            .map_err(|error| {
                if error.downcast_ref::<ConflictMarker>().is_some() {
                    ApplyRegistrationError::Conflict
                } else {
                    ApplyRegistrationError::Storage(error)
                }
            })
    }

    fn build_receipt(
        &self,
        source: &DidCoreId,
        request: &PushRegistrationHandoffRequestBody,
        request_digest: Hash,
    ) -> Result<PushRegistrationInstallationReceipt> {
        let stored_at = Utc::now();
        let mut receipt = PushRegistrationInstallationReceipt {
            registration_id: request.registration_id().clone(),
            push_target_id: request.push_target_id().clone(),
            device_id: request.device_id().clone(),
            state: request.state(),
            request_digest: request_digest.clone(),
            source_station_id: source.clone(),
            destination_gateway_id: self.gateway_id.clone(),
            stored_at,
            proof: PayloadProof {
                kind: proof_kind::DETACHED_JWS.to_owned(),
                verification_method: self.verification_method.clone(),
                payload_digest: request_digest,
                created_at: stored_at,
                domain: None,
                audience: Some(Audience::Single(source.as_str().to_owned())),
                proof_purpose: None,
                jws: "eyJhbGciOiJFZDI1NTE5In0..placeholder".to_owned(),
            },
        };
        receipt.proof.payload_digest = receipt.expected_payload_digest()?;
        receipt.proof.jws = arkret_signatures::sign_ed25519_detached_jws(
            &self.signing_key,
            &receipt.proof_binding_bytes()?,
        )?;
        receipt.validate_for_handoff(request, source, &self.gateway_id)?;
        Ok(receipt)
    }

    fn seal_route(
        &self,
        source: &DidCoreId,
        registration_id: &str,
        route: &EncryptedProviderRoute,
    ) -> Result<String> {
        let cipher = self.tenant_cipher(source)?;
        let aad = route_aad(source, registration_id);
        let plaintext = arkret_canonical::canonical::canonical_json_bytes(route)?;
        let mut nonce_bytes = [0_u8; NONCE_LEN];
        rand::rng().fill(&mut nonce_bytes);
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("provider route encryption failed"))?;
        let mut envelope = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ciphertext);
        Ok(base64::engine::general_purpose::STANDARD.encode(envelope))
    }

    fn open_route(
        &self,
        source: &DidCoreId,
        registration_id: &str,
        envelope: &str,
    ) -> Result<EncryptedProviderRoute> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(envelope)
            .context("provider route envelope is not base64")?;
        if bytes.len() < NONCE_LEN {
            bail!("provider route envelope is shorter than its nonce");
        }
        let (nonce_bytes, ciphertext) = bytes.split_at(NONCE_LEN);
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = self
            .tenant_cipher(source)?
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &route_aad(source, registration_id),
                },
            )
            .map_err(|_| anyhow::anyhow!("provider route decryption failed"))?;
        serde_json::from_slice(&plaintext).context("provider route plaintext is invalid")
    }

    fn tenant_cipher(&self, source: &DidCoreId) -> Result<ChaCha20Poly1305> {
        let hkdf = Hkdf::<Sha256>::new(
            Some(b"floria:push-registration-tenant:v1"),
            &self.encryption_master_key,
        );
        let mut key = [0_u8; 32];
        hkdf.expand(source.as_str().as_bytes(), &mut key)
            .map_err(|_| anyhow::anyhow!("failed to derive tenant registration key"))?;
        #[allow(deprecated)]
        Ok(ChaCha20Poly1305::new(Key::from_slice(&key)))
    }
}

fn route_aad(source: &DidCoreId, registration_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        ROUTE_AAD_PREFIX.len() + source.as_str().len() + registration_id.len() + 1,
    );
    aad.extend_from_slice(ROUTE_AAD_PREFIX);
    aad.extend_from_slice(source.as_str().as_bytes());
    aad.push(0);
    aad.extend_from_slice(registration_id.as_bytes());
    aad
}

fn advisory_lock_key<'a>(namespace: &str, parts: impl IntoIterator<Item = &'a str>) -> String {
    let mut key = String::from(namespace);
    for part in parts {
        write!(&mut key, "|{}:{part}", part.len()).expect("writing to String cannot fail");
    }
    key
}

fn load_existing(
    transaction: &mut postgres::Transaction<'_>,
    table: &str,
    source: &DidCoreId,
    registration_id: &str,
) -> Result<Option<ExistingRegistration>> {
    transaction
        .query_opt(
            &format!(
                "SELECT request_digest,state,push_target_id,device_id,receipt_json,successor_registration_id FROM {table} WHERE source_station_id=$1 AND registration_id=$2 FOR UPDATE"
            ),
            &[&source.as_str(), &registration_id],
        )?
        .map(|row| {
            Ok(ExistingRegistration {
                request_digest: row.get(0),
                state: row.get(1),
                push_target_id: row.get(2),
                device_id: row.get(3),
                receipt_json: row.get(4),
                successor_registration_id: row.get(5),
            })
        })
        .transpose()
}

fn tombstone_route(
    transaction: &mut postgres::Transaction<'_>,
    table: &str,
    source: &DidCoreId,
    registration_id: &str,
    target: &arkret_wire::PushTargetId,
    device: &arkret_wire::DeviceId,
    at: chrono::DateTime<Utc>,
) -> Result<()> {
    transaction.execute(
        &format!(
            "UPDATE {table} SET state='revoked',route_ciphertext=NULL,stored_at=$5 WHERE source_station_id=$1 AND registration_id=$2 AND state='active' AND push_target_id=$3 AND device_id=$4 AND successor_registration_id IS NULL AND route_ciphertext IS NOT NULL"
        ),
        &[
            &source.as_str(),
            &registration_id,
            &target.as_str(),
            &device.as_str(),
            &arkret_canonical::format_timestamp_canonical(at),
        ],
    )?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
#[error("registration conflict")]
struct ConflictMarker;

#[cfg(test)]
mod tests {
    use arkret_signatures::{PublicKeyMaterial, verify_ed25519_detached_jws_payload_proof};

    use super::*;

    fn source(value: &str) -> DidCoreId {
        arkret_wire::project_did_to_core_id(&arkret_wire::Did::new(value).unwrap()).unwrap()
    }

    fn store() -> RegistrationHandoffStore {
        RegistrationHandoffStore {
            pool: PostgresPool::new("postgres://localhost/floria", "unused test pool").unwrap(),
            table: SqlTableName::parse("handoff_test", "test").unwrap(),
            gateway_id: source("did:web:gateway.example"),
            verification_method: DidUrl::new("did:web:gateway.example#receipt").unwrap(),
            signing_key: Arc::new(ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32])),
            encryption_master_key: [11_u8; 32],
        }
    }

    fn active_request() -> PushRegistrationHandoffRequestBody {
        serde_json::from_value(serde_json::json!({
            "registration_id": "registration_0123456789abcdef",
            "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "state": "active",
            "push_key": "provider-secret",
            "platform": "apns",
            "app_id": "org.arkret.fixture",
            "visible_notification_opt_in": false
        }))
        .unwrap()
    }

    #[test]
    fn receipt_signs_the_sdk_owned_binding() {
        let store = store();
        let request = active_request();
        let source = source("did:web:station.example");
        let receipt = store
            .build_receipt(&source, &request, request.request_digest().unwrap())
            .unwrap();

        receipt
            .validate_for_handoff(&request, &source, &store.gateway_id)
            .unwrap();
        verify_ed25519_detached_jws_payload_proof(
            &receipt.proof,
            &receipt.proof_binding_bytes().unwrap(),
            &PublicKeyMaterial::Ed25519Raw {
                bytes: store.signing_key.verifying_key().to_bytes().to_vec(),
            },
        )
        .unwrap();
        assert!(
            !serde_json::to_string(&receipt)
                .unwrap()
                .contains("provider-secret")
        );
    }

    #[test]
    fn provider_route_ciphertext_is_bound_to_tenant_and_registration() {
        let store = store();
        let source_a = source("did:web:station-a.example");
        let source_b = source("did:web:station-b.example");
        let request = active_request();
        let PushRegistrationHandoffRequestBody::Active {
            push_key,
            platform,
            app_id,
            visible_notification_opt_in,
            expires_at,
            ..
        } = request
        else {
            unreachable!()
        };
        let route = EncryptedProviderRoute {
            push_key,
            platform,
            app_id,
            visible_notification_opt_in,
            expires_at,
        };
        let registration_id = "registration_0123456789abcdef";
        let sealed = store
            .seal_route(&source_a, registration_id, &route)
            .unwrap();

        let opened = store
            .open_route(&source_a, registration_id, &sealed)
            .unwrap();
        assert_eq!(opened.push_key.as_str(), "provider-secret");
        assert!(
            store
                .open_route(&source_b, registration_id, &sealed)
                .is_err()
        );
        assert!(
            store
                .open_route(&source_a, "registration_fedcba9876543210", &sealed)
                .is_err()
        );
    }

    #[test]
    fn advisory_lock_keys_are_postgres_text_and_unambiguous() {
        let first = advisory_lock_key("route", ["ab", "c"]);
        let second = advisory_lock_key("route", ["a", "bc"]);
        assert_ne!(first, second);
        assert!(!first.as_bytes().contains(&0));
        assert_eq!(first, "route|2:ab|1:c");
    }

    #[tokio::test]
    async fn postgres_handoff_is_exactly_replayable_and_terminal() {
        let Ok(postgres_url) = std::env::var("FLORIA_HANDOFF_TEST_DATABASE_URL") else {
            return;
        };
        let gateway = source("did:web:gateway.example");
        let mut config = RegistrationHandoffConfig::default();
        config.postgres_url = Some(postgres_url);
        config.encryption_key_hex = Some(hex::encode([11_u8; 32]));
        config.receipt_signing_key_seed_hex = Some(hex::encode([7_u8; 32]));
        config.receipt_verification_method = Some("did:web:gateway.example#receipt".to_owned());
        let store = RegistrationHandoffStore::from_config(&config, gateway.clone())
            .unwrap()
            .unwrap();
        let source = source(&format!(
            "did:web:station-{}.example",
            uuid::Uuid::new_v4().simple()
        ));
        let registration_id = format!("registration_{}", uuid::Uuid::new_v4().simple());
        let request: PushRegistrationHandoffRequestBody =
            serde_json::from_value(serde_json::json!({
                "registration_id": registration_id,
                "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
                "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                "state": "active",
                "push_key": "provider-secret",
                "platform": "apns",
                "app_id": "org.arkret.fixture",
                "visible_notification_opt_in": false
            }))
            .unwrap();
        let first = store
            .apply(source.clone(), gateway.clone(), request.clone())
            .await
            .unwrap();
        let replay = store
            .apply(source.clone(), gateway.clone(), request.clone())
            .await
            .unwrap();
        assert_eq!(first, replay);
        assert_eq!(
            store
                .resolve(
                    &source,
                    request.push_target_id(),
                    request.device_id(),
                    "https://gateway.example/",
                )
                .await
                .unwrap()
                .unwrap()
                .push_key
                .as_str(),
            "provider-secret"
        );

        let conflicting: PushRegistrationHandoffRequestBody =
            serde_json::from_value(serde_json::json!({
                "registration_id": registration_id,
                "push_target_id": request.push_target_id(),
                "device_id": request.device_id(),
                "state": "active",
                "push_key": "different-secret",
                "platform": "apns",
                "app_id": "org.arkret.fixture",
                "visible_notification_opt_in": false
            }))
            .unwrap();
        assert!(matches!(
            store
                .apply(source.clone(), gateway.clone(), conflicting)
                .await,
            Err(ApplyRegistrationError::Conflict)
        ));

        let revoked: PushRegistrationHandoffRequestBody =
            serde_json::from_value(serde_json::json!({
                "registration_id": registration_id,
                "push_target_id": request.push_target_id(),
                "device_id": request.device_id(),
                "state": "revoked"
            }))
            .unwrap();
        store
            .apply(source.clone(), gateway.clone(), revoked.clone())
            .await
            .unwrap();
        assert!(
            store
                .resolve(
                    &source,
                    revoked.push_target_id(),
                    revoked.device_id(),
                    "https://gateway.example/",
                )
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            store.apply(source.clone(), gateway.clone(), request).await,
            Err(ApplyRegistrationError::Conflict)
        ));

        let provider_invalid_request: PushRegistrationHandoffRequestBody =
            serde_json::from_value(serde_json::json!({
                "registration_id": format!("registration_{}", uuid::Uuid::new_v4().simple()),
                "push_target_id": revoked.push_target_id(),
                "device_id": revoked.device_id(),
                "state": "active",
                "push_key": "provider-invalid-secret",
                "platform": "apns",
                "app_id": "org.arkret.fixture",
                "visible_notification_opt_in": false
            }))
            .unwrap();
        store
            .apply(
                source.clone(),
                gateway.clone(),
                provider_invalid_request.clone(),
            )
            .await
            .unwrap();
        let provider_invalid_registration = store
            .resolve(
                &source,
                provider_invalid_request.push_target_id(),
                provider_invalid_request.device_id(),
                "https://gateway.example/",
            )
            .await
            .unwrap()
            .unwrap();
        store
            .terminalize_provider_invalidation(&source, &provider_invalid_registration)
            .await
            .unwrap();
        assert!(
            store
                .resolve(
                    &source,
                    provider_invalid_request.push_target_id(),
                    provider_invalid_request.device_id(),
                    "https://gateway.example/",
                )
                .await
                .unwrap()
                .is_none()
        );

        let provider_invalid_revoked: PushRegistrationHandoffRequestBody =
            serde_json::from_value(serde_json::json!({
                "registration_id": provider_invalid_request.registration_id(),
                "push_target_id": provider_invalid_request.push_target_id(),
                "device_id": provider_invalid_request.device_id(),
                "state": "revoked"
            }))
            .unwrap();
        let terminal_receipt = store
            .apply(source, gateway, provider_invalid_revoked.clone())
            .await
            .unwrap();
        assert_eq!(
            terminal_receipt.receipt.state,
            PushRegistrationHandoffState::Revoked
        );
        assert_eq!(
            terminal_receipt.receipt.request_digest,
            provider_invalid_revoked.request_digest().unwrap()
        );
    }

    #[tokio::test]
    async fn postgres_handoff_supersede_and_tenant_isolation() {
        let Ok(postgres_url) = std::env::var("FLORIA_HANDOFF_TEST_DATABASE_URL") else {
            return;
        };
        let gateway = source("did:web:gateway.example");
        let mut config = RegistrationHandoffConfig::default();
        config.postgres_url = Some(postgres_url);
        config.encryption_key_hex = Some(hex::encode([11_u8; 32]));
        config.receipt_signing_key_seed_hex = Some(hex::encode([7_u8; 32]));
        config.receipt_verification_method = Some("did:web:gateway.example#receipt".to_owned());
        let store = RegistrationHandoffStore::from_config(&config, gateway.clone())
            .unwrap()
            .unwrap();
        let source_a = source(&format!(
            "did:web:station-a-{}.example",
            uuid::Uuid::new_v4().simple()
        ));
        let source_b = source(&format!(
            "did:web:station-b-{}.example",
            uuid::Uuid::new_v4().simple()
        ));
        let source_c = source(&format!(
            "did:web:station-c-{}.example",
            uuid::Uuid::new_v4().simple()
        ));
        let predecessor_id = format!("registration_{}", uuid::Uuid::new_v4().simple());
        let successor_id = format!("registration_{}", uuid::Uuid::new_v4().simple());
        let target = "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8";
        let device = "ak:device:01904100-0000-7000-8000-000000000001";
        let predecessor: PushRegistrationHandoffRequestBody =
            serde_json::from_value(serde_json::json!({
                "registration_id": predecessor_id,
                "push_target_id": target,
                "device_id": device,
                "state": "active",
                "push_key": "tenant-local-provider-secret",
                "platform": "apns",
                "app_id": "org.arkret.fixture",
                "visible_notification_opt_in": false
            }))
            .unwrap();

        let receipt_a = store
            .apply(source_a.clone(), gateway.clone(), predecessor.clone())
            .await
            .unwrap();
        let receipt_b = store
            .apply(source_b.clone(), gateway.clone(), predecessor.clone())
            .await
            .unwrap();
        assert_eq!(receipt_a.receipt.source_station_id, source_a);
        assert_eq!(receipt_b.receipt.source_station_id, source_b);
        assert_ne!(receipt_a.receipt, receipt_b.receipt);

        let successor: PushRegistrationHandoffRequestBody =
            serde_json::from_value(serde_json::json!({
                "registration_id": successor_id,
                "push_target_id": target,
                "device_id": device,
                "state": "active",
                "push_key": "rotated-provider-secret",
                "platform": "apns",
                "app_id": "org.arkret.fixture",
                "visible_notification_opt_in": true,
                "supersedes_registration_id": predecessor.registration_id()
            }))
            .unwrap();
        store
            .apply(source_a.clone(), gateway.clone(), successor.clone())
            .await
            .unwrap();
        assert_eq!(
            store
                .resolve(
                    &source_a,
                    successor.push_target_id(),
                    successor.device_id(),
                    "https://gateway.example/",
                )
                .await
                .unwrap()
                .unwrap()
                .push_key
                .as_str(),
            "rotated-provider-secret"
        );
        assert!(matches!(
            store
                .apply(source_a.clone(), gateway.clone(), predecessor.clone())
                .await,
            Err(ApplyRegistrationError::Conflict)
        ));
        assert_eq!(
            store
                .resolve(
                    &source_b,
                    predecessor.push_target_id(),
                    predecessor.device_id(),
                    "https://gateway.example/",
                )
                .await
                .unwrap()
                .unwrap()
                .push_key
                .as_str(),
            "tenant-local-provider-secret"
        );

        let cross_tenant_successor: PushRegistrationHandoffRequestBody =
            serde_json::from_value(serde_json::json!({
                "registration_id": format!("registration_{}", uuid::Uuid::new_v4().simple()),
                "push_target_id": target,
                "device_id": device,
                "state": "active",
                "push_key": "cross-tenant-attempt",
                "platform": "apns",
                "app_id": "org.arkret.fixture",
                "visible_notification_opt_in": false,
                "supersedes_registration_id": predecessor.registration_id()
            }))
            .unwrap();
        assert!(matches!(
            store
                .apply(source_c, gateway.clone(), cross_tenant_successor)
                .await,
            Err(ApplyRegistrationError::Conflict)
        ));

        let wrong_target_revocation: PushRegistrationHandoffRequestBody =
            serde_json::from_value(serde_json::json!({
                "registration_id": successor.registration_id(),
                "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm9",
                "device_id": device,
                "state": "revoked"
            }))
            .unwrap();
        assert!(matches!(
            store
                .apply(source_a.clone(), gateway.clone(), wrong_target_revocation)
                .await,
            Err(ApplyRegistrationError::Conflict)
        ));
        assert!(matches!(
            store
                .apply(source_a, source("did:web:wrong-gateway.example"), successor,)
                .await,
            Err(ApplyRegistrationError::Conflict)
        ));
    }
}
