use std::fmt;

use anyhow::{Context, Result, bail};
use arkret_wire::DidUrl;
use serde::Deserialize;
use serde_json::{Map, Value};

use super::warn_unknown_fields;

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct RegistrationHandoffConfig {
    pub postgres_url: Option<String>,
    pub table: String,
    pub encryption_key_hex: Option<String>,
    pub receipt_signing_key_seed_hex: Option<String>,
    pub receipt_verification_method: Option<String>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl Default for RegistrationHandoffConfig {
    fn default() -> Self {
        Self {
            postgres_url: None,
            table: "floria_push_registration_handoffs".to_owned(),
            encryption_key_hex: None,
            receipt_signing_key_seed_hex: None,
            receipt_verification_method: None,
            extra: Map::new(),
        }
    }
}

impl fmt::Debug for RegistrationHandoffConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistrationHandoffConfig")
            .field(
                "postgres_url",
                &self.postgres_url.as_ref().map(|_| "<redacted>"),
            )
            .field("table", &self.table)
            .field(
                "encryption_key_hex",
                &self.encryption_key_hex.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "receipt_signing_key_seed_hex",
                &self
                    .receipt_signing_key_seed_hex
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field(
                "receipt_verification_method",
                &self.receipt_verification_method,
            )
            .field("extra_keys", &self.extra.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl RegistrationHandoffConfig {
    pub fn enabled(&self) -> bool {
        self.postgres_url
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
    }

    pub fn postgres_url(&self) -> Option<&str> {
        self.postgres_url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn table(&self) -> &str {
        let table = self.table.trim();
        if table.is_empty() {
            "floria_push_registration_handoffs"
        } else {
            table
        }
    }

    pub(super) fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "http.registration_handoff",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
    }

    pub fn validate(&self, gateway_service_id: Option<&arkret_wire::DidCoreId>) -> Result<()> {
        let configured = [
            self.encryption_key_hex.as_deref(),
            self.receipt_signing_key_seed_hex.as_deref(),
            self.receipt_verification_method.as_deref(),
        ]
        .into_iter()
        .any(|value| value.is_some());
        if !self.enabled() {
            if configured {
                bail!(
                    "http.registration_handoff.postgres_url is required when handoff secrets are configured"
                );
            }
            return Ok(());
        }

        crate::postgres_support::validate_postgres_url(
            self.postgres_url().expect("enabled handoff has URL"),
            "http.registration_handoff.postgres_url",
        )?;
        crate::postgres_support::SqlTableName::parse(
            self.table(),
            "http.registration_handoff.table",
        )?;
        decode_32_bytes(
            self.encryption_key_hex.as_deref(),
            "http.registration_handoff.encryption_key_hex",
        )?;
        decode_32_bytes(
            self.receipt_signing_key_seed_hex.as_deref(),
            "http.registration_handoff.receipt_signing_key_seed_hex",
        )?;
        let method = self.receipt_verification_method.as_deref().ok_or_else(|| {
            anyhow::anyhow!("http.registration_handoff.receipt_verification_method is required")
        })?;
        let method = DidUrl::new(method.to_owned()).map_err(|error| {
            anyhow::anyhow!(
                "http.registration_handoff.receipt_verification_method must be a DID URL: {error}"
            )
        })?;
        let controller = method
            .as_str()
            .rsplit_once('#')
            .map(|(controller, _)| controller)
            .ok_or_else(|| {
                anyhow::anyhow!("receipt verification method must contain a fragment")
            })?;
        let controller = arkret_wire::Did::new(controller.to_owned())
            .context("receipt verification method controller must be a DID")?;
        let controller = arkret_wire::project_did_to_core_id(&controller)
            .context("receipt verification method controller must project to a service core id")?;
        if gateway_service_id != Some(&controller) {
            bail!(
                "receipt verification method controller must equal the configured gateway service id"
            );
        }
        Ok(())
    }

    pub(crate) fn encryption_key(&self) -> Result<[u8; 32]> {
        decode_32_bytes(
            self.encryption_key_hex.as_deref(),
            "http.registration_handoff.encryption_key_hex",
        )
    }

    pub(crate) fn receipt_signing_seed(&self) -> Result<[u8; 32]> {
        decode_32_bytes(
            self.receipt_signing_key_seed_hex.as_deref(),
            "http.registration_handoff.receipt_signing_key_seed_hex",
        )
    }
}

fn decode_32_bytes(raw: Option<&str>, field: &str) -> Result<[u8; 32]> {
    let raw = raw.ok_or_else(|| anyhow::anyhow!("{field} is required"))?;
    let decoded = hex::decode(raw).with_context(|| format!("{field} must be hex"))?;
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("{field} must encode exactly 32 bytes"))
}
