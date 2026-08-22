use std::fmt;

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use serde_json::{Map, Value};

use super::warn_unknown_fields;

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    pub backend: String,
    pub file_path: Option<String>,
    pub endpoint: Option<String>,
    pub bearer_token: Option<String>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl fmt::Debug for AuditConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bearer_token = if self.bearer_token.is_some() {
            "<redacted>"
        } else {
            "<none>"
        };
        f.debug_struct("AuditConfig")
            .field("backend", &self.backend)
            .field("file_path", &self.file_path)
            .field("endpoint", &self.endpoint)
            .field("bearer_token", &bearer_token)
            .field("extra_keys", &self.extra.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            backend: "disabled".to_owned(),
            file_path: None,
            endpoint: None,
            bearer_token: None,
            extra: Map::new(),
        }
    }
}

impl AuditConfig {
    pub fn backend_kind(&self) -> &str {
        let backend = self.backend.trim();
        if backend.is_empty() {
            "disabled"
        } else {
            backend
        }
    }

    pub fn file_path(&self) -> Option<&str> {
        self.file_path
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn endpoint(&self) -> Option<&str> {
        self.endpoint
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn bearer_token(&self) -> Option<&str> {
        self.bearer_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub(super) fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "audit",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
    }

    pub fn validate(&self) -> Result<()> {
        match self.backend_kind() {
            "disabled" => Ok(()),
            "file" => {
                if self.file_path().is_none() {
                    bail!("audit.file_path is required when audit.backend=file");
                }
                Ok(())
            }
            "http" => {
                let endpoint = self
                    .endpoint()
                    .ok_or_else(|| anyhow!("audit.endpoint is required when audit.backend=http"))?;
                let parsed = endpoint
                    .parse::<reqwest::Url>()
                    .with_context(|| "audit.endpoint must be an absolute HTTP(S) URL")?;
                match parsed.scheme() {
                    "http" | "https" => {
                        crate::egress::validate_url_for_egress(&parsed, "audit.endpoint")
                            .map_err(anyhow::Error::msg)?;
                        Ok(())
                    }
                    scheme => bail!("audit.endpoint must use http or https, got `{scheme}`"),
                }
            }
            backend => bail!("audit.backend must be one of: disabled, file, http; got `{backend}`"),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    pub postgres_url: Option<String>,
    pub deactivation_queue_table: String,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            postgres_url: None,
            deactivation_queue_table: "floria_push_delivery_queue".to_owned(),
            extra: Map::new(),
        }
    }
}

impl StorageConfig {
    pub fn postgres_url(&self) -> Option<&str> {
        self.postgres_url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn deactivation_queue_table(&self) -> &str {
        let value = self.deactivation_queue_table.trim();
        if value.is_empty() {
            "floria_push_delivery_queue"
        } else {
            value
        }
    }

    pub(super) fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "storage",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(url) = self.postgres_url() {
            crate::postgres_support::validate_postgres_url(url, "storage.postgres_url")?;
        }
        crate::postgres_support::SqlTableName::parse(
            self.deactivation_queue_table(),
            "storage.deactivation_queue_table",
        )?;
        Ok(())
    }
}
