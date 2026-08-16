use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::models::RejectedDevice;

#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn record(&self, event: &AuditEvent) -> Result<()>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum AuditEvent {
    #[serde(rename = "org.arkret.floria.audit.policy_access")]
    PolicyAccess {
        request_id: String,
        origin_service_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        destination_service_id: Option<String>,
        access_kind: String,
    },
    // Floria's audit-sink record is an implementation event, not an Arkret
    // wire event kind. Product-local names must not occupy the `ak.*`
    // protocol namespace.
    #[serde(rename = "org.arkret.floria.audit.push_rejected_devices")]
    RejectedDevices {
        request_id: String,
        origin_service_id: String,
        devices: Vec<RejectedDevice>,
    },
}

#[derive(Debug)]
pub struct JsonlAuditSink {
    path: PathBuf,
    lock: Mutex<()>,
}

impl JsonlAuditSink {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Mutex::new(()),
        }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

#[async_trait]
impl AuditSink for JsonlAuditSink {
    async fn record(&self, event: &AuditEvent) -> Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| anyhow!("audit JSONL sink lock poisoned"))?;
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create audit JSONL directory {}",
                    parent.display()
                )
            })?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("failed to open audit JSONL file {}", self.path.display()))?;
        serde_json::to_writer(&mut file, event).with_context(|| {
            format!("failed to serialize audit event to {}", self.path.display())
        })?;
        file.write_all(b"\n").with_context(|| {
            format!(
                "failed to write audit JSONL newline to {}",
                self.path.display()
            )
        })?;
        file.flush()
            .with_context(|| format!("failed to flush audit JSONL file {}", self.path.display()))?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct HttpAuditSink {
    client: reqwest::Client,
    endpoint: String,
    bearer_token: Option<String>,
}

impl HttpAuditSink {
    pub fn new(endpoint: impl Into<String>, bearer_token: Option<String>) -> Self {
        Self {
            // Bound connect + overall time so a stalled audit endpoint
            // cannot block the dispatch path indefinitely (mirrors the
            // pushkin reqwest_support CONNECT_TIMEOUT / REQUEST_TIMEOUT).
            client: reqwest::Client::builder()
                .https_only(true)
                .connect_timeout(std::time::Duration::from_secs(5))
                .timeout(std::time::Duration::from_secs(30))
                .dns_resolver(crate::egress::dns_resolver())
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("build audit HTTP client"),
            endpoint: endpoint.into(),
            bearer_token,
        }
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

#[async_trait]
impl AuditSink for HttpAuditSink {
    async fn record(&self, event: &AuditEvent) -> Result<()> {
        let endpoint =
            crate::egress::validate_http_url_for_egress(&self.endpoint, "audit endpoint")
                .map_err(|error| anyhow!(error))?;
        let mut request = self.client.post(endpoint).json(event);
        if let Some(token) = self.bearer_token.as_deref() {
            request = request.bearer_auth(token);
        }
        request
            .send()
            .await
            .with_context(|| format!("failed to POST audit event to {}", self.endpoint))?
            .error_for_status()
            .with_context(|| format!("audit endpoint {} rejected the event", self.endpoint))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[tokio::test]
    async fn jsonl_sink_appends_events() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("audit-tests")
            .join(format!("jsonl-{unique}.jsonl"));
        let sink = JsonlAuditSink::new(&path);
        let event = AuditEvent::PolicyAccess {
            request_id: "req-1".to_owned(),
            origin_service_id: "ak:did_core:web:sync.example.com".to_owned(),
            destination_service_id: Some("ak:did_core:web:push.example.com".to_owned()),
            access_kind: "e2ee_late_recovery".to_owned(),
        };

        sink.record(&event).await.unwrap();

        let body = fs::read_to_string(&path).unwrap();
        let lines = body.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 1);
        let parsed: AuditEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed, event);
        let _ = fs::remove_file(&path);
    }
}
