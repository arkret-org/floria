use std::collections::HashMap;
use std::fmt;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Map, Value};

use super::{string_or_vec, validate_bearer_token_hashes, warn_unknown_fields};

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct NotifyAuthConfig {
    #[serde(default, deserialize_with = "string_or_vec")]
    pub bearer_tokens: Vec<String>,
    #[serde(default, deserialize_with = "string_or_vec")]
    pub bearer_token_hashes: Vec<String>,
    #[serde(default, deserialize_with = "string_or_vec")]
    pub trusted_service_ids: Vec<String>,
    #[serde(default, deserialize_with = "string_or_vec")]
    pub plaintext_metadata_service_ids: Vec<String>,
    /// Resolvable DID for this gateway. Transport headers continue to
    /// carry the derived service core id.
    pub gateway_service_did: Option<String>,
    /// Exact method-history head verified when the gateway DID was
    /// registered. Required together with `gateway_service_version_id` in
    /// production mode so Describe never invents resolution state.
    pub gateway_service_method_history_head: Option<String>,
    pub gateway_service_version_id: Option<String>,
    /// Complete method-native evidence published by the open service-resolution
    /// endpoint.  The commitment fields above are retained for compatibility,
    /// but when this value is present they must name its exact terminal state.
    pub gateway_service_resolution: Option<arkret_models_identity::AuthenticatedServiceResolution>,
    pub require_message_signatures: bool,
    pub signature_max_skew_seconds: u64,
    pub mtls_verified_header: String,
    pub mtls_fingerprint_header: String,
    pub mtls_subject_dn_header: String,
    pub mtls_subject_alt_names_header: String,
    /// When true, refuse to accept bearer-only or anonymous notify
    /// requests; every authenticated caller must satisfy HTTP Message
    /// Signature or mTLS, and the gateway DID must be configured.
    /// Also forbids dev-only conveniences (anonymous bypass, bearer
    /// fallback when no signature is present on a known principal).
    pub production_mode: bool,
    /// When true, a bearer-only request MUST present a recognised
    /// origin_id and the gateway will only accept the request
    /// if that service core id has a configured `service_principal` entry whose
    /// `bearer_tokens` / `bearer_token_hashes` match. This blocks a
    /// stolen gateway-wide bearer token from being used to impersonate
    /// an arbitrary tenant via the X-Arkret-Origin-Service-ID header.
    /// Has no effect in `production_mode` (which already disables the
    /// gateway-wide bearer fallback).
    pub bind_bearer_to_origin_id: bool,
    #[serde(default)]
    pub service_principals: HashMap<String, NotifyServicePrincipalConfig>,
    pub nonce_store: NotifyNonceStoreConfig,
    pub replay_window_seconds: u64,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl fmt::Debug for NotifyAuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bearer_tokens = format!("<redacted:{}>", self.bearer_tokens.len());
        let service_principals = self
            .service_principals
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        f.debug_struct("NotifyAuthConfig")
            .field("bearer_tokens", &bearer_tokens)
            .field("bearer_token_hashes", &self.bearer_token_hashes.len())
            .field("trusted_service_ids", &self.trusted_service_ids)
            .field(
                "plaintext_metadata_service_ids",
                &self.plaintext_metadata_service_ids,
            )
            .field("gateway_service_did", &self.gateway_service_did)
            .field(
                "gateway_service_method_history_head",
                &self.gateway_service_method_history_head,
            )
            .field(
                "gateway_service_version_id",
                &self.gateway_service_version_id,
            )
            .field(
                "gateway_service_resolution",
                &self
                    .gateway_service_resolution
                    .as_ref()
                    .map(|resolution| (&resolution.service_id, &resolution.service_kind)),
            )
            .field(
                "require_message_signatures",
                &self.require_message_signatures,
            )
            .field(
                "signature_max_skew_seconds",
                &self.signature_max_skew_seconds,
            )
            .field("mtls_verified_header", &self.mtls_verified_header)
            .field("mtls_fingerprint_header", &self.mtls_fingerprint_header)
            .field("mtls_subject_dn_header", &self.mtls_subject_dn_header)
            .field(
                "mtls_subject_alt_names_header",
                &self.mtls_subject_alt_names_header,
            )
            .field("production_mode", &self.production_mode)
            .field("bind_bearer_to_origin_id", &self.bind_bearer_to_origin_id)
            .field("service_principals", &service_principals)
            .field("nonce_store", &self.nonce_store)
            .field("replay_window_seconds", &self.replay_window_seconds)
            .field("extra_keys", &self.extra.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl NotifyAuthConfig {
    /// Project the gateway's registered DID to the stable service id
    /// carried by service-to-service transport headers.
    pub fn gateway_service_core_id(&self) -> Result<Option<arkret_wire::DidCoreId>> {
        self.gateway_service_did
            .as_ref()
            .map(|raw| {
                let did = arkret_wire::Did::new(raw.clone()).with_context(
                    || "http.notify_auth.gateway_service_did must be a resolvable DID",
                )?;
                arkret_wire::project_did_to_core_id(&did).with_context(
                    || "http.notify_auth.gateway_service_did uses an unsupported DID method",
                )
            })
            .transpose()
    }

    pub fn enabled(&self) -> bool {
        !self.bearer_tokens.is_empty()
            || !self.bearer_token_hashes.is_empty()
            || !self.trusted_service_ids.is_empty()
            || !self.service_principals.is_empty()
            || self.gateway_service_did.is_some()
            || self.require_message_signatures
    }

    pub(super) fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "http.notify_auth",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
        for (did, principal) in &self.service_principals {
            principal.emit_startup_warnings(did);
        }
        self.nonce_store.emit_startup_warnings();
    }

    pub fn signature_max_skew_seconds(&self) -> u64 {
        self.signature_max_skew_seconds.max(1)
    }

    pub fn mtls_verified_header(&self) -> &str {
        let value = self.mtls_verified_header.trim();
        if value.is_empty() {
            "x-client-certificate-verified"
        } else {
            value
        }
    }

    pub fn mtls_fingerprint_header(&self) -> &str {
        let value = self.mtls_fingerprint_header.trim();
        if value.is_empty() {
            "x-client-certificate-sha256"
        } else {
            value
        }
    }

    pub fn mtls_subject_dn_header(&self) -> &str {
        let value = self.mtls_subject_dn_header.trim();
        if value.is_empty() {
            "x-client-certificate-subject"
        } else {
            value
        }
    }

    pub fn mtls_subject_alt_names_header(&self) -> &str {
        let value = self.mtls_subject_alt_names_header.trim();
        if value.is_empty() {
            "x-client-certificate-san"
        } else {
            value
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.gateway_service_core_id()?;
        for (field, ids) in [
            ("trusted_service_ids", &self.trusted_service_ids),
            (
                "plaintext_metadata_service_ids",
                &self.plaintext_metadata_service_ids,
            ),
        ] {
            for service_id in ids {
                arkret_wire::DidCoreId::new(service_id.clone()).with_context(|| {
                    format!("http.notify_auth.{field} entries must be service core ids")
                })?;
            }
        }
        let history_head = self
            .gateway_service_method_history_head
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let version_id = self
            .gateway_service_version_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if history_head.is_some() != version_id.is_some() {
            bail!(
                "http.notify_auth.gateway_service_method_history_head and gateway_service_version_id must be configured together"
            );
        }
        if let Some(resolution) = &self.gateway_service_resolution {
            let gateway_service_id = self.gateway_service_core_id()?.ok_or_else(|| {
                anyhow::anyhow!(
                    "http.notify_auth.gateway_service_resolution requires gateway_service_did"
                )
            })?;
            resolution
                .validate_shape(&gateway_service_id, chrono::Utc::now())
                .context("http.notify_auth.gateway_service_resolution is invalid")?;
            if resolution.service_kind != arkret_wire::ServiceKind::PushGateway.as_str() {
                bail!(
                    "http.notify_auth.gateway_service_resolution must bind service_kind push_gateway"
                );
            }
            if resolution.normalized_did_document.id.as_str()
                != self.gateway_service_did.as_deref().unwrap_or_default()
            {
                bail!(
                    "http.notify_auth.gateway_service_resolution DID must equal gateway_service_did"
                );
            }
            let boundary = resolution.method_history_evidence.boundary();
            if history_head != Some(boundary.to_method_history_head.as_str())
                || version_id != Some(boundary.to_version_id.as_str())
            {
                bail!(
                    "gateway service commitment must equal gateway_service_resolution terminal coordinates"
                );
            }
        }
        if self.require_message_signatures && self.service_principals.is_empty() {
            bail!(
                "http.notify_auth.require_message_signatures requires at least one service_principal"
            );
        }
        validate_bearer_token_hashes(
            "http.notify_auth.bearer_token_hashes",
            &self.bearer_token_hashes,
        )?;
        for (did, principal) in &self.service_principals {
            arkret_wire::DidCoreId::new(did.clone()).with_context(
                || "http.notify_auth.service_principals keys must be service core ids",
            )?;
            principal.validate(did)?;
        }
        if self.require_message_signatures && self.replay_window_seconds == 0 {
            bail!(
                "http.notify_auth.require_message_signatures requires http.notify_auth.replay_window_seconds > 0"
            );
        }
        self.nonce_store.validate(self.replay_window_seconds)?;
        if self.production_mode {
            self.validate_production_mode()?;
        }
        Ok(())
    }

    pub fn replay_window_seconds(&self) -> u64 {
        self.replay_window_seconds
    }

    fn validate_production_mode(&self) -> Result<()> {
        if !self.enabled() {
            bail!(
                "http.notify_auth.production_mode requires authentication; configure service_principals or signed access"
            );
        }
        if self.gateway_service_did.is_none() {
            bail!("http.notify_auth.production_mode requires http.notify_auth.gateway_service_did");
        }
        if self.gateway_service_method_history_head.is_none()
            || self.gateway_service_version_id.is_none()
        {
            bail!(
                "http.notify_auth.production_mode requires gateway_service_method_history_head and gateway_service_version_id"
            );
        }
        if self.service_principals.is_empty() {
            bail!(
                "http.notify_auth.production_mode requires at least one configured service_principal"
            );
        }
        for (did, principal) in &self.service_principals {
            let has_signature = principal.signature_verification_method.is_some()
                && principal.signature_public_key_hex.is_some();
            if !has_signature && !principal.require_mtls {
                bail!(
                    "http.notify_auth.production_mode requires service_principals.{did} to set HTTP Message Signature or require_mtls"
                );
            }
            if !principal.bearer_tokens.is_empty() {
                bail!(
                    "http.notify_auth.production_mode rejects plaintext bearer_tokens on service_principals.{did}; production callers must use HTTP Message Signature or mTLS"
                );
            }
            if principal.allow_plaintext_metadata {
                let kind = principal
                    .service_kind
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty());
                let Some(kind) = kind else {
                    bail!(
                        "http.notify_auth.production_mode requires service_principals.{did}.service_kind when allow_plaintext_metadata is true"
                    );
                };
                if !is_plaintext_eligible_service_kind(kind) {
                    bail!(
                        "http.notify_auth.production_mode rejects allow_plaintext_metadata for service_kind `{kind}` on service_principals.{did}"
                    );
                }
            }
        }
        if !self.bearer_tokens.is_empty() || !self.bearer_token_hashes.is_empty() {
            bail!(
                "http.notify_auth.production_mode rejects gateway-wide bearer_tokens; configure per-principal credentials instead"
            );
        }
        Ok(())
    }
}

/// Caller `service_kind` values that are allowed to send plaintext
/// metadata (sender/realm/strand names, DID literals, etc.).
///
/// Active service kinds — kept in sync with `ak.profile.*` artifacts in
/// the principal services. New kinds must be reviewed for whether they
/// can legitimately read/forward plaintext bound to a user identity.
pub fn is_plaintext_eligible_service_kind(kind: &str) -> bool {
    matches!(
        kind.trim().to_ascii_lowercase().as_str(),
        "sync" | "sync_service" | "principal" | "principal_service"
    )
}

impl Default for NotifyAuthConfig {
    fn default() -> Self {
        Self {
            bearer_tokens: Vec::new(),
            bearer_token_hashes: Vec::new(),
            trusted_service_ids: Vec::new(),
            plaintext_metadata_service_ids: Vec::new(),
            gateway_service_did: None,
            gateway_service_method_history_head: None,
            gateway_service_version_id: None,
            gateway_service_resolution: None,
            require_message_signatures: false,
            signature_max_skew_seconds: 300,
            mtls_verified_header: "x-client-certificate-verified".to_owned(),
            mtls_fingerprint_header: "x-client-certificate-sha256".to_owned(),
            mtls_subject_dn_header: "x-client-certificate-subject".to_owned(),
            mtls_subject_alt_names_header: "x-client-certificate-san".to_owned(),
            production_mode: false,
            bind_bearer_to_origin_id: false,
            service_principals: HashMap::new(),
            nonce_store: NotifyNonceStoreConfig::default(),
            replay_window_seconds: 0,
            extra: Map::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NotifyNonceStoreConfig {
    pub backend: String,
    pub redis_url: Option<String>,
    pub key_prefix: String,
    /// Behaviour when the Redis backend is unreachable. `strict` (the
    /// default) is fail-closed: the gateway answers 503 on the calling
    /// site so the caller backs off instead of bypassing replay
    /// protection. `permissive` opts back into fail-open and MUST only be
    /// used in deployments that accept silent replay-protection bypass
    /// during Redis outages.
    pub redis_failure_policy: String,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl Default for NotifyNonceStoreConfig {
    fn default() -> Self {
        Self {
            backend: "memory".to_owned(),
            redis_url: None,
            key_prefix: "floria".to_owned(),
            redis_failure_policy: "strict".to_owned(),
            extra: Map::new(),
        }
    }
}

impl NotifyNonceStoreConfig {
    pub fn backend_kind(&self) -> &str {
        super::trimmed_or(&self.backend, "memory")
    }

    pub fn key_prefix(&self) -> &str {
        super::trimmed_or(&self.key_prefix, "floria")
    }

    pub fn failure_policy(&self) -> &str {
        super::trimmed_or(&self.redis_failure_policy, "strict")
    }

    pub(super) fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "http.notify_auth.nonce_store",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
    }

    pub fn validate(&self, replay_window_seconds: u64) -> Result<()> {
        match self.backend_kind() {
            "memory" => {}
            "redis" => {
                if replay_window_seconds == 0 {
                    bail!(
                        "http.notify_auth.nonce_store.backend=redis requires http.notify_auth.replay_window_seconds > 0"
                    );
                }
                if self
                    .redis_url
                    .as_deref()
                    .map(str::trim)
                    .is_none_or(|value| value.is_empty())
                {
                    bail!("http.notify_auth.nonce_store.redis_url is required when backend=redis");
                }
            }
            backend => {
                bail!(
                    "http.notify_auth.nonce_store.backend must be one of: memory, redis; got `{backend}`"
                );
            }
        }
        match self.failure_policy() {
            "permissive" | "strict" => {}
            other => {
                bail!(
                    "http.notify_auth.nonce_store.redis_failure_policy must be one of: permissive, strict; got `{other}`"
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct NotifyServicePrincipalConfig {
    pub service_kind: Option<String>,
    pub allow_plaintext_metadata: bool,
    #[serde(default, deserialize_with = "string_or_vec")]
    pub bearer_tokens: Vec<String>,
    #[serde(default, deserialize_with = "string_or_vec")]
    pub bearer_token_hashes: Vec<String>,
    pub signature_verification_method: Option<String>,
    pub signature_public_key_hex: Option<String>,
    pub require_mtls: bool,
    #[serde(default, deserialize_with = "string_or_vec")]
    pub mtls_cert_fingerprints: Vec<String>,
    /// Expected client-certificate Subject DN (exact, case-insensitive
    /// after whitespace normalisation). Set this when the reverse
    /// proxy can pass through the verified subject DN — it binds the
    /// cert to a specific issuer/subject so a fingerprint reuse on a
    /// different cert under the same trust root is still rejected.
    pub mtls_subject_dn: Option<String>,
    /// Subject Alternative Names that the verified client certificate
    /// is required to advertise. Each entry must appear in the SAN
    /// list passed by the reverse proxy. This is the typical hook
    /// for binding a service DID (`uri:did:web:sync.example.com`) to
    /// a particular cert.
    #[serde(default, deserialize_with = "string_or_vec")]
    pub mtls_subject_alt_names: Vec<String>,
    pub service_endpoint: Option<String>,
    #[serde(flatten)]
    pub(super) extra: Map<String, Value>,
}

impl fmt::Debug for NotifyServicePrincipalConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bearer_tokens = format!("<redacted:{}>", self.bearer_tokens.len());
        f.debug_struct("NotifyServicePrincipalConfig")
            .field("service_kind", &self.service_kind)
            .field("allow_plaintext_metadata", &self.allow_plaintext_metadata)
            .field("bearer_tokens", &bearer_tokens)
            .field("bearer_token_hashes", &self.bearer_token_hashes.len())
            .field(
                "signature_verification_method",
                &self.signature_verification_method,
            )
            .field("signature_public_key_hex", &self.signature_public_key_hex)
            .field("require_mtls", &self.require_mtls)
            .field("mtls_cert_fingerprints", &self.mtls_cert_fingerprints)
            .field("mtls_subject_dn", &self.mtls_subject_dn)
            .field("mtls_subject_alt_names", &self.mtls_subject_alt_names)
            .field("service_endpoint", &self.service_endpoint)
            .field("extra_keys", &self.extra.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Default for NotifyServicePrincipalConfig {
    fn default() -> Self {
        Self {
            service_kind: None,
            allow_plaintext_metadata: false,
            bearer_tokens: Vec::new(),
            bearer_token_hashes: Vec::new(),
            signature_verification_method: None,
            signature_public_key_hex: None,
            require_mtls: false,
            mtls_cert_fingerprints: Vec::new(),
            mtls_subject_dn: None,
            mtls_subject_alt_names: Vec::new(),
            service_endpoint: None,
            extra: Map::new(),
        }
    }
}

impl NotifyServicePrincipalConfig {
    fn emit_startup_warnings(&self, did: &str) {
        warn_unknown_fields(
            &format!("http.notify_auth.service_principals.{did}"),
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
    }

    fn validate(&self, did: &str) -> Result<()> {
        match (
            self.signature_verification_method.as_deref(),
            self.signature_public_key_hex.as_deref(),
        ) {
            (Some(_), Some(public_key_hex)) => {
                let bytes = hex::decode(public_key_hex).with_context(|| {
                    format!(
                        "http.notify_auth.service_principals.{did}.signature_public_key_hex must be hex"
                    )
                })?;
                if bytes.len() != 32 {
                    bail!(
                        "http.notify_auth.service_principals.{did}.signature_public_key_hex must encode 32 bytes"
                    );
                }
            }
            (None, None) => {}
            _ => {
                bail!(
                    "http.notify_auth.service_principals.{did} must set both signature_verification_method and signature_public_key_hex or neither"
                );
            }
        }
        if self.require_mtls
            && self
                .mtls_cert_fingerprints
                .iter()
                .any(|value| value.trim().is_empty())
        {
            bail!(
                "http.notify_auth.service_principals.{did}.mtls_cert_fingerprints must not contain empty values"
            );
        }
        validate_bearer_token_hashes(
            &format!("http.notify_auth.service_principals.{did}.bearer_token_hashes"),
            &self.bearer_token_hashes,
        )?;
        Ok(())
    }
}
