use std::time::Duration;

use thiserror::Error;

/// Dispatch failure raised by a provider adapter.
///
/// The `message` is human-readable free text. The optional structured
/// fields let callers classify the failure without string-matching:
/// `reason_code` aligns with the spec error-code-registry, `provider`
/// names the adapter kind (`apns` / `fcm` / …), and `upstream_status`
/// carries the provider HTTP status. They default to `None` so existing
/// construction sites keep working; adapters enrich them via the
/// `with_*` builders where the information is available, which lets the
/// retry queue / dead-letter ring and metrics key off a stable
/// (provider, reason_code) tuple instead of fragile free-text matches.
#[derive(Debug, Error)]
pub enum DispatchError {
    #[error("{message}")]
    Remote {
        message: String,
        reason_code: Option<&'static str>,
        provider: Option<&'static str>,
        upstream_status: Option<u16>,
    },
    #[error("{message}")]
    Temporary {
        message: String,
        retry_after: Option<Duration>,
        reason_code: Option<&'static str>,
        provider: Option<&'static str>,
        upstream_status: Option<u16>,
    },
    #[error("{message}")]
    Internal {
        message: String,
        reason_code: Option<&'static str>,
    },
}

impl DispatchError {
    pub fn remote(message: impl Into<String>) -> Self {
        Self::Remote {
            message: message.into(),
            reason_code: None,
            provider: None,
            upstream_status: None,
        }
    }

    pub fn temporary(message: impl Into<String>, retry_after: Option<Duration>) -> Self {
        Self::Temporary {
            message: message.into(),
            retry_after,
            reason_code: None,
            provider: None,
            upstream_status: None,
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
            reason_code: None,
        }
    }

    /// Attach a spec error-code-registry aligned reason code.
    pub fn with_reason_code(mut self, code: &'static str) -> Self {
        match &mut self {
            Self::Remote { reason_code, .. }
            | Self::Temporary { reason_code, .. }
            | Self::Internal { reason_code, .. } => *reason_code = Some(code),
        }
        self
    }

    /// Attach the provider kind that produced the failure.
    pub fn with_provider(mut self, value: &'static str) -> Self {
        match &mut self {
            Self::Remote { provider, .. } | Self::Temporary { provider, .. } => {
                *provider = Some(value)
            }
            Self::Internal { .. } => {}
        }
        self
    }

    /// Attach the upstream provider HTTP status.
    pub fn with_upstream_status(mut self, status: u16) -> Self {
        match &mut self {
            Self::Remote {
                upstream_status, ..
            }
            | Self::Temporary {
                upstream_status, ..
            } => *upstream_status = Some(status),
            Self::Internal { .. } => {}
        }
        self
    }

    pub fn is_remote(&self) -> bool {
        matches!(self, Self::Remote { .. } | Self::Temporary { .. })
    }

    pub fn is_temporary(&self) -> bool {
        matches!(self, Self::Temporary { .. })
    }

    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Temporary { retry_after, .. } => *retry_after,
            _ => None,
        }
    }

    pub fn reason_code(&self) -> Option<&'static str> {
        match self {
            Self::Remote { reason_code, .. }
            | Self::Temporary { reason_code, .. }
            | Self::Internal { reason_code, .. } => *reason_code,
        }
    }

    pub fn provider(&self) -> Option<&'static str> {
        match self {
            Self::Remote { provider, .. } | Self::Temporary { provider, .. } => *provider,
            Self::Internal { .. } => None,
        }
    }

    pub fn upstream_status(&self) -> Option<u16> {
        match self {
            Self::Remote {
                upstream_status, ..
            }
            | Self::Temporary {
                upstream_status, ..
            } => *upstream_status,
            Self::Internal { .. } => None,
        }
    }
}
