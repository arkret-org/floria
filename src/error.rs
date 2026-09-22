use std::time::Duration;

use thiserror::Error;

/// Dispatch failure raised by a provider adapter.
///
/// The `message` is human-readable free text. Callers classify a failure
/// through [`DispatchError::is_remote`] / [`DispatchError::is_temporary`]
/// and read the provider-supplied backoff through
/// [`DispatchError::retry_after`]; the provider kind is already known at
/// every dispatch call site, so it is not carried on the error.
#[derive(Debug, Error)]
pub enum DispatchError {
    #[error("{message}")]
    Remote { message: String },
    #[error("{message}")]
    Temporary {
        message: String,
        retry_after: Option<Duration>,
    },
    #[error("{message}")]
    Internal { message: String },
}

impl DispatchError {
    pub fn remote(message: impl Into<String>) -> Self {
        Self::Remote {
            message: message.into(),
        }
    }

    pub fn temporary(message: impl Into<String>, retry_after: Option<Duration>) -> Self {
        Self::Temporary {
            message: message.into(),
            retry_after,
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
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

    /// Stable operator-safe classification for logs, traces, caches and
    /// durable retry/dead-letter state.
    ///
    /// Adapter messages may contain an upstream response body or URL. Some
    /// providers echo the device token in those values, so they must never
    /// cross the dispatch boundary into observability or storage.
    pub fn safe_summary(&self) -> &'static str {
        match self {
            Self::Temporary { .. } => "push provider temporary failure",
            Self::Remote { .. } => "push provider rejected request",
            Self::Internal { .. } => "push provider internal failure",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_summary_never_exposes_adapter_message() {
        let provider_token = "provider-secret-device-token";
        for error in [
            DispatchError::temporary(
                format!("upstream echoed {provider_token}"),
                Some(Duration::from_secs(1)),
            ),
            DispatchError::remote(format!("bad target {provider_token}")),
            DispatchError::internal(format!("unexpected {provider_token}")),
        ] {
            assert!(!error.safe_summary().contains(provider_token));
            assert!(!format!("{}", error.safe_summary()).contains(provider_token));
        }
    }
}
