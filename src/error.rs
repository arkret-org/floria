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
}
