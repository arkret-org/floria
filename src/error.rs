use std::time::Duration;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DispatchError {
    #[error("{0}")]
    Remote(String),
    #[error("{message}")]
    Temporary {
        message: String,
        retry_after: Option<Duration>,
    },
    #[error("{0}")]
    Internal(String),
}

impl DispatchError {
    pub fn remote(message: impl Into<String>) -> Self {
        Self::Remote(message.into())
    }

    pub fn temporary(message: impl Into<String>, retry_after: Option<Duration>) -> Self {
        Self::Temporary {
            message: message.into(),
            retry_after,
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }

    pub fn is_remote(&self) -> bool {
        matches!(self, Self::Remote(_) | Self::Temporary { .. })
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
