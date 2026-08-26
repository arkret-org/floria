use std::time::Duration;

use anyhow::{Context, Result};

const DEFAULT_REDIS_POOL_SIZE: u32 = 32;
const REDIS_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) type RedisConnection = r2d2::PooledConnection<RedisConnectionManager>;

#[derive(Clone)]
pub(crate) struct RedisPool {
    inner: r2d2::Pool<RedisConnectionManager>,
    target_label: String,
}

impl std::fmt::Debug for RedisPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisPool")
            .field("target_label", &self.target_label)
            .finish_non_exhaustive()
    }
}

impl RedisPool {
    pub(crate) fn from_client(
        client: redis::Client,
        target_label: impl Into<String>,
    ) -> Result<Self> {
        let target_label = target_label.into();
        let manager = RedisConnectionManager { client };
        let pool = r2d2::Pool::builder()
            .max_size(DEFAULT_REDIS_POOL_SIZE)
            .connection_timeout(REDIS_CONNECTION_TIMEOUT)
            .build_unchecked(manager);
        Ok(Self {
            inner: pool,
            target_label,
        })
    }

    pub(crate) fn connection(&self) -> Result<RedisConnection> {
        self.inner
            .get()
            .with_context(|| format!("failed to get Redis connection {}", self.target_label))
    }

    /// One readiness probe shared by every Redis-backed store so a backend
    /// that answers `PING` with anything else fails the same way everywhere.
    pub(crate) fn ready(&self) -> Result<()> {
        let mut connection = self.connection()?;
        let pong: String = redis::cmd("PING")
            .query(&mut connection)
            .with_context(|| format!("failed to ping Redis backend {}", self.target_label))?;
        if pong == "PONG" {
            Ok(())
        } else {
            anyhow::bail!(
                "Redis backend {} returned unexpected PING response `{pong}`",
                self.target_label
            );
        }
    }
}

#[derive(Clone)]
pub(crate) struct RedisConnectionManager {
    client: redis::Client,
}

impl r2d2::ManageConnection for RedisConnectionManager {
    type Connection = redis::Connection;
    type Error = redis::RedisError;

    fn connect(&self) -> std::result::Result<Self::Connection, Self::Error> {
        self.client.get_connection()
    }

    fn is_valid(&self, conn: &mut Self::Connection) -> std::result::Result<(), Self::Error> {
        redis::cmd("PING").query::<String>(conn).map(|_| ())
    }

    fn has_broken(&self, _conn: &mut Self::Connection) -> bool {
        false
    }
}
