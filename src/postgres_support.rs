use std::str::FromStr;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use postgres::config::SslMode;

const DEFAULT_POSTGRES_POOL_SIZE: u32 = 16;
const POSTGRES_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
static RUSTLS_CRYPTO_PROVIDER: OnceLock<()> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlTableName {
    sql: String,
}

impl SqlTableName {
    pub fn parse(raw: &str, field: &str) -> Result<Self> {
        let value = raw.trim();
        if value.is_empty() {
            bail!("{field} must not be empty");
        }
        let parts = value.split('.').collect::<Vec<_>>();
        if parts.is_empty() || parts.len() > 2 {
            bail!("{field} must be `table` or `schema.table`; got `{raw}`");
        }
        for part in &parts {
            validate_identifier(part, field)?;
        }
        Ok(Self {
            sql: parts
                .iter()
                .map(|part| format!("\"{part}\""))
                .collect::<Vec<_>>()
                .join("."),
        })
    }

    pub fn as_sql(&self) -> &str {
        &self.sql
    }
}

pub fn validate_identifier(raw: &str, field: &str) -> Result<()> {
    let mut chars = raw.chars();
    let Some(first) = chars.next() else {
        bail!("{field} contains an empty identifier");
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        bail!("{field} identifier `{raw}` must start with ASCII letter or `_`");
    }
    if !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
        bail!("{field} identifier `{raw}` must contain only ASCII letters, digits, or `_`");
    }
    Ok(())
}

pub fn validate_postgres_url(raw: &str, field: &str) -> Result<()> {
    let value = raw.trim();
    if value.is_empty() {
        bail!("{field} must not be empty");
    }
    postgres::Config::from_str(value)
        .map(|_| ())
        .map_err(|error| anyhow!("{field} must be a valid PostgreSQL connection URL: {error}"))
}

#[derive(Clone)]
pub struct PostgresPool {
    inner: r2d2::Pool<PostgresConnectionManager>,
    target_label: String,
}

impl std::fmt::Debug for PostgresPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresPool")
            .field("target_label", &self.target_label)
            .finish_non_exhaustive()
    }
}

impl PostgresPool {
    pub fn new(url: &str, target_label: impl Into<String>) -> Result<Self> {
        let target_label = target_label.into();
        let manager = PostgresConnectionManager::new(url, &target_label)?;
        let pool = r2d2::Pool::builder()
            .max_size(DEFAULT_POSTGRES_POOL_SIZE)
            .connection_timeout(POSTGRES_CONNECTION_TIMEOUT)
            .build_unchecked(manager);
        Ok(Self {
            inner: pool,
            target_label,
        })
    }

    pub fn with_client<T>(&self, op: impl FnOnce(&mut postgres::Client) -> Result<T>) -> Result<T> {
        let mut client = self.inner.get().with_context(|| {
            format!("failed to get PostgreSQL connection {}", self.target_label)
        })?;
        op(&mut client)
    }
}

#[derive(Clone)]
struct PostgresConnectionManager {
    config: postgres::Config,
    tls: PostgresTlsMode,
}

impl PostgresConnectionManager {
    fn new(url: &str, target_label: &str) -> Result<Self> {
        let config = postgres::Config::from_str(url)
            .with_context(|| format!("invalid PostgreSQL connection URL for {target_label}"))?;
        let tls = match config.get_ssl_mode() {
            SslMode::Disable => PostgresTlsMode::Plain,
            SslMode::Prefer | SslMode::Require => {
                PostgresTlsMode::Rustls(load_postgres_tls(target_label)?)
            }
            _ => PostgresTlsMode::Rustls(load_postgres_tls(target_label)?),
        };
        if matches!(config.get_ssl_mode(), SslMode::Prefer) {
            tracing::warn!(
                backend = target_label,
                "PostgreSQL URL uses sslmode=prefer/default; set sslmode=require for encrypted DB transport without cleartext fallback"
            );
        }
        Ok(Self { config, tls })
    }
}

fn load_postgres_tls(target_label: &str) -> Result<tokio_postgres_rustls::MakeRustlsConnect> {
    RUSTLS_CRYPTO_PROVIDER.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
    let (tls, cert_errors) = tokio_postgres_rustls::MakeRustlsConnect::with_native_certs()
        .map_err(|errors| {
            anyhow!("failed to load native root certificates for PostgreSQL TLS: {errors:?}")
        })?;
    for error in cert_errors {
        tracing::warn!(
            error = ?error,
            backend = target_label,
            "native root certificate skipped while building PostgreSQL TLS connector"
        );
    }
    Ok(tls)
}

impl r2d2::ManageConnection for PostgresConnectionManager {
    type Connection = postgres::Client;
    type Error = postgres::Error;

    fn connect(&self) -> std::result::Result<Self::Connection, Self::Error> {
        match &self.tls {
            PostgresTlsMode::Plain => self.config.connect(postgres::NoTls),
            PostgresTlsMode::Rustls(tls) => self.config.connect(tls.clone()),
        }
    }

    fn is_valid(&self, conn: &mut Self::Connection) -> std::result::Result<(), Self::Error> {
        conn.simple_query("").map(|_| ())
    }

    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        conn.is_closed()
    }
}

#[derive(Clone)]
enum PostgresTlsMode {
    Plain,
    Rustls(tokio_postgres_rustls::MakeRustlsConnect),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_name_accepts_schema_table() {
        let table = SqlTableName::parse("floria.push_contact_cache", "storage.table").unwrap();
        assert_eq!(table.as_sql(), "\"floria\".\"push_contact_cache\"");
    }

    #[test]
    fn table_name_rejects_unsafe_identifiers() {
        let error =
            SqlTableName::parse("floria.push_contact_cache;drop", "storage.table").unwrap_err();
        assert!(error.to_string().contains("must contain only ASCII"));
    }

    #[test]
    fn postgres_url_sslmode_require_uses_tls_pool_manager() {
        let manager = PostgresConnectionManager::new(
            "postgres://floria:secret@localhost/floria?sslmode=require",
            "test",
        )
        .unwrap();
        assert!(matches!(manager.tls, PostgresTlsMode::Rustls(_)));
    }

    #[test]
    fn postgres_url_sslmode_disable_uses_plain_pool_manager() {
        let manager = PostgresConnectionManager::new(
            "postgres://floria:secret@localhost/floria?sslmode=disable",
            "test",
        )
        .unwrap();
        assert!(matches!(manager.tls, PostgresTlsMode::Plain));
    }
}
