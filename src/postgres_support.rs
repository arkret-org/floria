use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use postgres::config::SslMode;

const DEFAULT_POSTGRES_POOL_SIZE: u32 = 16;
const POSTGRES_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

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
    inner: Arc<SharedPostgresPool>,
    target_label: String,
}

struct SharedPostgresPool {
    pool: Option<r2d2::Pool<PostgresConnectionManager>>,
}

impl Drop for SharedPostgresPool {
    fn drop(&mut self) {
        let Some(pool) = self.pool.take() else {
            return;
        };
        // postgres::Client closes through its own runtime, including on Drop.
        // The last application-state owner can disappear on an async worker.
        // Only the final shared owner transfers cleanup to a runtime-free thread.
        if tokio::runtime::Handle::try_current().is_ok() {
            std::thread::spawn(move || drop(pool));
        } else {
            drop(pool);
        }
    }
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
            // Each configured source owns a pool. Open connections on demand
            // instead of reserving the full capacity for every idle source.
            .min_idle(Some(0))
            .connection_timeout(POSTGRES_CONNECTION_TIMEOUT)
            .build_unchecked(manager);
        Ok(Self {
            inner: Arc::new(SharedPostgresPool { pool: Some(pool) }),
            target_label,
        })
    }

    pub fn with_client<T>(
        &self,
        op: impl AsyncFnOnce(&mut tokio_postgres::Client) -> Result<T>,
    ) -> Result<T> {
        let mut client = self
            .inner
            .pool
            .as_ref()
            .expect("pool exists until final drop")
            .get()
            .with_context(|| {
                format!("failed to get PostgreSQL connection {}", self.target_label)
            })?;
        client.run(op, Duration::from_secs(30))
    }

    /// Retry the complete Serializable transaction within the existing operation deadline.
    pub fn with_serializable_client<T>(
        &self,
        mut op: impl AsyncFnMut(&mut tokio_postgres::Client) -> Result<T>,
    ) -> Result<T> {
        self.with_client(async |client| {
            let mut retries = 0_u32;
            loop {
                let result = op(client).await;
                let retryable = result.as_ref().err().is_some_and(|error| {
                    error.chain().any(|cause| {
                        cause.downcast_ref::<tokio_postgres::Error>().is_some_and(|error| {
                            error.code().is_some_and(|code| {
                                code == &tokio_postgres::error::SqlState::T_R_SERIALIZATION_FAILURE
                                    || code == &tokio_postgres::error::SqlState::T_R_DEADLOCK_DETECTED
                            })
                        })
                    })
                });
                if !retryable || retries == 4 {
                    return result;
                }
                tokio::time::sleep(Duration::from_millis(2_u64 << retries)).await;
                retries += 1;
            }
        })
    }
}

#[derive(Clone)]
struct PostgresConnectionManager {
    config: tokio_postgres::Config,
    tls: PostgresTlsMode,
}

impl PostgresConnectionManager {
    fn new(url: &str, target_label: &str) -> Result<Self> {
        let mut config = tokio_postgres::Config::from_str(url)
            .with_context(|| format!("invalid PostgreSQL connection URL for {target_label}"))?;
        config.connect_timeout(POSTGRES_CONNECTION_TIMEOUT);
        let options = format!(
            "{} -c statement_timeout=30000 -c lock_timeout=5000 -c idle_in_transaction_session_timeout=60000",
            config.get_options().unwrap_or("")
        );
        config.options(options);
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
                "PostgreSQL URL uses sslmode=prefer/default; set sslmode=require for encrypted DB transport without plaintext fallback"
            );
        }
        Ok(Self { config, tls })
    }
}

fn load_postgres_tls(target_label: &str) -> Result<tokio_postgres_rustls::MakeRustlsConnect> {
    crate::ensure_rustls_crypto_provider();
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
    type Connection = BoundedPostgresClient;
    type Error = std::io::Error;

    fn connect(&self) -> std::result::Result<Self::Connection, Self::Error> {
        BoundedPostgresClient::connect(self)
            .map_err(|error| std::io::Error::other(error.to_string()))
    }

    fn is_valid(&self, conn: &mut Self::Connection) -> std::result::Result<(), Self::Error> {
        conn.run(
            async |client| {
                client.simple_query("").await?;
                Ok(())
            },
            POSTGRES_CONNECTION_TIMEOUT,
        )
        .map_err(|error| std::io::Error::other(error.to_string()))
    }

    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        conn.broken || conn.client.is_closed()
    }
}

#[derive(Clone)]
enum PostgresTlsMode {
    Plain,
    Rustls(tokio_postgres_rustls::MakeRustlsConnect),
}

struct BoundedPostgresClient {
    runtime: tokio::runtime::Runtime,
    client: tokio_postgres::Client,
    connection: tokio::task::JoinHandle<()>,
    tls: PostgresTlsMode,
    broken: bool,
}

impl BoundedPostgresClient {
    fn connect(manager: &PostgresConnectionManager) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (client, connection) = runtime.block_on(async {
            tokio::time::timeout(POSTGRES_CONNECTION_TIMEOUT, async {
                match &manager.tls {
                    PostgresTlsMode::Plain => {
                        let (client, connection) =
                            manager.config.connect(tokio_postgres::NoTls).await?;
                        Ok::<_, tokio_postgres::Error>((
                            client,
                            tokio::spawn(async move {
                                let _ = connection.await;
                            }),
                        ))
                    }
                    PostgresTlsMode::Rustls(tls) => {
                        let (client, connection) = manager.config.connect(tls.clone()).await?;
                        Ok((
                            client,
                            tokio::spawn(async move {
                                let _ = connection.await;
                            }),
                        ))
                    }
                }
            })
            .await
            .context("PostgreSQL connection timed out")?
            .map_err(anyhow::Error::from)
        })?;
        Ok(Self {
            runtime,
            client,
            connection,
            tls: manager.tls.clone(),
            broken: false,
        })
    }

    fn run<T>(
        &mut self,
        operation: impl AsyncFnOnce(&mut tokio_postgres::Client) -> Result<T>,
        budget: Duration,
    ) -> Result<T> {
        let result = self
            .runtime
            .block_on(async { tokio::time::timeout(budget, operation(&mut self.client)).await });
        match result {
            Ok(result) => result,
            Err(_) => {
                self.broken = true;
                let cancel = self.client.cancel_token();
                self.connection.abort();
                // Drive the abort to close the socket, and cancel a backend that
                // is waiting for a lock and may not observe TCP EOF promptly.
                self.runtime.block_on(async {
                    tokio::task::yield_now().await;
                    let _ = tokio::time::timeout(Duration::from_secs(1), async {
                        match &self.tls {
                            PostgresTlsMode::Plain => {
                                cancel.cancel_query(tokio_postgres::NoTls).await
                            }
                            PostgresTlsMode::Rustls(tls) => cancel.cancel_query(tls.clone()).await,
                        }
                    })
                    .await;
                });
                bail!("PostgreSQL operation timed out; connection discarded")
            }
        }
    }
}

impl Drop for BoundedPostgresClient {
    fn drop(&mut self) {
        self.connection.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_retry_replays_only_retryable_failures() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let url = std::env::var("FLORIA_HANDOFF_TEST_DATABASE_URL")
            .expect("isolated test database required");
        let pool = PostgresPool::new(&url, "transaction retry regression").unwrap();
        let attempts = AtomicUsize::new(0);
        let value: i32 = pool
            .with_serializable_client(async |client| {
                let transaction = client.transaction().await?;
                if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    transaction
                        .batch_execute("DO $$ BEGIN RAISE EXCEPTION 'retry fixture' USING ERRCODE='40001'; END $$")
                        .await?;
                }
                let row = transaction.query_one("SELECT 42::int", &[]).await?;
                transaction.commit().await?;
                Ok(row.get(0))
            })
            .unwrap();
        assert_eq!(value, 42);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        for (code, expected_attempts) in [("23505", 1), ("40P01", 5)] {
            let attempts = AtomicUsize::new(0);
            let result: Result<()> = pool.with_serializable_client(async |client| {
                attempts.fetch_add(1, Ordering::SeqCst);
                let transaction = client.transaction().await?;
                transaction
                    .batch_execute(&format!(
                        "DO $$ BEGIN RAISE EXCEPTION 'retry fixture' USING ERRCODE='{code}'; END $$"
                    ))
                    .await?;
                transaction.commit().await?;
                Ok(())
            });
            assert!(result.is_err());
            assert_eq!(attempts.load(Ordering::SeqCst), expected_attempts);
        }
    }

    #[test]
    fn query_deadline_discards_the_session_and_cancels_the_backend() {
        let url = std::env::var("FLORIA_HANDOFF_TEST_DATABASE_URL")
            .expect("isolated test database required");
        let manager = PostgresConnectionManager::new(&url, "deadline regression").unwrap();
        let mut client = BoundedPostgresClient::connect(&manager).unwrap();
        let pid: i32 = client
            .run(
                async |client| {
                    Ok(client
                        .query_one("SELECT pg_backend_pid()", &[])
                        .await?
                        .get(0))
                },
                POSTGRES_CONNECTION_TIMEOUT,
            )
            .unwrap();
        let started = std::time::Instant::now();
        assert!(
            client
                .run(
                    async |client| {
                        client.query("SELECT pg_sleep(10)", &[]).await?;
                        Ok(())
                    },
                    Duration::from_millis(100)
                )
                .is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(client.broken);
        let mut observer = BoundedPostgresClient::connect(&manager).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let exists: bool = observer
                .run(
                    async |client| {
                        Ok(client
                            .query_one(
                                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)",
                                &[&pid],
                            )
                            .await?
                            .get(0))
                    },
                    POSTGRES_CONNECTION_TIMEOUT,
                )
                .unwrap();
            if !exists {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed-out session remained on the server"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn unanswered_postgres_handshake_has_a_deadline() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            use std::io::Read;
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(7)))
                .unwrap();
            let mut data = [0; 4096];
            while matches!(socket.read(&mut data), Ok(n) if n > 0) {}
        });
        let manager = PostgresConnectionManager::new(
            &format!("postgres://postgres@{address}/test?sslmode=disable"),
            "blackhole",
        )
        .unwrap();
        let started = std::time::Instant::now();
        assert!(BoundedPostgresClient::connect(&manager).is_err());
        assert!(started.elapsed() < Duration::from_secs(7));
        server.join().unwrap();
    }

    #[test]
    fn table_name_accepts_schema_table() {
        let table = SqlTableName::parse("floria.cache_entries", "storage.table").unwrap();
        assert_eq!(table.as_sql(), "\"floria\".\"cache_entries\"");
    }

    #[test]
    fn table_name_rejects_unsafe_identifiers() {
        let error = SqlTableName::parse("floria.cache_entries;drop", "storage.table").unwrap_err();
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
