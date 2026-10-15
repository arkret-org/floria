use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use redis::ConnectionLike as _;

const DEFAULT_REDIS_POOL_SIZE: u32 = 32;
const REDIS_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) type RedisConnection = r2d2::PooledConnection<RedisConnectionManager>;

#[derive(Clone)]
pub(crate) struct RedisPool {
    inner: Arc<SharedRedisPool>,
    target_label: String,
}

struct SharedRedisPool {
    pool: Option<r2d2::Pool<RedisConnectionManager>>,
}

impl Drop for SharedRedisPool {
    fn drop(&mut self) {
        let Some(pool) = self.pool.take() else {
            return;
        };
        if tokio::runtime::Handle::try_current().is_ok() {
            std::thread::spawn(move || drop(pool));
        } else {
            drop(pool);
        }
    }
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
            inner: Arc::new(SharedRedisPool { pool: Some(pool) }),
            target_label,
        })
    }

    pub(crate) fn connection(&self) -> Result<RedisConnection> {
        self.inner
            .pool
            .as_ref()
            .expect("pool exists until final drop")
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
    type Connection = BoundedRedisConnection;
    type Error = redis::RedisError;

    fn connect(&self) -> std::result::Result<Self::Connection, Self::Error> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let config = redis::AsyncConnectionConfig::new()
            .set_connection_timeout(Some(REDIS_CONNECTION_TIMEOUT))
            .set_response_timeout(Some(REDIS_CONNECTION_TIMEOUT));
        let connection = runtime.block_on(async {
            tokio::time::timeout(
                REDIS_CONNECTION_TIMEOUT,
                self.client
                    .get_multiplexed_async_connection_with_config(&config),
            )
            .await
            .map_err(|_| redis_timeout())?
        })?;
        let db = redis::aio::ConnectionLike::get_db(&connection);
        Ok(BoundedRedisConnection {
            runtime,
            connection: Some(connection),
            db,
        })
    }

    fn is_valid(&self, conn: &mut Self::Connection) -> std::result::Result<(), Self::Error> {
        redis::cmd("PING").query::<String>(conn).map(|_| ())
    }

    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        !conn.is_open()
    }
}

fn redis_timeout() -> redis::RedisError {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "Redis operation timed out; connection discarded",
    )
    .into()
}

pub(crate) struct BoundedRedisConnection {
    runtime: tokio::runtime::Runtime,
    connection: Option<redis::aio::MultiplexedConnection>,
    db: i64,
}

impl BoundedRedisConnection {
    fn run<T>(
        &mut self,
        operation: impl AsyncFnOnce(&mut redis::aio::MultiplexedConnection) -> redis::RedisResult<T>,
    ) -> redis::RedisResult<T> {
        let Some(connection) = self.connection.as_mut() else {
            return Err(redis_timeout());
        };
        let result = self.runtime.block_on(async {
            tokio::time::timeout(REDIS_CONNECTION_TIMEOUT, operation(connection)).await
        });
        match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => {
                self.connection.take();
                Err(error)
            }
            Err(_) => {
                self.connection.take();
                Err(redis_timeout())
            }
        }
    }
}

fn decoded_command(value: redis::Value) -> redis::RedisResult<redis::Cmd> {
    let redis::Value::Array(args) = value else {
        return Err((redis::ErrorKind::Client, "Invalid packed Redis command").into());
    };
    let mut command = redis::Cmd::new();
    for arg in args {
        let redis::Value::BulkString(bytes) = arg else {
            return Err((redis::ErrorKind::Client, "Invalid packed Redis argument").into());
        };
        command.arg(bytes);
    }
    Ok(command)
}

impl redis::ConnectionLike for BoundedRedisConnection {
    fn req_command(&mut self, cmd: &redis::Cmd) -> redis::RedisResult<redis::Value> {
        self.run(async |connection| connection.send_packed_command(cmd).await)
    }
    fn req_packed_command(&mut self, cmd: &[u8]) -> redis::RedisResult<redis::Value> {
        self.req_command(&decoded_command(redis::parse_redis_value(cmd)?)?)
    }
    fn req_packed_commands(
        &mut self,
        cmd: &[u8],
        offset: usize,
        count: usize,
    ) -> redis::RedisResult<Vec<redis::Value>> {
        let mut parser = redis::Parser::new();
        let mut reader = std::io::Cursor::new(cmd);
        let mut pipeline = redis::pipe();
        for _ in 0..offset.saturating_add(count) {
            pipeline.add_command(decoded_command(parser.parse_value(&mut reader)?)?);
        }
        self.run(async |connection| {
            connection
                .send_packed_commands(&pipeline, offset, count)
                .await
        })
    }
    fn get_db(&self) -> i64 {
        self.db
    }
    fn check_connection(&mut self) -> bool {
        redis::cmd("PING").query::<String>(self).is_ok()
    }
    fn is_open(&self) -> bool {
        self.connection.is_some()
    }
}

#[cfg(test)]
mod wait_tests {
    use super::*;

    #[test]
    fn unanswered_command_discards_connection() {
        let url = std::env::var("FLORIA_REDIS_TEST_URL").expect("isolated Redis required");
        let manager = RedisConnectionManager {
            client: redis::Client::open(url).unwrap(),
        };
        let mut connection = r2d2::ManageConnection::connect(&manager).unwrap();
        let key = format!("deadline-empty-{}", uuid::Uuid::new_v4());
        let started = std::time::Instant::now();
        assert!(
            redis::cmd("BLPOP")
                .arg(&key)
                .arg(0)
                .query::<redis::Value>(&mut connection)
                .is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(7));
        assert!(!connection.is_open());
        drop(connection);
        let mut replacement = r2d2::ManageConnection::connect(&manager).unwrap();
        assert_eq!(
            redis::cmd("PING")
                .query::<String>(&mut replacement)
                .unwrap(),
            "PONG"
        );
    }

    #[tokio::test]
    async fn final_pool_owner_can_drop_on_async_worker() {
        let url = std::env::var("FLORIA_REDIS_TEST_URL").expect("isolated Redis required");
        let pool = tokio::task::spawn_blocking(move || {
            let pool = RedisPool::from_client(redis::Client::open(url).unwrap(), "test").unwrap();
            pool.ready().unwrap();
            pool
        })
        .await
        .unwrap();
        drop(pool);
    }

    #[test]
    fn unanswered_redis_setup_finishes() {
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
        let manager = RedisConnectionManager {
            client: redis::Client::open(format!("redis://{address}/")).unwrap(),
        };
        let started = std::time::Instant::now();
        assert!(r2d2::ManageConnection::connect(&manager).is_err());
        assert!(started.elapsed() < Duration::from_secs(7));
        server.join().unwrap();
    }

    #[test]
    fn bounded_connection_preserves_binary_commands_and_transactions() {
        let url = std::env::var("FLORIA_REDIS_TEST_URL").expect("isolated Redis required");
        let manager = RedisConnectionManager {
            client: redis::Client::open(url).unwrap(),
        };
        let mut connection = r2d2::ManageConnection::connect(&manager).unwrap();
        let bytes = vec![0, 255, 13, 10, 42];
        redis::cmd("SET")
            .arg("deadline-binary")
            .arg(&bytes)
            .query::<()>(&mut connection)
            .unwrap();
        let value: Vec<u8> = redis::cmd("GET")
            .arg("deadline-binary")
            .query(&mut connection)
            .unwrap();
        assert_eq!(value, bytes);
        let result: (Vec<u8>, i64) = redis::pipe()
            .atomic()
            .cmd("GET")
            .arg("deadline-binary")
            .cmd("DEL")
            .arg("deadline-binary")
            .query(&mut connection)
            .unwrap();
        assert_eq!(result, (bytes, 1));
    }
}
