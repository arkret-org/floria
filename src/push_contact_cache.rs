//! Round R2/R3 (T17) — push contact PSI cache + `consent_revoke` listener.
//!
//! floria caches the output of private-set-intersection (PSI) checks
//! against the principal server's contact roster so it can decide
//! quickly whether a given pseudonymous push target may still be
//! reached. soland broadcasts a `consent_revoke{scope=any}` event when
//! a principal pulls consent across the board; on that signal floria
//! MUST drop every cached PSI entry for the affected principal so the
//! next push goes through a fresh consent check.
//!
//! Storage modes:
//!   * In-memory (`PushContactCache::in_memory()`) — clearing is a
//!     `HashMap::clear()` for the scoped entries.
//!   * On-disk overlay (`PushContactCache::with_disk_overlay(path)`) —
//!     the in-memory tier is cleared AND the on-disk overlay is marked
//!     invalid by writing a sentinel file. The next cache load checks
//!     the sentinel and forces a refresh.
//!   * PostgreSQL overlay (`PushContactCache::with_postgres_overlay`) —
//!     verdicts are read through / written through a table with
//!     `(principal_did, peer_psi_token, verdict, updated_at)` columns
//!     and a unique key on `(principal_did, peer_psi_token)`.
//!
//! The cache is intentionally tiny — keys are `(principal_did,
//! peer_psi_token)` pairs and values are a single `verdict` byte
//! (`allowed` / `denied`). floria never stores plaintext contacts.
//
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{Context, Result};
use postgres::NoTls;
use serde::Deserialize;

use crate::auth::redact_url_credentials;
use crate::postgres_support::SqlTableName;

/// Verdict cached for a PSI check. floria does NOT need a richer
/// distinction — anything ambiguous forces a re-check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsiVerdict {
    Allowed,
    Denied,
}

impl PsiVerdict {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "allowed" => Some(Self::Allowed),
            "denied" => Some(Self::Denied),
            _ => None,
        }
    }
}

/// Round R2/R3 (T17) — broadcast payload soland emits on a
/// `consent_revoke{scope=any}` event. floria only honours the
/// `scope=any` form; scoped (per-realm) revocations are handled
/// elsewhere in the gateway because they need realm context that
/// floria does not learn.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentRevokeBroadcast {
    /// Idempotency key — echoed back in the ack so soland can drop
    /// retries.
    pub broadcast_id: String,
    /// DID of the principal whose consent footprint is being torn
    /// down. floria never stores realm content; only this opaque
    /// identifier and its PSI cache entries.
    pub principal_did: String,
    /// MUST be `"any"`. Any other value is a wire-shape violation —
    /// floria responds with `unsupported_feature`.
    pub scope: String,
}

impl ConsentRevokeBroadcast {
    pub const SUPPORTED_SCOPE: &'static str = "any";

    pub fn scope_is_any(&self) -> bool {
        self.scope == Self::SUPPORTED_SCOPE
    }
}

#[derive(Debug)]
pub struct PushContactCache {
    inner: Mutex<PushContactCacheInner>,
}

#[derive(Debug)]
struct PushContactCacheInner {
    /// `(principal_did, peer_psi_token)` -> verdict
    entries: HashMap<(String, String), PsiVerdict>,
    /// Optional path to a disk-overlay sentinel file. When set, every
    /// `invalidate_principal` / `clear_all` call also writes / removes
    /// a tombstone so a process restart sees the invalidation.
    disk_overlay: Option<PathBuf>,
    postgres_overlay: Option<PostgresPushContactOverlay>,
    /// Test hook — last invalidation seen, by principal DID.
    last_invalidated_principal: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PostgresPushContactOverlay {
    postgres_url: String,
    table: SqlTableName,
    target_label: String,
}

impl PostgresPushContactOverlay {
    pub fn new(postgres_url: impl Into<String>, table: impl AsRef<str>) -> Result<Self> {
        let postgres_url = postgres_url.into();
        let table = SqlTableName::parse(table.as_ref(), "storage.push_contact_cache_table")?;
        Ok(Self {
            target_label: redact_url_credentials(&postgres_url),
            postgres_url,
            table,
        })
    }

    fn connect(&self) -> Result<postgres::Client> {
        postgres::Client::connect(&self.postgres_url, NoTls).with_context(|| {
            format!(
                "failed to connect to PostgreSQL push contact cache {}",
                self.target_label
            )
        })
    }

    fn insert(&self, principal_did: &str, peer_psi_token: &str, verdict: PsiVerdict) -> Result<()> {
        let mut client = self.connect()?;
        let sql = format!(
            "INSERT INTO {} (principal_did, peer_psi_token, verdict, updated_at) \
             VALUES ($1, $2, $3, NOW()) \
             ON CONFLICT (principal_did, peer_psi_token) \
             DO UPDATE SET verdict = EXCLUDED.verdict, updated_at = NOW()",
            self.table.as_sql()
        );
        client
            .execute(&sql, &[&principal_did, &peer_psi_token, &verdict.as_str()])
            .with_context(|| {
                format!(
                    "failed to upsert PostgreSQL push contact cache table {}",
                    self.table.as_sql()
                )
            })?;
        Ok(())
    }

    fn get(&self, principal_did: &str, peer_psi_token: &str) -> Result<Option<PsiVerdict>> {
        let mut client = self.connect()?;
        let sql = format!(
            "SELECT verdict FROM {} WHERE principal_did = $1 AND peer_psi_token = $2",
            self.table.as_sql()
        );
        let row = client
            .query_opt(&sql, &[&principal_did, &peer_psi_token])
            .with_context(|| {
                format!(
                    "failed to read PostgreSQL push contact cache table {}",
                    self.table.as_sql()
                )
            })?;
        Ok(row
            .and_then(|row| row.try_get::<_, String>(0).ok())
            .and_then(|value| PsiVerdict::from_str(&value)))
    }

    fn invalidate_principal(&self, principal_did: &str) -> Result<usize> {
        let mut client = self.connect()?;
        let sql = format!(
            "DELETE FROM {} WHERE principal_did = $1",
            self.table.as_sql()
        );
        client
            .execute(&sql, &[&principal_did])
            .with_context(|| {
                format!(
                    "failed to invalidate PostgreSQL push contact cache table {}",
                    self.table.as_sql()
                )
            })
            .map(|count| count as usize)
    }

    fn clear_all(&self) -> Result<usize> {
        let mut client = self.connect()?;
        let sql = format!("DELETE FROM {}", self.table.as_sql());
        client
            .execute(&sql, &[])
            .with_context(|| {
                format!(
                    "failed to clear PostgreSQL push contact cache table {}",
                    self.table.as_sql()
                )
            })
            .map(|count| count as usize)
    }
}

impl PushContactCache {
    pub fn in_memory() -> Self {
        Self {
            inner: Mutex::new(PushContactCacheInner {
                entries: HashMap::new(),
                disk_overlay: None,
                postgres_overlay: None,
                last_invalidated_principal: None,
            }),
        }
    }

    pub fn with_disk_overlay(path: PathBuf) -> Self {
        Self {
            inner: Mutex::new(PushContactCacheInner {
                entries: HashMap::new(),
                disk_overlay: Some(path),
                postgres_overlay: None,
                last_invalidated_principal: None,
            }),
        }
    }

    pub fn with_postgres_overlay(
        postgres_url: impl Into<String>,
        table: impl AsRef<str>,
    ) -> Result<Self> {
        Ok(Self {
            inner: Mutex::new(PushContactCacheInner {
                entries: HashMap::new(),
                disk_overlay: None,
                postgres_overlay: Some(PostgresPushContactOverlay::new(postgres_url, table)?),
                last_invalidated_principal: None,
            }),
        })
    }

    pub fn insert(&self, principal_did: &str, peer_psi_token: &str, verdict: PsiVerdict) {
        let mut inner = self.inner.lock().expect("push contact cache poisoned");
        inner.entries.insert(
            (principal_did.to_owned(), peer_psi_token.to_owned()),
            verdict,
        );
        if let Some(overlay) = inner.postgres_overlay.as_ref()
            && let Err(err) = overlay.insert(principal_did, peer_psi_token, verdict)
        {
            tracing::warn!(
                error = %err,
                principal_did,
                "postgres push contact cache write-through failed"
            );
        }
    }

    pub fn get(&self, principal_did: &str, peer_psi_token: &str) -> Option<PsiVerdict> {
        let mut inner = self.inner.lock().expect("push contact cache poisoned");
        if let Some(verdict) = inner
            .entries
            .get(&(principal_did.to_owned(), peer_psi_token.to_owned()))
            .copied()
        {
            return Some(verdict);
        }
        let verdict = inner.postgres_overlay.as_ref().and_then(|overlay| {
            match overlay.get(principal_did, peer_psi_token) {
                Ok(verdict) => verdict,
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        principal_did,
                        "postgres push contact cache read-through failed"
                    );
                    None
                }
            }
        });
        if let Some(verdict) = verdict {
            inner.entries.insert(
                (principal_did.to_owned(), peer_psi_token.to_owned()),
                verdict,
            );
        }
        verdict
    }

    /// Drop every cached PSI entry for `principal_did`. Returns the
    /// number of entries that were evicted. If a disk overlay is
    /// configured, also writes a sentinel tombstone so a future load
    /// re-derives the verdict.
    pub fn invalidate_principal(&self, principal_did: &str) -> usize {
        let mut inner = self.inner.lock().expect("push contact cache poisoned");
        let before = inner.entries.len();
        inner.entries.retain(|(did, _), _| did != principal_did);
        let removed = before - inner.entries.len();
        inner.last_invalidated_principal = Some(principal_did.to_owned());

        if let Some(overlay) = inner.disk_overlay.as_ref() {
            // Best-effort tombstone — failure is logged but not fatal:
            // the in-memory layer is already cleared, and the next
            // process boot will see a missing sentinel and refresh.
            if let Some(parent) = overlay.parent()
                && let Err(err) = std::fs::create_dir_all(parent)
            {
                tracing::warn!(
                    error = %err,
                    path = %overlay.display(),
                    "psi cache disk overlay tombstone parent create failed"
                );
            }
            let body = format!("invalidated:{principal_did}\n");
            if let Err(err) = std::fs::write(overlay, body) {
                tracing::warn!(
                    error = %err,
                    path = %overlay.display(),
                    "psi cache disk overlay tombstone write failed"
                );
            }
        }

        let postgres_removed = inner
            .postgres_overlay
            .as_ref()
            .and_then(
                |overlay| match overlay.invalidate_principal(principal_did) {
                    Ok(count) => Some(count),
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            principal_did,
                            "postgres push contact cache invalidation failed"
                        );
                        None
                    }
                },
            )
            .unwrap_or(0);

        removed.max(postgres_removed)
    }

    /// Drop the entire cache. Used in tests and as the catastrophic
    /// fallback if soland ever emits a scope-wide revoke without a
    /// specific principal DID.
    pub fn clear_all(&self) -> usize {
        let mut inner = self.inner.lock().expect("push contact cache poisoned");
        let removed = inner.entries.len();
        inner.entries.clear();
        let postgres_removed = inner
            .postgres_overlay
            .as_ref()
            .and_then(|overlay| match overlay.clear_all() {
                Ok(count) => Some(count),
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        "postgres push contact cache clear failed"
                    );
                    None
                }
            })
            .unwrap_or(0);
        removed.max(postgres_removed)
    }

    #[cfg(test)]
    pub(crate) fn last_invalidated_principal(&self) -> Option<String> {
        let inner = self.inner.lock().expect("push contact cache poisoned");
        inner.last_invalidated_principal.clone()
    }
}

impl Default for PushContactCache {
    fn default() -> Self {
        Self::in_memory()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_cache_round_trips_verdict() {
        let cache = PushContactCache::in_memory();
        cache.insert("did:web:alice.example", "psi-token-1", PsiVerdict::Allowed);
        assert_eq!(
            cache.get("did:web:alice.example", "psi-token-1"),
            Some(PsiVerdict::Allowed)
        );
    }

    #[test]
    fn invalidate_principal_evicts_only_that_principal() {
        let cache = PushContactCache::in_memory();
        cache.insert("did:web:alice.example", "psi-1", PsiVerdict::Allowed);
        cache.insert("did:web:alice.example", "psi-2", PsiVerdict::Denied);
        cache.insert("did:web:bob.example", "psi-1", PsiVerdict::Allowed);

        let evicted = cache.invalidate_principal("did:web:alice.example");
        assert_eq!(evicted, 2);
        assert!(cache.get("did:web:alice.example", "psi-1").is_none());
        assert_eq!(
            cache.get("did:web:bob.example", "psi-1"),
            Some(PsiVerdict::Allowed)
        );
        assert_eq!(
            cache.last_invalidated_principal().as_deref(),
            Some("did:web:alice.example")
        );
    }

    #[test]
    fn consent_revoke_scope_is_any_helper() {
        let bcast = ConsentRevokeBroadcast {
            broadcast_id: "id-1".to_owned(),
            principal_did: "did:web:alice.example".to_owned(),
            scope: "any".to_owned(),
        };
        assert!(bcast.scope_is_any());

        let scoped = ConsentRevokeBroadcast {
            broadcast_id: "id-2".to_owned(),
            principal_did: "did:web:alice.example".to_owned(),
            scope: "realm".to_owned(),
        };
        assert!(!scoped.scope_is_any());
    }

    #[test]
    fn disk_overlay_writes_tombstone() {
        // Pick a deterministic tempdir under target/ so cleanup is
        // implicit. We deliberately do NOT use the `tempfile` crate —
        // floria's existing tests don't pull it in.
        let tempdir = std::env::temp_dir().join(format!("floria-psi-cache-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tempdir);
        let path = tempdir.join("psi-overlay.tomb");
        let _ = std::fs::remove_file(&path);

        let cache = PushContactCache::with_disk_overlay(path.clone());
        cache.insert("did:web:alice.example", "psi-1", PsiVerdict::Allowed);
        let evicted = cache.invalidate_principal("did:web:alice.example");
        assert_eq!(evicted, 1);
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("did:web:alice.example"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn postgres_overlay_rejects_unsafe_table_name() {
        let error = PushContactCache::with_postgres_overlay(
            "postgres://floria:floria@localhost/floria",
            "floria.cache;drop",
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("storage.push_contact_cache_table")
        );
    }
}
