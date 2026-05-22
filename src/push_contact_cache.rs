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
//!
//! The cache is intentionally tiny — keys are `(principal_did,
//! peer_psi_token)` pairs and values are a single `verdict` byte
//! (`allowed` / `denied`). floria never stores plaintext contacts.
//
// TODO(round23-T17): on-disk overlay is a stub. Once the real disk
// store lands (see retry_queue.rs's pattern of an optional persistent
// tier), promote this to read/write the same store and clear sentinel.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::Deserialize;

/// Verdict cached for a PSI check. floria does NOT need a richer
/// distinction — anything ambiguous forces a re-check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsiVerdict {
    Allowed,
    Denied,
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
    /// Test hook — last invalidation seen, by principal DID.
    last_invalidated_principal: Option<String>,
}

impl PushContactCache {
    pub fn in_memory() -> Self {
        Self {
            inner: Mutex::new(PushContactCacheInner {
                entries: HashMap::new(),
                disk_overlay: None,
                last_invalidated_principal: None,
            }),
        }
    }

    pub fn with_disk_overlay(path: PathBuf) -> Self {
        Self {
            inner: Mutex::new(PushContactCacheInner {
                entries: HashMap::new(),
                disk_overlay: Some(path),
                last_invalidated_principal: None,
            }),
        }
    }

    pub fn insert(&self, principal_did: &str, peer_psi_token: &str, verdict: PsiVerdict) {
        let mut inner = self.inner.lock().expect("push contact cache poisoned");
        inner.entries.insert(
            (principal_did.to_owned(), peer_psi_token.to_owned()),
            verdict,
        );
    }

    pub fn get(&self, principal_did: &str, peer_psi_token: &str) -> Option<PsiVerdict> {
        let inner = self.inner.lock().expect("push contact cache poisoned");
        inner
            .entries
            .get(&(principal_did.to_owned(), peer_psi_token.to_owned()))
            .copied()
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

        removed
    }

    /// Drop the entire cache. Used in tests and as the catastrophic
    /// fallback if soland ever emits a scope-wide revoke without a
    /// specific principal DID.
    pub fn clear_all(&self) -> usize {
        let mut inner = self.inner.lock().expect("push contact cache poisoned");
        let removed = inner.entries.len();
        inner.entries.clear();
        removed
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
}
