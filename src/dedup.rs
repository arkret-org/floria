use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use blake2::Blake2s256;
use blake2::digest::Digest;

use crate::models::NotifyResponse;

#[derive(Debug, Clone)]
pub struct CachedNotifyResponse {
    pub response: NotifyResponse,
}

#[derive(Debug)]
struct CacheEntry {
    expires_at: Instant,
    response: CachedNotifyResponse,
}

#[derive(Debug)]
pub struct NotifyDeduplicator {
    ttl: Duration,
    entries: Mutex<HashMap<String, CacheEntry>>,
    delivered_devices: Mutex<HashMap<String, Instant>>,
}

impl NotifyDeduplicator {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
            delivered_devices: Mutex::new(HashMap::new()),
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn get(&self, key: &str) -> Option<CachedNotifyResponse> {
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|_, entry| entry.expires_at > now);
        entries.get(key).map(|entry| entry.response.clone())
    }

    pub fn insert_success(&self, key: &str, response: NotifyResponse) {
        if self.ttl.is_zero() {
            return;
        }

        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|_, entry| entry.expires_at > now);
        entries.insert(
            key.to_owned(),
            CacheEntry {
                expires_at: now + self.ttl,
                response: CachedNotifyResponse { response },
            },
        );
    }

    pub fn contains_delivered_device(
        &self,
        notification_key: &str,
        app_id: &str,
        pushkey: &str,
    ) -> bool {
        let key = delivered_device_key(notification_key, app_id, pushkey);
        let now = Instant::now();
        let mut entries = self
            .delivered_devices
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|_, expires_at| *expires_at > now);
        entries.contains_key(&key)
    }

    pub fn mark_delivered_device(&self, notification_key: &str, app_id: &str, pushkey: &str) {
        if self.ttl.is_zero() {
            return;
        }

        let key = delivered_device_key(notification_key, app_id, pushkey);
        let now = Instant::now();
        let mut entries = self
            .delivered_devices
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|_, expires_at| *expires_at > now);
        entries.insert(key, now + self.ttl);
    }
}

pub fn request_hash(request_body: &[u8]) -> String {
    let mut hasher = Blake2s256::new();
    hasher.update(request_body);
    hex::encode(hasher.finalize())
}

fn delivered_device_key(notification_key: &str, app_id: &str, pushkey: &str) -> String {
    let mut hasher = Blake2s256::new();
    hasher.update(notification_key.as_bytes());
    hasher.update([0]);
    hasher.update(app_id.as_bytes());
    hasher.update([0]);
    hasher.update(pushkey.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_inserted_response_before_expiry() {
        let dedup = NotifyDeduplicator::new(Duration::from_secs(5));
        let response = NotifyResponse {
            rejected: vec!["pushkey".to_owned()],
        };
        let key = request_hash(br#"{"notification":{}}"#);

        dedup.insert_success(&key, response.clone());

        assert_eq!(
            dedup.get(&key).map(|cached| cached.response),
            Some(response)
        );
    }

    #[test]
    fn expires_entries_after_ttl() {
        let dedup = NotifyDeduplicator::new(Duration::from_millis(1));
        let key = request_hash(br#"{"notification":{}}"#);
        dedup.insert_success(&key, NotifyResponse { rejected: vec![] });

        std::thread::sleep(Duration::from_millis(5));

        assert!(dedup.get(&key).is_none());
    }

    #[test]
    fn remembers_delivered_devices_until_expiry() {
        let dedup = NotifyDeduplicator::new(Duration::from_secs(5));
        let notification_key = request_hash(br#"{"notification":{}}"#);

        dedup.mark_delivered_device(&notification_key, "com.example.app", "pushkey");

        assert!(dedup.contains_delivered_device(
            &notification_key,
            "com.example.app",
            "pushkey"
        ));
    }
}
