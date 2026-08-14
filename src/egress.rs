//! Push-gateway binding of the shared Arkret egress guard.
//!
//! The gateway has a single outbound posture — public HTTPS only — so this
//! module is just the named entry point; the parse/judge/resolve/bind sequence
//! itself lives in `arkret-egress-reqwest`.

use std::sync::Arc;

use arkret_egress_reqwest::{EgressGuard, GuardedDnsResolver};
use reqwest::Url;

/// The gateway's outbound posture.
#[must_use]
pub fn guard() -> EgressGuard {
    EgressGuard::public_https()
}

/// Connect-time adapter for the shared Arkret outbound policy.
#[must_use]
pub fn dns_resolver() -> Arc<GuardedDnsResolver> {
    guard().resolver()
}

pub fn validate_http_url_for_egress(raw_url: &str, purpose: &str) -> Result<Url, String> {
    guard()
        .lock_str(raw_url, purpose)
        .map(|target| target.url().clone())
        .map_err(|error| error.to_string())
}

pub fn validate_url_for_egress(url: &Url, purpose: &str) -> Result<(), String> {
    guard()
        .lock_url(url, purpose)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_rejects_http_and_non_public_targets() {
        for raw in [
            "http://93.184.216.34/audit",
            "https://127.0.0.1/audit",
            "https://10.1.2.3/audit",
            "https://172.16.0.1/audit",
            "https://192.168.0.1/audit",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/audit",
        ] {
            let url = Url::parse(raw).unwrap();
            assert!(validate_url_for_egress(&url, "test").is_err());
        }
    }

    #[test]
    fn rejects_all_normative_transition_forms() {
        for raw in [
            "https://[64:ff9b::a9fe:a9fe]/latest/meta-data",
            "https://[2002:a00:1::1]/x",
            "https://[2001:0000:7f00:0001:0000:0000:3f57:fefe]/x",
        ] {
            let url = Url::parse(raw).unwrap();
            assert!(
                validate_url_for_egress(&url, "test").is_err(),
                "expected {raw} to be blocked"
            );
        }
    }
}
