use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use arkret_egress_policy::OutboundPolicy;
use reqwest::Url;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Connect-time adapter for the shared Arkret outbound policy.
#[derive(Debug, Clone)]
pub struct EgressGuardResolver;

impl EgressGuardResolver {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl Resolve for EgressGuardResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            type DnsError = Box<dyn std::error::Error + Send + Sync>;
            let resolved: Vec<SocketAddr> = tokio::task::spawn_blocking(move || {
                (host.as_str(), 0u16)
                    .to_socket_addrs()
                    .map(|addrs| addrs.collect::<Vec<_>>())
            })
            .await
            .map_err(|error| -> DnsError { Box::new(std::io::Error::other(error)) })?
            .map_err(|error| -> DnsError { Box::new(error) })?;

            OutboundPolicy::public_https()
                .validate_resolved_addresses(&resolved)
                .map_err(|error| -> DnsError { Box::new(error) })?;
            let addrs: Addrs = Box::new(resolved.into_iter());
            Ok(addrs)
        })
    }
}

pub fn validate_http_url_for_egress(raw_url: &str, purpose: &str) -> Result<Url, String> {
    let url = Url::parse(raw_url).map_err(|error| format!("{purpose}: invalid URL: {error}"))?;
    validate_url_for_egress(&url, purpose, false)?;
    Ok(url)
}

pub fn validate_url_for_egress(
    url: &Url,
    purpose: &str,
    local_development: bool,
) -> Result<(), String> {
    let policy = policy(local_development);
    policy
        .validate_url(url)
        .map_err(|error| format!("{purpose}: {error}"))?;
    let host = url.host_str().expect("validated URL has a host");
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    let port = url.port_or_known_default().unwrap_or(443);
    let resolved = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("{purpose}: DNS resolution for {host} failed: {error}"))?
        .collect::<Vec<_>>();
    policy
        .validate_resolved_addresses(&resolved)
        .map_err(|error| format!("{purpose}: {error}"))
}

fn policy(local_development: bool) -> OutboundPolicy {
    if local_development {
        OutboundPolicy::local_development()
    } else {
        OutboundPolicy::public_https()
    }
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
            assert!(validate_url_for_egress(&url, "test", false).is_err());
        }
    }

    #[test]
    fn local_development_only_adds_http_loopback() {
        let loopback = Url::parse("http://127.0.0.1:5001/audit").unwrap();
        assert!(validate_url_for_egress(&loopback, "test", true).is_ok());

        let private = Url::parse("http://10.0.0.1:5001/audit").unwrap();
        assert!(validate_url_for_egress(&private, "test", true).is_err());
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
                validate_url_for_egress(&url, "test", false).is_err(),
                "expected {raw} to be blocked"
            );
        }
    }
}
