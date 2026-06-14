use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use reqwest::Url;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

const FLORIA_EGRESS_ALLOW_PRIVATE_NETWORKS: &str = "FLORIA_EGRESS_ALLOW_PRIVATE_NETWORKS";

pub fn private_networks_allowed() -> bool {
    env_bool(FLORIA_EGRESS_ALLOW_PRIVATE_NETWORKS).unwrap_or(false)
}

/// DNS resolver that re-applies the egress blocklist to *every* address
/// the system resolver returns, at connect time, and hands the connector
/// only the surviving (validated) `SocketAddr`s.
///
/// This closes the TOCTOU / DNS-rebinding gap (FLO-03-001): the previous
/// design validated the host once via a standalone `to_socket_addrs`
/// then let reqwest resolve the *name* again independently at connect
/// time, so a hostile name could resolve to a public IP during
/// validation and to `169.254.169.254` / `10.x` / `::1` during connect.
/// Installing this resolver on the reqwest client means the addresses the
/// connector dials are exactly the ones we filtered — there is no second,
/// unchecked resolution.
#[derive(Debug, Clone)]
pub struct EgressGuardResolver {
    allow_private_networks: bool,
}

impl EgressGuardResolver {
    pub fn from_env() -> Arc<Self> {
        Arc::new(Self {
            allow_private_networks: private_networks_allowed(),
        })
    }
}

impl Resolve for EgressGuardResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let allow_private = self.allow_private_networks;
        Box::pin(async move {
            type DnsError = Box<dyn std::error::Error + Send + Sync>;
            let resolved: Vec<SocketAddr> = tokio::task::spawn_blocking(move || {
                // Port is irrelevant here — reqwest overrides it with the
                // URL/scheme port afterwards — so resolve against 0.
                (host.as_str(), 0u16)
                    .to_socket_addrs()
                    .map(|addrs| addrs.collect::<Vec<_>>())
            })
            .await
            .map_err(|error| -> DnsError { Box::new(std::io::Error::other(error)) })?
            .map_err(|error| -> DnsError { Box::new(error) })?;

            if allow_private {
                let addrs: Addrs = Box::new(resolved.into_iter());
                return Ok(addrs);
            }

            let safe: Vec<SocketAddr> = resolved
                .into_iter()
                .filter(|addr| !blocked_ip(addr.ip()))
                .collect();
            if safe.is_empty() {
                return Err(Box::<dyn std::error::Error + Send + Sync>::from(
                    "egress target resolved only to blocked (private/metadata) addresses",
                ));
            }
            let addrs: Addrs = Box::new(safe.into_iter());
            Ok(addrs)
        })
    }
}

pub fn validate_http_url_for_egress(raw_url: &str, purpose: &str) -> Result<Url, String> {
    let url = Url::parse(raw_url).map_err(|error| format!("{purpose}: invalid URL: {error}"))?;
    validate_url_for_egress(&url, purpose, private_networks_allowed())?;
    Ok(url)
}

pub fn validate_url_for_egress(
    url: &Url,
    purpose: &str,
    allow_private_networks: bool,
) -> Result<(), String> {
    match url.scheme() {
        "http" | "https" => {}
        scheme => return Err(format!("{purpose}: URL scheme {scheme:?} is not allowed")),
    }
    let host = url
        .host_str()
        .filter(|host| !host.trim().is_empty())
        .ok_or_else(|| format!("{purpose}: URL host is required"))?;
    if allow_private_networks {
        return Ok(());
    }
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return Err(format!("{purpose}: localhost egress target is not allowed"));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return validate_resolved_ip(ip, purpose);
    }
    let port = url.port_or_known_default().unwrap_or(443);
    let resolved = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("{purpose}: DNS resolution for {host} failed: {error}"))?;
    for addr in resolved {
        validate_resolved_ip(addr.ip(), purpose)?;
    }
    Ok(())
}

fn validate_resolved_ip(ip: IpAddr, purpose: &str) -> Result<(), String> {
    if blocked_ip(ip) {
        return Err(format!(
            "{purpose}: egress target resolved to blocked address {ip}"
        ));
    }
    Ok(())
}

/// Resolve `host` and return *only* the addresses that survive the egress
/// blocklist, so a caller that cannot install [`EgressGuardResolver`]
/// (e.g. the isahc-based WebPush client, which has no dynamic resolver
/// hook) can pin the connection to these exact validated IPs and close
/// the same TOCTOU / DNS-rebinding gap (FLO-03-001).
///
/// `host` may itself be an IP literal, in which case it is validated and
/// returned as-is. The returned vector is never empty on `Ok`; if every
/// resolved address is blocked, this returns `Err` instead so the caller
/// fails closed.
///
/// When `FLORIA_EGRESS_ALLOW_PRIVATE_NETWORKS` is set the blocklist is
/// disabled (local-dev override) and every resolved address is returned.
pub fn resolved_egress_ips(host: &str, port: u16, purpose: &str) -> Result<Vec<IpAddr>, String> {
    let allow_private = private_networks_allowed();
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !allow_private {
            validate_resolved_ip(ip, purpose)?;
        }
        return Ok(vec![ip]);
    }
    let resolved: Vec<IpAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("{purpose}: DNS resolution for {host} failed: {error}"))?
        .map(|addr| addr.ip())
        .collect();
    if allow_private {
        return Ok(resolved);
    }
    let safe: Vec<IpAddr> = resolved.into_iter().filter(|ip| !blocked_ip(*ip)).collect();
    if safe.is_empty() {
        return Err(format!(
            "{purpose}: egress target {host} resolved only to blocked (private/metadata) addresses"
        ));
    }
    Ok(safe)
}

fn blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => blocked_ipv4(ip),
        IpAddr::V6(ip) => {
            // Unwrap any IPv4 smuggled through a translation / tunnel
            // mechanism (IPv4-mapped, NAT64, 6to4) and re-check it against
            // the IPv4 blocklist so e.g. `64:ff9b::169.254.169.254` or a
            // 6to4-wrapped 10.0.0.0/8 cannot bypass the v4 rules.
            if let Some(v4) = ipv4_mapped(ip)
                .or_else(|| nat64_embedded_ipv4(ip))
                .or_else(|| sixtofour_embedded_ipv4(ip))
                && blocked_ipv4(v4)
            {
                return true;
            }
            blocked_ipv6(ip)
        }
    }
}

fn blocked_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 169 && b == 254 && c == 169 && d == 254)
        || a >= 224
}

fn blocked_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        // NAT64 well-known prefix 64:ff9b::/96 and local-use 64:ff9b:1::/48
        // (RFC 6052 / RFC 8215). These translate to IPv4 destinations and
        // could reach internal v4 ranges, so block the whole prefix in
        // addition to unwrapping the embedded v4 above.
        || (segments[0] == 0x0064 && segments[1] == 0xff9b)
        // 6to4 2002::/16 (RFC 3056) — tunnels arbitrary embedded IPv4.
        || segments[0] == 0x2002
}

fn ipv4_mapped(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = ip.segments();
    if segments[..5] == [0, 0, 0, 0, 0] && segments[5] == 0xffff {
        let high = segments[6].to_be_bytes();
        let low = segments[7].to_be_bytes();
        Some(Ipv4Addr::new(high[0], high[1], low[0], low[1]))
    } else {
        None
    }
}

/// Embedded IPv4 of a NAT64 well-known-prefix address (64:ff9b::/96):
/// the last 32 bits carry the translated IPv4 destination.
fn nat64_embedded_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = ip.segments();
    if segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2..6] == [0, 0, 0, 0] {
        let high = segments[6].to_be_bytes();
        let low = segments[7].to_be_bytes();
        Some(Ipv4Addr::new(high[0], high[1], low[0], low[1]))
    } else {
        None
    }
}

/// Embedded IPv4 of a 6to4 address (2002:V4ADDR::/48): segments 1–2 hold
/// the encapsulated IPv4 address.
fn sixtofour_embedded_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = ip.segments();
    if segments[0] == 0x2002 {
        let high = segments[1].to_be_bytes();
        let low = segments[2].to_be_bytes();
        Some(Ipv4Addr::new(high[0], high[1], low[0], low[1]))
    } else {
        None
    }
}

fn env_bool(name: &str) -> Option<bool> {
    std::env::var(name)
        .ok()
        .map(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_private_and_metadata_targets() {
        for raw in [
            "http://127.0.0.1/audit",
            "http://10.1.2.3/audit",
            "http://172.16.0.1/audit",
            "http://192.168.0.1/audit",
            "http://169.254.169.254/latest/meta-data",
            "http://[::1]/audit",
        ] {
            let url = Url::parse(raw).unwrap();
            assert!(validate_url_for_egress(&url, "test", false).is_err());
        }
    }

    #[test]
    fn explicit_allow_private_networks_keeps_local_dev_possible() {
        let url = Url::parse("http://127.0.0.1:5001/audit").unwrap();
        assert!(validate_url_for_egress(&url, "test", true).is_ok());
    }

    #[test]
    fn rejects_nat64_and_6to4_wrapped_internal_targets() {
        for raw in [
            // NAT64 well-known prefix wrapping the cloud metadata IP.
            "http://[64:ff9b::a9fe:a9fe]/latest/meta-data",
            // NAT64 local-use prefix.
            "http://[64:ff9b:1::1]/x",
            // 6to4 wrapping 10.0.0.1 (2002:0a00:0001::).
            "http://[2002:a00:1::1]/x",
        ] {
            let url = Url::parse(raw).unwrap();
            assert!(
                validate_url_for_egress(&url, "test", false).is_err(),
                "expected {raw} to be blocked"
            );
        }
    }
}
