use std::net::{IpAddr, ToSocketAddrs};
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use ipnet::IpNet;

/// How the user named a target, kept around so reports can echo the original input.
#[derive(Debug, Clone)]
pub struct TargetSpec {
    raw: String,
    kind: TargetKind,
}

#[derive(Debug, Clone)]
enum TargetKind {
    Single(IpAddr),
    Network(IpNet),
    Hostname(String),
}

/// One concrete address to scan.
#[derive(Debug, Clone)]
pub struct Host {
    pub addr: IpAddr,
    /// Present when the user gave a name rather than a literal address.
    pub hostname: Option<String>,
}

impl TargetSpec {
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Expands this spec into concrete hosts. Hostnames hit DNS here, so this
    /// can fail at call time even though parsing already succeeded.
    pub fn resolve(&self) -> Result<Vec<Host>> {
        match &self.kind {
            TargetKind::Single(addr) => Ok(vec![Host {
                addr: *addr,
                hostname: None,
            }]),

            TargetKind::Network(net) => Ok(net
                .hosts()
                .map(|addr| Host {
                    addr,
                    hostname: None,
                })
                .collect()),

            TargetKind::Hostname(name) => {
                // `to_socket_addrs` insists on a port; 0 is fine, we only want the IPs.
                let addrs: Vec<IpAddr> = (name.as_str(), 0u16)
                    .to_socket_addrs()
                    .with_context(|| format!("could not resolve {name:?}"))?
                    .map(|sa| sa.ip())
                    .collect();

                if addrs.is_empty() {
                    bail!("{name:?} resolved to no addresses");
                }

                Ok(addrs
                    .into_iter()
                    .map(|addr| Host {
                        addr,
                        hostname: Some(name.clone()),
                    })
                    .collect())
            }
        }
    }

    /// Host count without touching DNS, so we can reject absurd scans up front.
    pub fn approx_host_count(&self) -> u128 {
        match &self.kind {
            TargetKind::Single(_) => 1,
            TargetKind::Hostname(_) => 1,
            TargetKind::Network(net) => match net {
                IpNet::V4(v4) => {
                    let total = 1u128 << (32 - v4.prefix_len());
                    // `hosts()` drops network and broadcast below /31.
                    if v4.prefix_len() >= 31 {
                        total
                    } else {
                        total - 2
                    }
                }
                IpNet::V6(v6) => {
                    let bits = 128 - v6.prefix_len();
                    if bits >= 128 {
                        u128::MAX
                    } else {
                        1u128 << bits
                    }
                }
            },
        }
    }
}

impl FromStr for TargetSpec {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let raw = s.trim().to_string();
        if raw.is_empty() {
            bail!("target is empty");
        }

        // Order matters: a bare address must not be mistaken for a network.
        let kind = if let Ok(addr) = raw.parse::<IpAddr>() {
            TargetKind::Single(addr)
        } else if let Ok(net) = raw.parse::<IpNet>() {
            TargetKind::Network(net)
        } else if looks_like_hostname(&raw) {
            TargetKind::Hostname(raw.clone())
        } else {
            bail!("{raw:?} is not an IP address, a CIDR block, or a hostname");
        };

        Ok(TargetSpec { raw, kind })
    }
}

fn looks_like_hostname(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);

    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_literal_ip() {
        let spec: TargetSpec = "192.168.1.1".parse().unwrap();
        let hosts = spec.resolve().unwrap();

        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].addr.to_string(), "192.168.1.1");
        assert!(hosts[0].hostname.is_none());
    }

    #[test]
    fn expands_cidr_without_network_and_broadcast() {
        let spec: TargetSpec = "10.0.0.0/30".parse().unwrap();
        let hosts = spec.resolve().unwrap();

        assert_eq!(hosts.len(), 2);
        assert_eq!(spec.approx_host_count(), 2);
    }

    #[test]
    fn rejects_garbage() {
        assert!("not a host!".parse::<TargetSpec>().is_err());
    }
}
