//! Multiaddr network utilities for classifying addresses.
//!
//! This module provides utilities for determining whether multiaddresses are
//! public, private, or unroutable based on IP ranges and DNS domain names.
//!
//! Original implementation: https://github.com/multiformats/go-multiaddr/blob/master/net/private.go

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libp2p::{Multiaddr, multiaddr::Protocol};

/// Private IPv4 CIDR ranges.
const PRIVATE_CIDR4: &[(&str, Ipv4Addr, u8)] = &[
    // localhost
    ("127.0.0.0/8", Ipv4Addr::new(127, 0, 0, 0), 8),
    // private networks
    ("10.0.0.0/8", Ipv4Addr::new(10, 0, 0, 0), 8),
    ("100.64.0.0/10", Ipv4Addr::new(100, 64, 0, 0), 10),
    ("172.16.0.0/12", Ipv4Addr::new(172, 16, 0, 0), 12),
    ("192.168.0.0/16", Ipv4Addr::new(192, 168, 0, 0), 16),
    // link local
    ("169.254.0.0/16", Ipv4Addr::new(169, 254, 0, 0), 16),
];

/// Private IPv6 CIDR ranges.
const PRIVATE_CIDR6: &[(&str, Ipv6Addr, u8)] = &[
    // localhost
    ("::1/128", Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 128),
    // ULA reserved
    ("fc00::/7", Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
    // link local
    ("fe80::/10", Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
];

/// Unroutable IPv4 CIDR ranges.
const UNROUTABLE_CIDR4: &[(&str, Ipv4Addr, u8)] = &[
    ("0.0.0.0/8", Ipv4Addr::new(0, 0, 0, 0), 8),
    ("192.0.0.0/26", Ipv4Addr::new(192, 0, 0, 0), 26),
    ("192.0.2.0/24", Ipv4Addr::new(192, 0, 2, 0), 24),
    ("192.88.99.0/24", Ipv4Addr::new(192, 88, 99, 0), 24),
    ("198.18.0.0/15", Ipv4Addr::new(198, 18, 0, 0), 15),
    ("198.51.100.0/24", Ipv4Addr::new(198, 51, 100, 0), 24),
    ("203.0.113.0/24", Ipv4Addr::new(203, 0, 113, 0), 24),
    ("224.0.0.0/4", Ipv4Addr::new(224, 0, 0, 0), 4),
    ("240.0.0.0/4", Ipv4Addr::new(240, 0, 0, 0), 4),
    ("255.255.255.255/32", Ipv4Addr::new(255, 255, 255, 255), 32),
];

/// Unroutable IPv6 CIDR ranges.
const UNROUTABLE_CIDR6: &[(&str, Ipv6Addr, u8)] = &[
    // multicast
    ("ff00::/8", Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
    // documentation
    (
        "2001:db8::/32",
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
        32,
    ),
];

/// Global unicast IPv6 CIDR range.
const GLOBAL_UNICAST_CIDR6: &[(&str, Ipv6Addr, u8)] =
    &[("2000::/3", Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3)];

/// NAT64 CIDR ranges.
const NAT64_CIDRS: &[(&str, Ipv6Addr, u8)] = &[
    // RFC 8215 - Local use NAT64 prefix
    (
        "64:ff9b:1::/48",
        Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0),
        48,
    ),
    // RFC 6052 - WellKnown NAT64 prefix
    (
        "64:ff9b::/96",
        Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0),
        96,
    ),
];

/// Unresolvable domains that do not resolve to an IP address.
/// Ref: https://en.wikipedia.org/wiki/Special-use_domain_name#Reserved_domain_names
const UNRESOLVABLE_DOMAINS: &[&str] = &[
    // Reverse DNS Lookup
    ".in-addr.arpa",
    ".ip6.arpa",
    // RFC 6761: Users MAY assume that queries for "invalid" names will always return NXDOMAIN
    ".invalid",
];

/// Private use domains reserved for private use with no central authority.
/// Ref: https://en.wikipedia.org/wiki/Special-use_domain_name#Reserved_domain_names
const PRIVATE_USE_DOMAINS: &[&str] = &[
    // RFC 8375: Reserved for home networks
    ".home.arpa",
    // MDNS
    ".local",
    // RFC 6761: No central authority for .test names
    ".test",
];

/// RFC 6761: Users may assume that IPv4 and IPv6 address queries for localhost
/// names will always resolve to the respective IP loopback address.
const LOCALHOST_DOMAIN: &str = ".localhost";

/// Extension trait for `Multiaddr` providing network classification methods.
pub trait Manet {
    /// Returns `true` if the IP part of the multiaddr is a publicly routable
    /// address or if it's a DNS address without a special use domain (e.g.,
    /// `.local`).
    fn is_public(&self) -> bool;

    /// Returns `true` if the IP part of the multiaddr is in a private network.
    fn is_private(&self) -> bool;
}

impl Manet for Multiaddr {
    fn is_public(&self) -> bool {
        for proto in self.iter() {
            match proto {
                Protocol::Ip6zone(_) => {
                    // Skip zone identifier, continue checking
                    continue;
                }
                Protocol::Ip4(ip) => {
                    return !in_ipv4_range(ip, PRIVATE_CIDR4)
                        && !in_ipv4_range(ip, UNROUTABLE_CIDR4);
                }
                Protocol::Ip6(ip) => {
                    // IP6 documentation prefix (part of Unroutable6) is a subset of the ip6
                    // global unicast allocation so we ensure that it's not a documentation
                    // prefix by diffing with Unroutable6
                    let is_public_unicast = in_ipv6_range(ip, GLOBAL_UNICAST_CIDR6)
                        && !in_ipv6_range(ip, UNROUTABLE_CIDR6);
                    if is_public_unicast {
                        return true;
                    }
                    // The WellKnown NAT64 prefix (RFC 6052) can only reference a public IPv4
                    // address. The Local use NAT64 prefix (RFC 8215) can
                    // reference private IPv4 addresses. But since the
                    // translation from Local use NAT64 prefix to IPv4 address is left
                    // to the user we have no way of knowing which IPv4 address is referenced.
                    // We count these as Public addresses because a false negative for this method
                    // here is generally worse than a false positive.
                    return in_ipv6_range(ip, NAT64_CIDRS);
                }
                Protocol::Dns(name)
                | Protocol::Dns4(name)
                | Protocol::Dns6(name)
                | Protocol::Dnsaddr(name) => {
                    if is_subdomain(&name, LOCALHOST_DOMAIN) {
                        return false;
                    }
                    for ud in UNRESOLVABLE_DOMAINS {
                        if is_subdomain(&name, ud) {
                            return false;
                        }
                    }
                    for pd in PRIVATE_USE_DOMAINS {
                        if is_subdomain(&name, pd) {
                            return false;
                        }
                    }
                    return true;
                }
                _ => {
                    // For other protocols, stop checking
                    return false;
                }
            }
        }
        false
    }

    fn is_private(&self) -> bool {
        for proto in self.iter() {
            match proto {
                Protocol::Ip6zone(_) => {
                    // Skip zone identifier, continue checking
                    continue;
                }
                Protocol::Ip4(ip) => {
                    return in_ipv4_range(ip, PRIVATE_CIDR4);
                }
                Protocol::Ip6(ip) => {
                    return in_ipv6_range(ip, PRIVATE_CIDR6);
                }
                Protocol::Dns(name)
                | Protocol::Dns4(name)
                | Protocol::Dns6(name)
                | Protocol::Dnsaddr(name) => {
                    // Only localhost domain is considered private for DNS
                    // We don't check for privateUseDomains because private use domains can
                    // resolve to public IP addresses
                    return is_subdomain(&name, LOCALHOST_DOMAIN);
                }
                _ => {
                    // For other protocols, stop checking
                    return false;
                }
            }
        }
        false
    }
}

/// Checks if `child` is a subdomain of `parent`.
/// Also returns `true` if `child` and `parent` are the same domain.
/// `parent` must have a "." prefix.
fn is_subdomain(child: &str, parent: &str) -> bool {
    child.ends_with(parent) || child == &parent[1..]
}

/// Checks if an IPv4 address is within any of the given CIDR ranges.
fn in_ipv4_range(ip: Ipv4Addr, ranges: &[(&str, Ipv4Addr, u8)]) -> bool {
    let ip_bits = u32::from(ip);
    for (_, network, prefix_len) in ranges {
        let network_bits = u32::from(*network);
        let mask = if *prefix_len == 0 {
            0
        } else {
            !0u32 << (32u8.saturating_sub(*prefix_len))
        };
        if (ip_bits & mask) == (network_bits & mask) {
            return true;
        }
    }
    false
}

/// Checks if an IPv6 address is within any of the given CIDR ranges.
fn in_ipv6_range(ip: Ipv6Addr, ranges: &[(&str, Ipv6Addr, u8)]) -> bool {
    let ip_bits = u128::from(ip);
    for (_, network, prefix_len) in ranges {
        let network_bits = u128::from(*network);
        let mask = if *prefix_len == 0 {
            0
        } else {
            !0u128 << (128u8.saturating_sub(*prefix_len))
        };
        if (ip_bits & mask) == (network_bits & mask) {
            return true;
        }
    }
    false
}

/// Extension trait for `IpAddr` providing network classification methods.
pub trait ManetIp {
    /// Returns `true` if the IP address is publicly routable.
    fn is_public_ip(&self) -> bool;

    /// Returns `true` if the IP address is in a private network.
    fn is_private_ip(&self) -> bool;
}

impl ManetIp for IpAddr {
    fn is_public_ip(&self) -> bool {
        match self {
            IpAddr::V4(ip) => {
                !in_ipv4_range(*ip, PRIVATE_CIDR4) && !in_ipv4_range(*ip, UNROUTABLE_CIDR4)
            }
            IpAddr::V6(ip) => {
                let is_public_unicast = in_ipv6_range(*ip, GLOBAL_UNICAST_CIDR6)
                    && !in_ipv6_range(*ip, UNROUTABLE_CIDR6);
                if is_public_unicast {
                    return true;
                }
                in_ipv6_range(*ip, NAT64_CIDRS)
            }
        }
    }

    fn is_private_ip(&self) -> bool {
        match self {
            IpAddr::V4(ip) => in_ipv4_range(*ip, PRIVATE_CIDR4),
            IpAddr::V6(ip) => in_ipv6_range(*ip, PRIVATE_CIDR6),
        }
    }
}

impl ManetIp for Ipv4Addr {
    fn is_public_ip(&self) -> bool {
        !in_ipv4_range(*self, PRIVATE_CIDR4) && !in_ipv4_range(*self, UNROUTABLE_CIDR4)
    }

    fn is_private_ip(&self) -> bool {
        in_ipv4_range(*self, PRIVATE_CIDR4)
    }
}

impl ManetIp for Ipv6Addr {
    fn is_public_ip(&self) -> bool {
        let is_public_unicast =
            in_ipv6_range(*self, GLOBAL_UNICAST_CIDR6) && !in_ipv6_range(*self, UNROUTABLE_CIDR6);
        if is_public_unicast {
            return true;
        }
        in_ipv6_range(*self, NAT64_CIDRS)
    }

    fn is_private_ip(&self) -> bool {
        in_ipv6_range(*self, PRIVATE_CIDR6)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn ipv4_private() {
        // Localhost
        assert!(Ipv4Addr::new(127, 0, 0, 1).is_private_ip());
        assert!(Ipv4Addr::new(127, 255, 255, 255).is_private_ip());

        // 10.0.0.0/8
        assert!(Ipv4Addr::new(10, 0, 0, 1).is_private_ip());
        assert!(Ipv4Addr::new(10, 255, 255, 255).is_private_ip());

        // 172.16.0.0/12
        assert!(Ipv4Addr::new(172, 16, 0, 1).is_private_ip());
        assert!(Ipv4Addr::new(172, 31, 255, 255).is_private_ip());
        assert!(!Ipv4Addr::new(172, 32, 0, 0).is_private_ip());

        // 192.168.0.0/16
        assert!(Ipv4Addr::new(192, 168, 0, 1).is_private_ip());
        assert!(Ipv4Addr::new(192, 168, 255, 255).is_private_ip());

        // Link local
        assert!(Ipv4Addr::new(169, 254, 0, 1).is_private_ip());

        // Public
        assert!(!Ipv4Addr::new(8, 8, 8, 8).is_private_ip());
        assert!(!Ipv4Addr::new(1, 1, 1, 1).is_private_ip());
    }

    #[test]
    fn ipv4_public() {
        // Public addresses
        assert!(Ipv4Addr::new(8, 8, 8, 8).is_public_ip());
        assert!(Ipv4Addr::new(1, 1, 1, 1).is_public_ip());
        assert!(Ipv4Addr::new(142, 250, 185, 14).is_public_ip());

        // Private addresses are not public
        assert!(!Ipv4Addr::new(127, 0, 0, 1).is_public_ip());
        assert!(!Ipv4Addr::new(10, 0, 0, 1).is_public_ip());
        assert!(!Ipv4Addr::new(192, 168, 1, 1).is_public_ip());

        // Unroutable addresses are not public
        assert!(!Ipv4Addr::new(0, 0, 0, 0).is_public_ip());
        assert!(!Ipv4Addr::new(255, 255, 255, 255).is_public_ip());
        assert!(!Ipv4Addr::new(224, 0, 0, 1).is_public_ip()); // Multicast
    }

    #[test]
    fn ipv6_private() {
        // Localhost
        assert!(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).is_private_ip());

        // ULA
        assert!(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1).is_private_ip());
        assert!(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).is_private_ip());

        // Link local
        assert!(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).is_private_ip());

        // Public
        assert!(!Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888).is_private_ip());
    }

    #[test]
    fn ipv6_public() {
        // Google DNS
        assert!(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888).is_public_ip());

        // Cloudflare DNS
        assert!(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111).is_public_ip());

        // Private addresses are not public
        assert!(!Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).is_public_ip());
        assert!(!Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1).is_public_ip());
        assert!(!Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).is_public_ip());

        // Documentation prefix is not public
        assert!(!Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1).is_public_ip());

        // Multicast is not public
        assert!(!Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 1).is_public_ip());
    }

    #[test]
    fn multiaddr_public_ipv4() {
        let public_addr = Multiaddr::from_str("/ip4/8.8.8.8/tcp/4001").unwrap();
        assert!(public_addr.is_public());

        let private_addr = Multiaddr::from_str("/ip4/192.168.1.1/tcp/4001").unwrap();
        assert!(!private_addr.is_public());

        let localhost_addr = Multiaddr::from_str("/ip4/127.0.0.1/tcp/4001").unwrap();
        assert!(!localhost_addr.is_public());
    }

    #[test]
    fn multiaddr_public_ipv6() {
        let public_addr = Multiaddr::from_str("/ip6/2001:4860:4860::8888/tcp/4001").unwrap();
        assert!(public_addr.is_public());

        let private_addr = Multiaddr::from_str("/ip6/fc00::1/tcp/4001").unwrap();
        assert!(!private_addr.is_public());

        let localhost_addr = Multiaddr::from_str("/ip6/::1/tcp/4001").unwrap();
        assert!(!localhost_addr.is_public());

        // Documentation prefix should not be public
        let doc_addr = Multiaddr::from_str("/ip6/2001:db8::1/tcp/4001").unwrap();
        assert!(!doc_addr.is_public());
    }

    #[test]
    fn multiaddr_private() {
        // IPv4 private
        let private_ipv4 = Multiaddr::from_str("/ip4/192.168.1.1/tcp/4001").unwrap();
        assert!(private_ipv4.is_private());

        // IPv6 private
        let private_ipv6 = Multiaddr::from_str("/ip6/fc00::1/tcp/4001").unwrap();
        assert!(private_ipv6.is_private());

        // Public addresses are not private
        let public_ipv4 = Multiaddr::from_str("/ip4/8.8.8.8/tcp/4001").unwrap();
        assert!(!public_ipv4.is_private());
    }

    #[test]
    fn multiaddr_dns_public() {
        let public_dns = Multiaddr::from_str("/dns/example.com/tcp/4001").unwrap();
        assert!(public_dns.is_public());

        let public_dns4 = Multiaddr::from_str("/dns4/example.com/tcp/4001").unwrap();
        assert!(public_dns4.is_public());
    }

    #[test]
    fn multiaddr_dns_private() {
        // .localhost
        let localhost = Multiaddr::from_str("/dns/localhost/tcp/4001").unwrap();
        assert!(!localhost.is_public());
        assert!(localhost.is_private());

        let sub_localhost = Multiaddr::from_str("/dns/app.localhost/tcp/4001").unwrap();
        assert!(!sub_localhost.is_public());
        assert!(sub_localhost.is_private());

        // .local (mDNS)
        let local = Multiaddr::from_str("/dns/myhost.local/tcp/4001").unwrap();
        assert!(!local.is_public());

        // .test
        let test = Multiaddr::from_str("/dns/example.test/tcp/4001").unwrap();
        assert!(!test.is_public());

        // .invalid
        let invalid = Multiaddr::from_str("/dns/example.invalid/tcp/4001").unwrap();
        assert!(!invalid.is_public());

        // .home.arpa
        let home_arpa = Multiaddr::from_str("/dns/myhost.home.arpa/tcp/4001").unwrap();
        assert!(!home_arpa.is_public());
    }

    #[test]
    fn is_subdomain_works() {
        assert!(is_subdomain("localhost", ".localhost"));
        assert!(is_subdomain("app.localhost", ".localhost"));
        assert!(is_subdomain("deep.app.localhost", ".localhost"));

        assert!(is_subdomain("example.local", ".local"));
        assert!(is_subdomain("local", ".local"));

        assert!(!is_subdomain("notlocal", ".local"));
        assert!(!is_subdomain("localexample.com", ".local"));
    }

    #[test]
    fn nat64_addresses() {
        // RFC 6052 WellKnown NAT64 prefix
        let nat64_wellknown = Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0x0808, 0x0808);
        assert!(nat64_wellknown.is_public_ip());

        // RFC 8215 Local use NAT64 prefix
        let nat64_local = Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 1);
        assert!(nat64_local.is_public_ip());
    }

    #[test]
    fn cgnat_private() {
        // 100.64.0.0/10 (CGNAT)
        assert!(Ipv4Addr::new(100, 64, 0, 1).is_private_ip());
        assert!(Ipv4Addr::new(100, 127, 255, 255).is_private_ip());
        assert!(!Ipv4Addr::new(100, 128, 0, 0).is_private_ip());
    }

    /// Test cases from the original Go implementation.
    /// See: https://github.com/multiformats/go-multiaddr/blob/master/net/private_test.go
    #[test]
    fn is_public_addr_go_compat() {
        struct TestCase {
            addr: &'static str,
            is_public: bool,
            is_private: bool,
        }

        let tests = [
            TestCase {
                addr: "/ip4/192.168.1.1/tcp/80",
                is_public: false,
                is_private: true,
            },
            TestCase {
                addr: "/ip4/1.1.1.1/tcp/80",
                is_public: true,
                is_private: false,
            },
            TestCase {
                // tcp before ip4 - should return false for both
                addr: "/tcp/80/ip4/1.1.1.1",
                is_public: false,
                is_private: false,
            },
            TestCase {
                addr: "/dns/node.libp2p.io/udp/1/quic-v1",
                is_public: true,
                is_private: false,
            },
            TestCase {
                addr: "/dnsaddr/node.libp2p.io/udp/1/quic-v1",
                is_public: true,
                is_private: false,
            },
            TestCase {
                // .local domains are not public
                addr: "/dns/node.libp2p.local/udp/1/quic-v1",
                is_public: false,
                // You can configure .local domains in local networks to return public addrs
                is_private: false,
            },
            TestCase {
                addr: "/dns/localhost/udp/1/quic-v1",
                is_public: false,
                is_private: true,
            },
            TestCase {
                addr: "/dns/a.localhost/tcp/1",
                is_public: false,
                is_private: true,
            },
            TestCase {
                addr: "/ip6/2400::1/tcp/10",
                is_public: true,
                is_private: false,
            },
            TestCase {
                // Documentation prefix (2001:db8::/32) is not public
                addr: "/ip6/2001:db8::42/tcp/10",
                is_public: false,
                is_private: false,
            },
            TestCase {
                // NAT64 WellKnown prefix (64:ff9b::/96) - embeds 1.1.1.1
                addr: "/ip6/64:ff9b::1.1.1.1/tcp/10",
                is_public: true,
                is_private: false,
            },
        ];

        for (i, test) in tests.iter().enumerate() {
            let addr = Multiaddr::from_str(test.addr).unwrap_or_else(|e| {
                panic!(
                    "test {}: failed to parse multiaddr '{}': {}",
                    i, test.addr, e
                )
            });

            let is_public = addr.is_public();
            let is_private = addr.is_private();

            assert_eq!(
                is_public, test.is_public,
                "test {}: IsPublicAddr check failed for {}: expected {}, got {}",
                i, test.addr, test.is_public, is_public
            );
            assert_eq!(
                is_private, test.is_private,
                "test {}: IsPrivateAddr check failed for {}: expected {}, got {}",
                i, test.addr, test.is_private, is_private
            );
        }
    }
}
