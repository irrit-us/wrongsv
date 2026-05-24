use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    IPv4,
    IPv6,
    Domain,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    IPv4([u8; 4]),
    IPv6([u8; 16]),
    Domain(String),
}

impl Address {
    pub fn family(&self) -> AddressFamily {
        match self {
            Address::IPv4(_) => AddressFamily::IPv4,
            Address::IPv6(_) => AddressFamily::IPv6,
            Address::Domain(_) => AddressFamily::Domain,
        }
    }

    pub fn parse(s: &str) -> Self {
        let s = s.trim();
        // Strip brackets from IPv6 addresses like "[::1]"
        let s = if s.starts_with('[') && s.ends_with(']') {
            &s[1..s.len() - 1]
        } else {
            s
        };
        if let Ok(ip) = s.parse::<Ipv4Addr>() {
            return Address::IPv4(ip.octets());
        }
        if let Ok(ip) = s.parse::<Ipv6Addr>() {
            return Address::IPv6(ip.octets());
        }
        Address::Domain(s.to_string())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::IPv4(octets) => {
                let ip = Ipv4Addr::from(*octets);
                write!(f, "{}", ip)
            }
            Address::IPv6(octets) => {
                let ip = Ipv6Addr::from(*octets);
                write!(f, "[{}]", ip)
            }
            Address::Domain(d) => write!(f, "{}", d),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4() {
        let addr = Address::parse("192.168.1.1");
        assert_eq!(addr, Address::IPv4([192, 168, 1, 1]));
        assert_eq!(addr.family(), AddressFamily::IPv4);
    }

    #[test]
    fn test_parse_ipv6() {
        let addr = Address::parse("::1");
        assert_eq!(addr.family(), AddressFamily::IPv6);
        assert_eq!(addr.to_string(), "[::1]");
    }

    #[test]
    fn test_parse_ipv6_bracketed() {
        let addr = Address::parse("[2001:db8::1]");
        assert!(matches!(addr, Address::IPv6(_)));
    }

    #[test]
    fn test_parse_domain() {
        let addr = Address::parse("example.com");
        assert_eq!(addr, Address::Domain("example.com".to_string()));
        assert_eq!(addr.family(), AddressFamily::Domain);
    }

    #[test]
    fn test_display_ipv4() {
        let addr = Address::IPv4([10, 0, 0, 1]);
        assert_eq!(addr.to_string(), "10.0.0.1");
    }

    #[test]
    fn test_display_domain() {
        let addr = Address::Domain("example.com".into());
        assert_eq!(addr.to_string(), "example.com");
    }
}
