/// SOCKS5 address parsing for sing-anytls stream destinations.
///
/// Wire format: [type(1B)][addr(var)][port(2B BE)]
///   type 1 = IPv4 (4 bytes)
///   type 3 = Domain (1B len + N bytes)
///   type 4 = IPv6 (16 bytes)
use wrongsv_net_types::{Address, Port};

/// Parsed SOCKS5 address plus how many bytes were consumed.
pub fn parse_socks_addr(data: &[u8]) -> Option<(Address, Port, usize)> {
    if data.is_empty() {
        return None;
    }
    match data[0] {
        0x01 => {
            // IPv4: type(1) + addr(4) + port(2) = 7 bytes
            if data.len() < 7 {
                return None;
            }
            let addr = Address::IPv4([data[1], data[2], data[3], data[4]]);
            let port = Port(u16::from_be_bytes([data[5], data[6]]));
            Some((addr, port, 7))
        }
        0x03 => {
            // Domain: type(1) + len(1) + addr(N) + port(2)
            if data.len() < 4 {
                return None;
            }
            let domain_len = data[1] as usize;
            let total = 1 + 1 + domain_len + 2;
            if data.len() < total {
                return None;
            }
            let domain = String::from_utf8_lossy(&data[2..2 + domain_len]).into_owned();
            let port_off = 2 + domain_len;
            let port = Port(u16::from_be_bytes([data[port_off], data[port_off + 1]]));
            Some((Address::Domain(domain), port, total))
        }
        0x04 => {
            // IPv6: type(1) + addr(16) + port(2) = 19 bytes
            if data.len() < 19 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let addr = Address::IPv6(octets);
            let port = Port(u16::from_be_bytes([data[17], data[18]]));
            Some((addr, port, 19))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4() {
        let buf = [1, 192, 0, 2, 1, 0, 80]; // 192.0.2.1:80
        let (addr, port, n) = parse_socks_addr(&buf).unwrap();
        assert_eq!(addr, Address::IPv4([192, 0, 2, 1]));
        assert_eq!(port, Port(80));
        assert_eq!(n, 7);
    }

    #[test]
    fn parse_domain() {
        let domain = b"httpbin.org";
        let mut buf = vec![3, domain.len() as u8];
        buf.extend_from_slice(domain);
        buf.extend_from_slice(&[1, 187]); // port 443
        let (addr, port, n) = parse_socks_addr(&buf).unwrap();
        assert_eq!(addr, Address::Domain("httpbin.org".into()));
        assert_eq!(port, Port(443));
        assert_eq!(n, 1 + 1 + domain.len() + 2);
    }

    #[test]
    fn parse_ipv6() {
        let mut buf = vec![4u8];
        buf.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        buf.extend_from_slice(&[0x01, 0xbb]); // port 443
        let (addr, port, n) = parse_socks_addr(&buf).unwrap();
        assert_eq!(port, Port(443));
        assert_eq!(n, 19);
        if let Address::IPv6(octets) = addr {
            assert_eq!(octets[0], 0x20);
            assert_eq!(octets[1], 0x01);
        } else {
            panic!("expected IPv6");
        }
    }

    #[test]
    fn incomplete_rejected() {
        assert!(parse_socks_addr(&[]).is_none());
        assert!(parse_socks_addr(&[1, 192, 0]).is_none()); // truncated IPv4
        assert!(parse_socks_addr(&[3, 20, b'a']).is_none()); // truncated domain
        assert!(parse_socks_addr(&[4]).is_none()); // truncated IPv6
    }
}
