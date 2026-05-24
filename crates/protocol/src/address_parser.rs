/// Reads and writes Address+Port from byte streams using the VLESS wire format.
///
/// Wire format: type_byte (1=IPv4, 2=Domain, 3=IPv6) + address_bytes + port (2 bytes BE).
/// VLESS uses a port-first variant.
use crate::net_types::{Address, Port};
use bytes::{BufMut, BytesMut};
use std::io::Read;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AddressParseError {
    #[error("invalid address type byte: {0}")]
    InvalidType(u8),
    #[error("domain too long: {0} bytes")]
    DomainTooLong(usize),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// VLESS uses port-then-address ordering (unlike SOCKS which does address-then-port).
pub struct AddressParser {
    port_first: bool,
}

impl Default for AddressParser {
    fn default() -> Self {
        AddressParser { port_first: true }
    }
}

impl AddressParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Read an address and port from a byte stream (port-first ordering).
    pub fn read_address_port<R: Read>(
        &self,
        reader: &mut R,
    ) -> Result<(Address, Port), AddressParseError> {
        let port = if self.port_first {
            let mut port_buf = [0u8; 2];
            reader.read_exact(&mut port_buf)?;
            Port::from(u16::from_be_bytes(port_buf))
        } else {
            Port(0) // caller must handle
        };

        let mut type_buf = [0u8; 1];
        reader.read_exact(&mut type_buf)?;
        let addr_type = type_buf[0];

        let address = match addr_type {
            1 => {
                // IPv4
                let mut ip = [0u8; 4];
                reader.read_exact(&mut ip)?;
                Address::IPv4(ip)
            }
            2 => {
                // Domain
                let mut len_buf = [0u8; 1];
                reader.read_exact(&mut len_buf)?;
                let domain_len = len_buf[0] as usize;
                if domain_len > 256 {
                    return Err(AddressParseError::DomainTooLong(domain_len));
                }
                let mut domain = [0u8; 256];
                reader.read_exact(&mut domain[..domain_len])?;
                let domain_str = std::str::from_utf8(&domain[..domain_len])
                    .map_err(|_| AddressParseError::InvalidType(2))?;
                Address::Domain(domain_str.to_string())
            }
            3 => {
                // IPv6
                let mut ip = [0u8; 16];
                reader.read_exact(&mut ip)?;
                Address::IPv6(ip)
            }
            _ => return Err(AddressParseError::InvalidType(addr_type)),
        };

        let port = if self.port_first {
            port
        } else {
            let mut port_buf = [0u8; 2];
            reader.read_exact(&mut port_buf)?;
            Port::from(u16::from_be_bytes(port_buf))
        };

        Ok((address, port))
    }

    /// Write an address and port into a buffer (port-first ordering).
    pub fn write_address_port(&self, buf: &mut BytesMut, addr: &Address, port: Port) {
        // Port first (VLESS convention)
        buf.put_u16(port.0);

        match addr {
            Address::IPv4(octets) => {
                buf.put_u8(1); // type
                buf.put_slice(octets);
            }
            Address::Domain(domain) => {
                buf.put_u8(2); // type
                buf.put_u8(domain.len() as u8);
                buf.put_slice(domain.as_bytes());
            }
            Address::IPv6(octets) => {
                buf.put_u8(3); // type
                buf.put_slice(octets);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_roundtrip_ipv4() {
        let parser = AddressParser::new();
        let addr = Address::IPv4([192, 168, 1, 100]);
        let port = Port(443);

        let mut buf = BytesMut::new();
        parser.write_address_port(&mut buf, &addr, port);

        let mut cursor = Cursor::new(&buf[..]);
        let (decoded_addr, decoded_port) = parser.read_address_port(&mut cursor).unwrap();

        assert_eq!(decoded_addr, addr);
        assert_eq!(decoded_port, port);
    }

    #[test]
    fn test_roundtrip_domain() {
        let parser = AddressParser::new();
        let addr = Address::Domain("example.com".into());
        let port = Port(8080);

        let mut buf = BytesMut::new();
        parser.write_address_port(&mut buf, &addr, port);

        let mut cursor = Cursor::new(&buf[..]);
        let (decoded_addr, decoded_port) = parser.read_address_port(&mut cursor).unwrap();

        assert_eq!(decoded_addr, addr);
        assert_eq!(decoded_port, port);
    }

    #[test]
    fn test_roundtrip_ipv6() {
        let parser = AddressParser::new();
        let addr = Address::IPv6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let port = Port(53);

        let mut buf = BytesMut::new();
        parser.write_address_port(&mut buf, &addr, port);

        let mut cursor = Cursor::new(&buf[..]);
        let (decoded_addr, decoded_port) = parser.read_address_port(&mut cursor).unwrap();

        assert_eq!(decoded_addr, addr);
        assert_eq!(decoded_port, port);
    }
}
