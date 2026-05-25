use crate::addons::{Addons, decode_header_addons, encode_header_addons};
use bytes::{BufMut, BytesMut};
use thiserror::Error;
use wrongsv_net_types::{Address, Port};
use wrongsv_protocol::{AddressParser, MemoryUser, RequestCommand, RequestHeader};

#[derive(Debug, Error)]
pub enum EncodeError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("addons error: {0}")]
    Addons(#[from] crate::addons::AddonsError),
}

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("addons error: {0}")]
    Addons(#[from] crate::addons::AddonsError),
    #[error("invalid request version: {0}")]
    InvalidVersion(u8),
    #[error("user not found for id: {0}")]
    UserNotFound(String),
    #[error("invalid request command: {0}")]
    InvalidCommand(u8),
    #[error("invalid request address")]
    InvalidAddress,
    #[error("address parse error: {0}")]
    AddressParse(#[from] wrongsv_protocol::AddressParseError),
}

/// Result of decoding a request header.
pub struct DecodedRequest {
    pub user_sent_id: [u8; 16],
    pub header: RequestHeader,
    pub addons: Addons,
}

/// Encode a VLESS request header into a buffer.
///
/// Wire layout: version(1) | user_id(16) | addons(var) | command(1) | [address+port]
pub fn encode_request_header(
    buf: &mut BytesMut,
    request: &RequestHeader,
    addons: &Addons,
) -> Result<(), EncodeError> {
    buf.put_u8(request.version);
    buf.put_slice(request.user.account.id.bytes());
    encode_header_addons(buf, addons)?;
    buf.put_u8(request.command as u8);

    let addr_parser = AddressParser::new();
    if request.command != RequestCommand::Mux && request.command != RequestCommand::Rvs {
        addr_parser.write_address_port(buf, &request.address, request.port);
    }

    Ok(())
}

/// Decode a VLESS request header from a reader.
///
/// `lookup_user` is called with the raw 16-byte user ID from the wire
/// and must return the MemoryUser if valid, or None.
pub fn decode_request_header<R: std::io::Read>(
    reader: &mut R,
    lookup_user: impl FnOnce(&[u8; 16]) -> Option<MemoryUser>,
) -> Result<DecodedRequest, DecodeError> {
    let mut version_buf = [0u8; 1];
    reader.read_exact(&mut version_buf)?;
    let version = version_buf[0];

    if version != 0 {
        return Err(DecodeError::InvalidVersion(version));
    }

    let mut id_bytes = [0u8; 16];
    reader.read_exact(&mut id_bytes)?;

    let user = lookup_user(&id_bytes).ok_or_else(|| {
        let hex_id: String = id_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        DecodeError::UserNotFound(hex_id)
    })?;

    let addons = decode_header_addons(reader)?;

    let mut cmd_buf = [0u8; 1];
    reader.read_exact(&mut cmd_buf)?;
    let command =
        RequestCommand::from_byte(cmd_buf[0]).ok_or(DecodeError::InvalidCommand(cmd_buf[0]))?;

    let addr_parser = AddressParser::new();
    let (address, port) = match command {
        RequestCommand::Mux => (Address::Domain("v1.mux.cool".to_string()), Port(0)),
        RequestCommand::Rvs => (Address::Domain("v1.rvs.cool".to_string()), Port(0)),
        RequestCommand::Tcp | RequestCommand::Udp => addr_parser.read_address_port(reader)?,
    };

    Ok(DecodedRequest {
        user_sent_id: id_bytes,
        header: RequestHeader {
            version,
            command,
            address,
            port,
            user,
        },
        addons,
    })
}

/// Encode a VLESS response header into a buffer.
///
/// Wire layout: version(1) | addons(var)
pub fn encode_response_header(
    buf: &mut BytesMut,
    request: &RequestHeader,
    addons: &Addons,
) -> Result<(), EncodeError> {
    buf.put_u8(request.version);
    encode_header_addons(buf, addons)?;
    Ok(())
}

/// Decode a VLESS response header from a reader.
pub fn decode_response_header<R: std::io::Read>(
    reader: &mut R,
    request: &RequestHeader,
) -> Result<Addons, DecodeError> {
    let mut version_buf = [0u8; 1];
    reader.read_exact(&mut version_buf)?;
    if version_buf[0] != request.version {
        return Err(DecodeError::InvalidVersion(version_buf[0]));
    }
    Ok(decode_header_addons(reader)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use wrongsv_protocol::{ID, MemoryAccount, MemoryUser};
    use wrongsv_uuid::Uuid;

    fn make_test_user() -> MemoryUser {
        let uuid = Uuid::parse_string("12345678-1234-1234-1234-123456789abc").unwrap();
        MemoryUser {
            account: MemoryAccount {
                id: ID::new(uuid),
                flow: String::new(),
                encryption: String::new(),
                udp: true,
                xor_mode: 0,
                seconds: 0,
                padding: String::new(),
                testpre: 0,
                testseed: vec![],
            },
            email: String::new(),
            level: 0,
        }
    }

    fn empty_addons() -> Addons {
        Addons {
            flow: String::new(),
            ..Default::default()
        }
    }

    #[test]
    fn test_request_header_roundtrip_tcp() {
        let user = make_test_user();
        let user_id = user.account.id.clone();
        let request = RequestHeader {
            version: 0,
            command: RequestCommand::Tcp,
            address: Address::Domain("example.com".into()),
            port: Port(443),
            user,
        };
        let addons = empty_addons();

        let mut buf = BytesMut::new();
        encode_request_header(&mut buf, &request, &addons).unwrap();

        let mut cursor = Cursor::new(&buf[..]);
        let decoded = decode_request_header(&mut cursor, |id| {
            if id == user_id.bytes() {
                Some(make_test_user())
            } else {
                None
            }
        })
        .unwrap();

        assert_eq!(decoded.header.version, 0);
        assert_eq!(decoded.header.command, RequestCommand::Tcp);
        assert_eq!(
            decoded.header.address,
            Address::Domain("example.com".into())
        );
        assert_eq!(decoded.header.port, Port(443));
        assert_eq!(decoded.addons.flow, "");
    }

    #[test]
    fn test_request_header_mux() {
        let user = make_test_user();
        let user_id = user.account.id.clone();
        let request = RequestHeader {
            version: 0,
            command: RequestCommand::Mux,
            address: Address::Domain("v1.mux.cool".into()),
            port: Port(0),
            user,
        };
        let addons = empty_addons();

        let mut buf = BytesMut::new();
        encode_request_header(&mut buf, &request, &addons).unwrap();

        let mut cursor = Cursor::new(&buf[..]);
        let decoded = decode_request_header(&mut cursor, |id| {
            if id == user_id.bytes() {
                Some(make_test_user())
            } else {
                None
            }
        })
        .unwrap();

        assert_eq!(decoded.header.command, RequestCommand::Mux);
        assert_eq!(
            decoded.header.address,
            Address::Domain("v1.mux.cool".into())
        );
    }

    #[test]
    fn test_response_header_roundtrip() {
        let user = make_test_user();
        let request = RequestHeader {
            version: 0,
            command: RequestCommand::Tcp,
            address: Address::Domain("example.com".into()),
            port: Port(443),
            user,
        };
        let addons = empty_addons();

        let mut buf = BytesMut::new();
        encode_response_header(&mut buf, &request, &addons).unwrap();

        let mut cursor = Cursor::new(&buf[..]);
        let decoded = decode_response_header(&mut cursor, &request).unwrap();
        assert_eq!(decoded.flow, "");
    }

    #[test]
    fn test_decode_invalid_user_errors() {
        let user = make_test_user();
        let request = RequestHeader {
            version: 0,
            command: RequestCommand::Tcp,
            address: Address::Domain("example.com".into()),
            port: Port(443),
            user,
        };
        let addons = empty_addons();

        let mut buf = BytesMut::new();
        encode_request_header(&mut buf, &request, &addons).unwrap();

        let mut cursor = Cursor::new(&buf[..]);
        let result = decode_request_header(&mut cursor, |_| None);
        assert!(result.is_err());
    }
}
