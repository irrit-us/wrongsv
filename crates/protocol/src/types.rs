/// VLESS request/response types matching xray-core common/protocol.
use crate::net_types::{Address, Port};
use crate::user::MemoryUser;

/// Request command byte values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RequestCommand {
    Tcp = 0x01,
    Udp = 0x02,
    Mux = 0x03,
    Rvs = 0x04,
}

impl RequestCommand {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(RequestCommand::Tcp),
            0x02 => Some(RequestCommand::Udp),
            0x03 => Some(RequestCommand::Mux),
            0x04 => Some(RequestCommand::Rvs),
            _ => None,
        }
    }
}

/// Request option bitmask flags.
pub mod request_option {
    pub const CHUNK_STREAM: u8 = 0x01;
    pub const CHUNK_MASKING: u8 = 0x04;
    pub const GLOBAL_PADDING: u8 = 0x08;
    pub const AUTHENTICATED_LENGTH: u8 = 0x10;
}

/// Security types used in VLESS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SecurityType {
    Unknown = 0,
    Legacy = 1,
    Auto = 2,
    Aes128Gcm = 3,
    ChaCha20Poly1305 = 4,
    None = 5,
    Zero = 6,
}

impl SecurityType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(SecurityType::Unknown),
            1 => Some(SecurityType::Legacy),
            2 => Some(SecurityType::Auto),
            3 => Some(SecurityType::Aes128Gcm),
            4 => Some(SecurityType::ChaCha20Poly1305),
            5 => Some(SecurityType::None),
            6 => Some(SecurityType::Zero),
            _ => None,
        }
    }
}

/// VLESS request header, decoded from the wire.
#[derive(Debug, Clone)]
pub struct RequestHeader {
    pub version: u8,
    pub command: RequestCommand,
    pub address: Address,
    pub port: Port,
    pub user: MemoryUser,
}

/// VLESS response header, minimal (version byte only in practice).
#[derive(Debug, Clone)]
pub struct ResponseHeader {
    pub version: u8,
}

/// Address type bytes on the wire.
#[repr(u8)]
pub enum AddressType {
    IPv4 = 1,
    Domain = 2,
    IPv6 = 3,
}

/// VLESS-specific account stored in-memory after parsing.
#[derive(Debug, Clone)]
pub struct MemoryAccount {
    pub id: crate::id::ID,
    pub flow: String,
    pub encryption: String,
    pub udp: bool,
    pub xor_mode: u32,
    pub seconds: u32,
    pub padding: String,
    pub testpre: u32,
    pub testseed: Vec<u32>,
}

pub const VLESS_XRV: &str = "xtls-rprx-vision";
pub const VLESS_NONE: &str = "none";
