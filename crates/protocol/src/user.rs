use crate::types::MemoryAccount;

/// Parsed form of a protocol user — holds the account and metadata.
#[derive(Debug, Clone)]
pub struct MemoryUser {
    pub account: MemoryAccount,
    pub email: String,
    pub level: u32,
}
