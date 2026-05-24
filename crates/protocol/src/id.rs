use crate::uuid::Uuid;
use md5::{Digest, Md5};

const CMD_KEY_SALT: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const ID_BYTES_LEN: usize = 16;

/// Protocol-level ID wrapping a UUID with derived command key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ID {
    uuid: Uuid,
    cmd_key: [u8; ID_BYTES_LEN],
}

impl ID {
    pub fn new(uuid: Uuid) -> Self {
        let mut hasher = Md5::new();
        hasher.update(uuid.as_bytes());
        hasher.update(CMD_KEY_SALT);
        let hash = hasher.finalize();
        let mut cmd_key = [0u8; 16];
        cmd_key.copy_from_slice(&hash[..16]);
        ID { uuid, cmd_key }
    }

    pub fn uuid(&self) -> Uuid {
        self.uuid
    }

    pub fn bytes(&self) -> &[u8; 16] {
        self.uuid.as_bytes()
    }

    pub fn cmd_key(&self) -> &[u8; 16] {
        &self.cmd_key
    }

    pub fn equals(&self, other: &ID) -> bool {
        self.uuid == other.uuid
    }
}

impl std::fmt::Display for ID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.uuid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_command_key_is_derived() {
        let uuid = Uuid::parse_string("12345678-1234-1234-1234-123456789abc").unwrap();
        let id = ID::new(uuid);
        // cmd_key must be 16 bytes and not all-zero
        assert_eq!(id.cmd_key().len(), 16);
        assert_ne!(id.cmd_key(), &[0u8; 16]);
    }

    #[test]
    fn test_id_display_delegates_to_uuid() {
        let uuid = Uuid::parse_string("12345678-1234-1234-1234-123456789abc").unwrap();
        let id = ID::new(uuid);
        assert_eq!(id.to_string(), uuid.to_string());
    }
}
