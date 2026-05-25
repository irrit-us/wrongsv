use std::collections::HashMap;
use std::sync::RwLock;
use thiserror::Error;
use wrongsv_protocol::MemoryUser;
use wrongsv_uuid::process_uuid;

#[derive(Debug, Error)]
pub enum ValidatorError {
    #[error("user {0} already exists")]
    DuplicateEmail(String),
    #[error("user {0} not found")]
    NotFound(String),
}

/// Thread-safe in-memory VLESS user registry.
pub trait Validator: Send + Sync {
    fn get(&self, id: &[u8; 16]) -> Option<MemoryUser>;
    fn add(&self, user: MemoryUser) -> Result<(), ValidatorError>;
    fn del(&self, email: &str) -> Result<(), ValidatorError>;
    fn get_by_email(&self, email: &str) -> Option<MemoryUser>;
    fn get_all(&self) -> Vec<MemoryUser>;
    fn get_count(&self) -> usize;
}

pub struct MemoryValidator {
    // Keyed by ProcessUUID(id)
    users: RwLock<HashMap<[u8; 16], MemoryUser>>,
    // Keyed by lowercase email
    emails: RwLock<HashMap<String, MemoryUser>>,
}

impl Default for MemoryValidator {
    fn default() -> Self {
        MemoryValidator {
            users: RwLock::new(HashMap::new()),
            emails: RwLock::new(HashMap::new()),
        }
    }
}

impl MemoryValidator {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Validator for MemoryValidator {
    fn get(&self, id: &[u8; 16]) -> Option<MemoryUser> {
        let key = process_uuid(id);
        self.users.read().unwrap_or_else(|e| e.into_inner()).get(&key).cloned()
    }

    fn add(&self, user: MemoryUser) -> Result<(), ValidatorError> {
        if !user.email.is_empty() {
            let mut emails = self.emails.write().unwrap_or_else(|e| e.into_inner());
            let key = user.email.to_lowercase();
            if emails.contains_key(&key) {
                return Err(ValidatorError::DuplicateEmail(user.email));
            }
            emails.insert(key, user.clone());
        }
        let uid_key = process_uuid(user.account.id.uuid().as_bytes());
        self.users.write().unwrap_or_else(|e| e.into_inner()).insert(uid_key, user);
        Ok(())
    }

    fn del(&self, email: &str) -> Result<(), ValidatorError> {
        let key = email.to_lowercase();
        let user = {
            let emails = self.emails.read().unwrap_or_else(|e| e.into_inner());
            emails.get(&key).cloned()
        };
        match user {
            Some(u) => {
                self.emails.write().unwrap_or_else(|e| e.into_inner()).remove(&key);
                let uid_key = process_uuid(u.account.id.uuid().as_bytes());
                self.users.write().unwrap_or_else(|e| e.into_inner()).remove(&uid_key);
                Ok(())
            }
            None => Err(ValidatorError::NotFound(format!(
                "user {} not found",
                email
            ))),
        }
    }

    fn get_by_email(&self, email: &str) -> Option<MemoryUser> {
        let key = email.to_lowercase();
        self.emails.read().unwrap_or_else(|e| e.into_inner()).get(&key).cloned()
    }

    fn get_all(&self) -> Vec<MemoryUser> {
        self.emails
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect()
    }

    fn get_count(&self) -> usize {
        self.emails.read().unwrap_or_else(|e| e.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wrongsv_protocol::{MemoryAccount, ID};
    use wrongsv_uuid::Uuid;

    fn make_user(id_str: &str, email: &str) -> MemoryUser {
        let uuid = Uuid::parse_string(id_str).unwrap();
        MemoryUser {
            account: MemoryAccount {
                id: ID::new(uuid),
                flow: String::new(),
                encryption: String::new(),
                xor_mode: 0,
                seconds: 0,
                padding: String::new(),
                testpre: 0,
                testseed: vec![],
            },
            email: email.to_string(),
            level: 0,
        }
    }

    #[test]
    fn test_add_and_get() {
        let v = MemoryValidator::new();
        let user = make_user("12345678-1234-1234-1234-123456789abc", "test@example.com");
        let id = *user.account.id.bytes();
        v.add(user).unwrap();
        let found = v.get(&id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().email, "test@example.com");
    }

    #[test]
    fn test_get_by_email() {
        let v = MemoryValidator::new();
        let user = make_user("12345678-1234-1234-1234-123456789abc", "Test@Example.com");
        v.add(user).unwrap();
        assert!(v.get_by_email("test@example.com").is_some());
        assert!(v.get_by_email("Test@Example.com").is_some());
    }

    #[test]
    fn test_delete() {
        let v = MemoryValidator::new();
        let user = make_user("12345678-1234-1234-1234-123456789abc", "test@example.com");
        let id = *user.account.id.bytes();
        v.add(user).unwrap();
        v.del("test@example.com").unwrap();
        assert!(v.get(&id).is_none());
        assert!(v.get_by_email("test@example.com").is_none());
    }

    #[test]
    fn test_duplicate_email() {
        let v = MemoryValidator::new();
        let u1 = make_user("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "test@example.com");
        let u2 = make_user("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "test@example.com");
        v.add(u1).unwrap();
        assert!(v.add(u2).is_err());
    }

    #[test]
    fn test_delete_nonexistent_returns_not_found() {
        let v = MemoryValidator::new();
        let err = v.del("nobody@example.com").unwrap_err();
        assert!(matches!(err, ValidatorError::NotFound(_)));
    }

    #[test]
    fn test_count() {
        let v = MemoryValidator::new();
        assert_eq!(v.get_count(), 0);
        v.add(make_user("11111111-1111-1111-1111-111111111111", "a@b.com"))
            .unwrap();
        assert_eq!(v.get_count(), 1);
        v.add(make_user("22222222-2222-2222-2222-222222222222", "c@d.com"))
            .unwrap();
        assert_eq!(v.get_count(), 2);
    }
}
