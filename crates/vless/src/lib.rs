pub mod account;
pub mod validator;
pub mod vision;

pub use account::MemoryAccount;
pub use validator::{MemoryValidator, Validator};
pub use vision::{
    TrafficState, VisionReader, VisionWriter, is_complete_record, xtls_filter_tls, xtls_padding,
    xtls_unpadding,
};

pub const XRV: &str = wrongsv_protocol::VLESS_XRV;
pub const NONE: &str = wrongsv_protocol::VLESS_NONE;
