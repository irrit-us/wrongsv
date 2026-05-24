pub mod addons;
pub mod body;
pub mod encoding;

pub use addons::Addons;
pub use body::{LengthPacketReader, LengthPacketWriter, MultiLengthPacketWriter};
pub use encoding::{
    decode_request_header, decode_response_header, encode_request_header, encode_response_header,
    DecodedRequest,
};

pub const VERSION: u8 = 0;
