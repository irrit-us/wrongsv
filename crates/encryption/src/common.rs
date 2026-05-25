/// CommonConn wraps a byte stream with TLS-1.3-disguised AEAD encryption.
///
/// Every write is split into AES-GCM/ChaCha20-Poly1305 records, each prefixed
/// with a 5-byte TLS application data header (0x17 0x03 0x03 ...).
/// Every read expects the same format and decrypts the payload.
use crate::aead::AeadKey;
use crate::header;
use std::io::{Read, Write};

/// Max plaintext per record.
pub const MAX_PLAINTEXT: usize = 8192;

/// Wraps a raw stream with encrypting writes and decrypting reads.
pub struct CommonConn<S> {
    inner: S,
    write_aead: AeadKey,
    read_aead: AeadKey,
    read_buffer: Vec<u8>,
    read_pos: usize,
    ct_buf: Vec<u8>,
}

impl<S: Read + Write> CommonConn<S> {
    pub fn new(stream: S, write_aead: AeadKey, read_aead: AeadKey) -> Self {
        CommonConn {
            inner: stream,
            write_aead,
            read_aead,
            read_buffer: Vec::new(),
            read_pos: 0,
            ct_buf: Vec::with_capacity(16384),
        }
    }

    /// Get a reference to the inner stream.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Consume and return the inner stream.
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Write plaintext, splitting into TLS-disguised AEAD records.
    pub fn write_all(&mut self, mut data: &[u8]) -> std::io::Result<()> {
        while !data.is_empty() {
            let chunk_len = data.len().min(MAX_PLAINTEXT);
            let chunk = &data[..chunk_len];
            data = &data[chunk_len..];

            // AEAD tag is always 16 bytes, so ciphertext = plaintext + 16
            let payload_len = chunk.len() + 16;
            let mut hdr = [0u8; 5];
            header::encode_header(&mut hdr, payload_len);

            let ct = self
                .write_aead
                .seal(chunk, &hdr)
                .map_err(std::io::Error::other)?;

            self.inner.write_all(&hdr)?;
            self.inner.write_all(&ct)?;
        }
        Ok(())
    }

    /// Read plaintext, decrypting TLS-disguised AEAD records.
    pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Serve buffered data first
        if self.read_pos < self.read_buffer.len() {
            let available = self.read_buffer.len() - self.read_pos;
            let n = available.min(buf.len());
            buf[..n].copy_from_slice(&self.read_buffer[self.read_pos..self.read_pos + n]);
            self.read_pos += n;
            if self.read_pos >= self.read_buffer.len() {
                self.read_buffer.clear();
                self.read_pos = 0;
            }
            return Ok(n);
        }

        let mut hdr = [0u8; 5];
        self.inner.read_exact(&mut hdr)?;
        let payload_len = header::decode_header(&hdr)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        if self.ct_buf.len() < payload_len {
            self.ct_buf.resize(payload_len, 0);
        }
        self.inner.read_exact(&mut self.ct_buf[..payload_len])?;

        let plaintext = self
            .read_aead
            .open(&self.ct_buf[..payload_len], &hdr)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        let n = plaintext.len().min(buf.len());
        buf[..n].copy_from_slice(&plaintext[..n]);

        if plaintext.len() > n {
            self.read_buffer = plaintext[n..].to_vec();
            self.read_pos = 0;
        }

        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::AeadKey;
    use std::io::Cursor;

    #[test]
    fn test_common_conn_write_read_roundtrip() {
        let key = b"0123456789abcdef0123456789abcdef";

        // Write to a buffer via CommonConn
        let write_buf = Cursor::new(Vec::new());
        let mut writer = CommonConn::new(
            write_buf,
            AeadKey::new("test", key, true),
            AeadKey::new("test", key, true),
        );
        writer.write_all(b"hello world").unwrap();
        let encrypted = writer.into_inner().into_inner();

        assert!(!encrypted.is_empty());

        // Read back via CommonConn
        let mut reader = CommonConn::new(
            Cursor::new(encrypted),
            AeadKey::new("test", key, true),
            AeadKey::new("test", key, true),
        );
        let mut buf = [0u8; 32];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello world");
    }
}
