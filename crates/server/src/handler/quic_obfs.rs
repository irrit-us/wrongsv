use std::fmt;
use std::io;
use std::io::IoSliceMut;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use blake2::digest::{Update, VariableOutput};
use quinn::{AsyncUdpSocket, UdpPoller, udp::{RecvMeta, Transmit}};
use rand::RngCore;

const SALAMANDER_SALT_LEN: usize = 8;
const SALAMANDER_KEY_LEN: usize = 32;
const SALAMANDER_MIN_PASSWORD_LEN: usize = 4;
const QUIC_OBFS_BUFFER_SIZE: usize = 2048;

#[derive(Clone, Debug)]
pub(crate) struct SalamanderConfig {
    pub password: Vec<u8>,
}

pub(crate) fn wrap_async_udp_socket_salamander(
    inner: Arc<dyn AsyncUdpSocket>,
    password: &[u8],
) -> Result<Arc<dyn AsyncUdpSocket>, String> {
    if password.len() < SALAMANDER_MIN_PASSWORD_LEN {
        return Err(format!(
            "salamander password must be at least {SALAMANDER_MIN_PASSWORD_LEN} bytes"
        ));
    }
    Ok(Arc::new(SalamanderAsyncUdpSocket {
        inner,
        password: password.to_vec(),
        recv_buf: Mutex::new(vec![0u8; QUIC_OBFS_BUFFER_SIZE]),
        send_buf: Mutex::new(vec![0u8; QUIC_OBFS_BUFFER_SIZE]),
    }))
}

struct SalamanderAsyncUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    password: Vec<u8>,
    recv_buf: Mutex<Vec<u8>>,
    send_buf: Mutex<Vec<u8>>,
}

impl fmt::Debug for SalamanderAsyncUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SalamanderAsyncUdpSocket")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for SalamanderAsyncUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let mut send_buf = self.send_buf.lock().expect("salamander send mutex poisoned");
        if send_buf.len() < transmit.contents.len() + SALAMANDER_SALT_LEN {
            send_buf.resize(transmit.contents.len() + SALAMANDER_SALT_LEN, 0);
        }
        let encoded_len = salamander_obfuscate(&self.password, transmit.contents, &mut send_buf);
        let wrapped = Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &send_buf[..encoded_len],
            segment_size: None,
            src_ip: transmit.src_ip,
        };
        self.inner.try_send(&wrapped)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }

        loop {
            let mut recv_buf = self.recv_buf.lock().expect("salamander recv mutex poisoned");
            let mut recv_meta = [RecvMeta::default()];
            let mut recv_slices = [IoSliceMut::new(recv_buf.as_mut_slice())];
            match self.inner.poll_recv(cx, &mut recv_slices, &mut recv_meta) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(0)) => return Poll::Ready(Ok(0)),
                Poll::Ready(Ok(_count)) => {
                    let raw_len = recv_meta[0].len;
                    let packet = &recv_buf[..raw_len];
                    let out: &mut [u8] = &mut bufs[0];
                    let Some(decoded_len) =
                        salamander_deobfuscate(&self.password, packet, out)
                    else {
                        continue;
                    };
                    meta[0] = recv_meta[0];
                    meta[0].len = decoded_len;
                    meta[0].stride = decoded_len;
                    return Poll::Ready(Ok(1));
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

fn salamander_obfuscate(password: &[u8], input: &[u8], out: &mut [u8]) -> usize {
    let salt = &mut out[..SALAMANDER_SALT_LEN];
    rand::thread_rng().fill_bytes(salt);
    let key = salamander_key(password, salt);
    for (idx, byte) in input.iter().enumerate() {
        out[SALAMANDER_SALT_LEN + idx] = byte ^ key[idx % SALAMANDER_KEY_LEN];
    }
    SALAMANDER_SALT_LEN + input.len()
}

fn salamander_deobfuscate(password: &[u8], input: &[u8], out: &mut [u8]) -> Option<usize> {
    if input.len() <= SALAMANDER_SALT_LEN {
        return None;
    }
    let payload_len = input.len() - SALAMANDER_SALT_LEN;
    if out.len() < payload_len {
        return None;
    }
    let salt = &input[..SALAMANDER_SALT_LEN];
    let key = salamander_key(password, salt);
    for (idx, byte) in input[SALAMANDER_SALT_LEN..].iter().enumerate() {
        out[idx] = byte ^ key[idx % SALAMANDER_KEY_LEN];
    }
    Some(payload_len)
}

fn salamander_key(password: &[u8], salt: &[u8]) -> [u8; SALAMANDER_KEY_LEN] {
    let mut hasher = blake2::Blake2bVar::new(SALAMANDER_KEY_LEN)
        .expect("salamander key length should be valid");
    hasher.update(password);
    hasher.update(salt);
    let mut key = [0u8; SALAMANDER_KEY_LEN];
    hasher
        .finalize_variable(&mut key)
        .expect("salamander key output buffer should be valid");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salamander_roundtrip() {
        let password = b"secret-psk";
        let mut obfuscated = vec![0u8; QUIC_OBFS_BUFFER_SIZE];
        let encoded_len = salamander_obfuscate(password, b"hello", &mut obfuscated);
        let mut decoded = [0u8; 16];
        let decoded_len =
            salamander_deobfuscate(password, &obfuscated[..encoded_len], &mut decoded).unwrap();
        assert_eq!(&decoded[..decoded_len], b"hello");
    }
}
