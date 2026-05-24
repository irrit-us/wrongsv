#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
    Unix,
}

impl Network {
    pub fn as_str(&self) -> &'static str {
        match self {
            Network::Tcp => "tcp",
            Network::Udp => "udp",
            Network::Unix => "unix",
        }
    }
}
