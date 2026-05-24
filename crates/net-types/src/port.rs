use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Port(pub u16);

impl Port {
    pub const fn new(port: u16) -> Self {
        Port(port)
    }
}

impl From<u16> for Port {
    fn from(p: u16) -> Self {
        Port(p)
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
