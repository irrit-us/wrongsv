use crate::address::Address;
use crate::network::Network;
use crate::port::Port;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub address: Address,
    pub port: Port,
    pub network: Network,
}

impl Destination {
    pub fn new(address: Address, port: Port, network: Network) -> Self {
        Destination {
            address,
            port,
            network,
        }
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.address, self.port)
    }
}
