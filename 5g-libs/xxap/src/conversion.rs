use crate::{GtpTeid, TransportLayerAddress};
use anyhow::bail;
use async_net::IpAddr;
use bitvec::prelude::*;

impl From<IpAddr> for TransportLayerAddress {
    fn from(ip: IpAddr) -> Self {
        TransportLayerAddress(match ip {
            IpAddr::V4(x) => BitVec::<_, Msb0>::from_slice(&x.octets()),
            IpAddr::V6(x) => BitVec::<_, Msb0>::from_slice(&x.octets()),
        })
    }
}

impl TryFrom<&str> for TransportLayerAddress {
    type Error = anyhow::Error;
    fn try_from(addr: &str) -> Result<Self, anyhow::Error> {
        Ok(addr.parse::<IpAddr>()?.into())
    }
}

impl TryFrom<&String> for TransportLayerAddress {
    type Error = anyhow::Error;
    fn try_from(addr: &String) -> Result<Self, anyhow::Error> {
        addr.as_str().try_into()
    }
}

impl TryFrom<TransportLayerAddress> for IpAddr {
    type Error = anyhow::Error;
    fn try_from(addr: TransportLayerAddress) -> Result<Self, anyhow::Error> {
        let v = addr.0.into_vec();
        match v.len() {
            4 => {
                let arr: [u8; 4] = v.try_into().unwrap();
                Ok(IpAddr::V4(arr.into()))
            }
            16 => {
                let arr: [u8; 16] = v.try_into().unwrap();
                Ok(IpAddr::V6(arr.into()))
            }
            x => bail!("Bad length {}", x),
        }
    }
}

impl TryFrom<TransportLayerAddress> for String {
    type Error = anyhow::Error;
    fn try_from(addr: TransportLayerAddress) -> Result<Self, anyhow::Error> {
        let ip_addr: IpAddr = addr.try_into()?;
        Ok(ip_addr.to_string())
    }
}

impl std::fmt::Display for TransportLayerAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match String::try_from(self.clone()) {
            Ok(s) => write!(f, "{}", s),
            Err(_) => write!(f, "invalid"),
        }
    }
}

impl std::fmt::Display for GtpTeid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x?}", u32::from_be_bytes(self.0))
    }
}
