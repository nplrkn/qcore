use std::net::{IpAddr, Ipv4Addr};

use anyhow::{Result, bail};
use async_std::stream::StreamExt;
use rtnetlink::{
    Handle, RouteMessageBuilder, new_connection_with_socket,
    packet_route::{
        AddressFamily,
        address::{AddressAttribute, AddressMessage},
        link::{LinkAttribute, LinkMessage},
    },
    sys::SmolSocket,
};
use slog::{Logger, debug, warn};

#[derive(Clone)]
pub struct Netlink {
    netlink_handle: Handle,
    ue_if_index: u32,
}

impl Netlink {
    pub fn new(ue_if_index: u32) -> Result<Self> {
        let (connection, handle, _) = new_connection_with_socket::<SmolSocket>()?;
        async_std::task::spawn(connection);
        Ok(Self {
            netlink_handle: handle,
            ue_if_index,
        })
    }

    pub async fn get_link_addr_info(&self, if_index: u32) -> Result<(Ipv4Addr, [u8; 6])> {
        let Some(link_info) = self
            .netlink_handle
            .link()
            .get()
            .match_index(if_index)
            .execute()
            .next()
            .await
        else {
            bail!("Couldn't retrieve link info for if index {if_index}")
        };
        let mut mac = None;
        match link_info {
            Err(e) => bail!("Netlink error {e} getting link info for if index {if_index}"),
            Ok(LinkMessage { attributes, .. }) => {
                for attr in attributes.iter() {
                    if let LinkAttribute::Address(addr) = attr {
                        mac = Some(addr.clone());
                    }
                }
            }
        };
        let Some(mac) = mac else {
            bail!("Couldn't find MAC address on inteface index {}", if_index);
        };
        let Ok(mac) = mac.try_into() else {
            bail!("Interface hardware address isn't 6 bytes");
        };

        let mut address_stream = self
            .netlink_handle
            .address()
            .get()
            .set_link_index_filter(if_index)
            .execute();

        let mut ipv4 = None;
        while let Some(x) = address_stream.next().await {
            match x {
                Ok(AddressMessage {
                    header, attributes, ..
                }) => {
                    if header.family != AddressFamily::Inet {
                        continue;
                    }
                    for attr in attributes.iter() {
                        if let AddressAttribute::Address(IpAddr::V4(addr)) = attr {
                            ipv4 = Some(*addr);
                        }
                    }
                }
                Err(e) => bail!("Netlink error {e} getting addresses for if index {if_index}"),
            }
        }
        let Some(ipv4) = ipv4 else {
            bail!("Couldn't find IPv4 address on interface index {}", if_index);
        };

        Ok((ipv4, mac))
    }

    pub async fn add_host_route(&self, ipv4: Ipv4Addr, logger: &Logger) -> Result<()> {
        debug!(logger, "Program route for {ipv4} if {}", self.ue_if_index);
        match self
            .netlink_handle
            .route()
            .add(
                RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(ipv4, 32)
                    .output_interface(self.ue_if_index)
                    .build(),
            )
            .execute()
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => {
                // TODO - 'file exists' can probably always be ignored, but others maybe not
                warn!(logger, "Carry on after netlink error {e}");
                Ok(())
            }
        }
    }

    pub async fn delete_host_route(&self, ipv4: Ipv4Addr, logger: &Logger) {
        debug!(logger, "Deprogram route for {ipv4} if {}", self.ue_if_index);
        match self
            .netlink_handle
            .route()
            .del(
                RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(ipv4, 32)
                    .output_interface(self.ue_if_index)
                    .build(),
            )
            .execute()
            .await
        {
            Ok(_) => {}
            Err(e) => {
                // TODO - 'file exists' can probably always be ignored, but others maybe not
                warn!(logger, "Carry on after netlink error {e}");
            }
        }
    }
}
