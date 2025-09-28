use std::net::Ipv4Addr;

use anyhow::Result;
use rtnetlink::{Handle, RouteMessageBuilder, new_connection_with_socket, sys::SmolSocket};
use slog::{Logger, warn};

#[derive(Clone)]
pub struct NetlinkRouteProgrammer {
    netlink_handle: Handle,
    if_index: u32,
}

impl NetlinkRouteProgrammer {
    pub fn new(if_index: u32) -> Result<Self> {
        let (connection, handle, _) = new_connection_with_socket::<SmolSocket>()?;
        async_std::task::spawn(connection);
        Ok(Self {
            netlink_handle: handle,
            if_index,
        })
    }

    pub async fn add_host_route(&self, ipv4: Ipv4Addr, logger: &Logger) -> Result<()> {
        println!("Program route for {ipv4} if {}", self.if_index);
        match self
            .netlink_handle
            .route()
            .add(
                RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(ipv4, 32)
                    .output_interface(self.if_index)
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
        match self
            .netlink_handle
            .route()
            .del(
                RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(ipv4, 32)
                    .output_interface(self.if_index)
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
