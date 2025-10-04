use super::{dhcp::DhcpClient, netlink::Netlink};
use crate::data::UeIpAllocationConfig;
use anyhow::Result;
use slog::{Logger, info, warn};
use std::{net::Ipv4Addr, sync::Arc};

#[derive(Clone)]
pub struct UeIpAllocator {
    netlink_route_programmer: Netlink,
    mode: UeIpAllocationMode,
}

#[derive(Clone)]
enum UeIpAllocationMode {
    // Allocate addresses from a /24 IPv4 prefix.
    RoutedUeSubnet(Ipv4Addr),

    // Obtain addresses using DHCP over the given interface name
    Dhcp(Arc<DhcpClient>),
}

impl UeIpAllocator {
    pub async fn new(
        ue_network_if_index: u32,
        config: UeIpAllocationConfig,
        logger: &Logger,
    ) -> Result<Self> {
        let netlink = Netlink::new(ue_network_if_index)?;

        let mode = match config {
            UeIpAllocationConfig::RoutedUeSubnet(subnet) => {
                info!(
                    logger,
                    "UE address allocation model: /24 addresses on {}", subnet
                );

                UeIpAllocationMode::RoutedUeSubnet(subnet)
            }
            UeIpAllocationConfig::Dhcp(if_index, server) => {
                info!(
                    logger,
                    "UE address allocation model: DHCP on LAN connected over if index {}", if_index
                );
                let (ip, mac) = netlink.get_link_addr_info(if_index).await?;
                let dhcp_client = DhcpClient::new(mac, ip, server, logger).await?;
                UeIpAllocationMode::Dhcp(Arc::new(dhcp_client))
            }
        };
        Ok(Self {
            netlink_route_programmer: netlink,
            mode,
        })
    }

    pub async fn allocate(
        &self,
        idx: u8,
        dhcp_client_identifier: Vec<u8>,
        logger: &Logger,
    ) -> Result<Ipv4Addr> {
        let addr = match &self.mode {
            UeIpAllocationMode::RoutedUeSubnet(ue_subnet) => {
                // Calculate an address ourselves
                let mut ue_addr_octets = ue_subnet.octets();
                ue_addr_octets[3] = idx;
                Ipv4Addr::from(ue_addr_octets)
            }
            UeIpAllocationMode::Dhcp(dhcp_client) => {
                // Ask the DHCP server for an address
                dhcp_client
                    .obtain_lease(dhcp_client_identifier, logger)
                    .await?
            }
        };

        // Program a host route for it (which enables Linux proxy ARP + UE packet reception by eBPF).
        self.netlink_route_programmer
            .add_host_route(addr, logger)
            .await?;

        Ok(addr)
    }

    pub async fn dhcp_self_test(&self, logger: &Logger) -> Result<()> {
        if let UeIpAllocationMode::Dhcp(dhcp_client) = &self.mode {
            dhcp_client.self_test(logger).await?
        }
        Ok(())
    }

    pub async fn release(&self, addr: Ipv4Addr, logger: &Logger) {
        match &self.mode {
            UeIpAllocationMode::RoutedUeSubnet(_ue_subnet) => {}
            UeIpAllocationMode::Dhcp(dhcp_client) => {
                if let Err(e) = dhcp_client.cancel_lease(&addr).await {
                    warn!(logger, "DHCP cancel lease failed - {e}")
                }
            }
        };

        self.netlink_route_programmer
            .delete_host_route(addr, logger)
            .await;
    }
}
