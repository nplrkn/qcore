use crate::{data::UeIpAllocationConfig, userplane::netlink_route::NetlinkRouteProgrammer};
use anyhow::{Result, ensure};
use slog::Logger;
use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};

#[derive(Clone)]
enum UeIpAllocationMode {
    // Allocate addresses from a /24 IPv4 prefix.
    RoutedUeSubnet(Ipv4Addr),

    // Obtain addresses using DHCP over the given interface name
    Dhcp(Arc<DhcpClient>),
}

// The UeIpAllocator obtains IP address for PDU sesions, either using DHCP
// or by allocating addresses from a configured /24 subnet.
#[derive(Clone)]
pub struct UeIpAllocator {
    netlink_route_programmer: NetlinkRouteProgrammer,
    mode: UeIpAllocationMode,
}

// TODO move to strategy pattern

impl UeIpAllocator {
    pub async fn new(ue_network_if_index: u32, config: UeIpAllocationConfig) -> Result<Self> {
        let mode = match config {
            UeIpAllocationConfig::RoutedUeSubnet(subnet) => {
                UeIpAllocationMode::RoutedUeSubnet(subnet)
            }
            UeIpAllocationConfig::Dhcp => {
                // Start the DHCP client
                UeIpAllocationMode::Dhcp(Arc::new(DhcpClient::new().await?))
            }
        };
        Ok(Self {
            netlink_route_programmer: NetlinkRouteProgrammer::new(ue_network_if_index)?,
            mode,
        })
    }

    pub async fn allocate(&self, idx: u8, logger: &Logger) -> Result<Ipv4Addr> {
        let addr = match &self.mode {
            UeIpAllocationMode::RoutedUeSubnet(ue_subnet) => {
                let mut ue_addr_octets = ue_subnet.octets();
                ue_addr_octets[3] = idx;
                Ipv4Addr::from(ue_addr_octets)
            }
            UeIpAllocationMode::Dhcp(dhcp_client) => {
                // Obtain a new address and store the lease.
                let lease = DhcpLease::new(&dhcp_client).await?;

                // TODO: store the lease handle in a map

                lease.ip
            }
        };

        // Program a host route for it (which enables Linux proxy ARP + UE packet reception by ebpf).
        self.netlink_route_programmer
            .add_host_route(addr, logger)
            .await?;

        Ok(addr)
    }

    // TODO: we shouldn't hold up the release process until we get a response from the server.
    // It should be a separate task. See comment on drop() below.
    pub async fn release(&self, addr: Ipv4Addr, logger: &Logger) {
        // TODO: look up the lease cancel handle in a map + cancel it
        // if let Some(lease) = addr.handle {
        //     lease.cancel().await;
        // }

        self.netlink_route_programmer
            .delete_host_route(addr, logger)
            .await;
    }
}

use async_std::{channel::Sender, net::UdpSocket, sync::Mutex};
type ServerMessage = u32;

// The DHCP client owns a UDP socket listening on port 68.
// It sends requests over its socket and routes responses back to the requester.
// It can cope with multiple parallel transactions from different clients.
struct DhcpClient {
    socket: UdpSocket,
    pending_requests: Arc<Mutex<HashMap<ClientRequestKey, Sender<ServerMessage>>>>,
}

type ClientRequestKey = u32;

impl DhcpClient {
    async fn new() -> Result<Self> {
        // Surely this is not ok as it is going to clash with other DHCP clients?  Test
        let socket = UdpSocket::bind("0.0.0.0:68").await?;
        println!("Bound DHCP socket to UDP 68");
        let pending_requests = Arc::new(Mutex::new(HashMap::new()));
        let _ = async_std::task::spawn(async {});
        Ok(Self {
            socket,
            pending_requests,
        })
    }

    pub async fn send(&self, m: DhcpClientMessage) -> Result<DhcpServerMessage> {
        todo!()
    }
}

type DhcpClientMessage = u32;
type DhcpServerMessage = u32;
const OFFER: u32 = 1;
const ACK: u32 = 2;

// The DHCP lease object maintains a DHCP lease until cancelled.  Each DHCP lease has a
// task with a reference to a DhcpClient that periodically makes requests to renew the lease.
struct DhcpLease {
    pub ip: Ipv4Addr,
    cancel_sender: u32,
}
impl DhcpLease {
    pub async fn new(client: &DhcpClient) -> Result<Self> {
        let discover = 1;
        let offer = client.send(discover).await?;
        ensure!(offer == OFFER, "Expected OFFER");
        let request = 1;
        let ack = client.send(request).await?;
        ensure!(ack == ACK, "Expected ACK");

        //let addr = ack.address;
        let ip = Ipv4Addr::new(1, 1, 1, 1);

        // All good.  TODO.  Spawn the task to keep the lease.
        let cancel_sender = 1;

        Ok(Self { ip, cancel_sender })
    }
    pub async fn cancel(self) {
        todo!()
    }
}

// TODO - have lease drop() spawn a task to carry out the lease cancel procedure?
