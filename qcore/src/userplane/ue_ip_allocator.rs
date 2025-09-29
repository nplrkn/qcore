use crate::{data::UeIpAllocationConfig, userplane::netlink_route::NetlinkRouteProgrammer};
use anyhow::{Result, anyhow, bail, ensure};
use dhcproto::{
    Decodable, Decoder, Encodable, Encoder,
    v4::{self, Message, MessageType},
};
use slog::{Logger, warn};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

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
    pub async fn new(
        ue_network_if_index: u32,
        config: UeIpAllocationConfig,
        logger: &Logger,
    ) -> Result<Self> {
        let mode = match config {
            UeIpAllocationConfig::RoutedUeSubnet(subnet) => {
                UeIpAllocationMode::RoutedUeSubnet(subnet)
            }
            UeIpAllocationConfig::Dhcp => {
                // Start the DHCP client
                println!("Using hardcoded local MAC!");
                let local_mac = [0x48, 0x21, 0x0b, 0x56, 0xfd, 0xe1];
                // test with tcpdump -i any port 67 or port 68
                UeIpAllocationMode::Dhcp(Arc::new(DhcpClient::new(local_mac, logger).await?))
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

use async_std::{channel::Sender, sync::Mutex};
use smol::net::UdpSocket;

// The DHCP client owns a UDP socket listening on port 68.
// It sends requests over its socket and routes responses back to the requester.
// It can cope with multiple parallel transactions from different clients.
struct DhcpClient {
    socket: UdpSocket,
    local_mac: [u8; 6],

    // This is keyed on the DHCP XID
    pending_requests: Arc<Mutex<HashMap<u32, Sender<Message>>>>,
}

impl DhcpClient {
    async fn new(local_mac: [u8; 6], logger: &Logger) -> Result<Self> {
        // Surely this is going to clash with other DHCP clients?  Test
        let socket = UdpSocket::bind("255.255.255.255:68").await?;
        socket.set_broadcast(true)?;
        println!("Bound DHCP socket to UDP 68 and set broadcast");
        let pending_requests = Arc::new(Mutex::new(HashMap::new()));
        let socket_clone = socket.clone();
        let pending_requests_clone = pending_requests.clone();
        let logger_clone = logger.clone();
        let _ = async_std::task::spawn(async {
            dispatch_all(pending_requests_clone, socket_clone, logger_clone)
        });
        Ok(Self {
            socket,
            local_mac,
            pending_requests,
        })
    }

    // Send a request and get back the response with a given transaction ID, or timeout.
    pub async fn send(&self, xid: u32, bytes: &[u8]) -> Result<Message> {
        let (sender, receiver) = async_std::channel::bounded::<Message>(1);
        self.pending_requests.lock().await.insert(xid, sender);
        self.socket
            .send_to(bytes, SocketAddr::from(([255, 255, 255, 255], 67)))
            .await?;
        let Ok(rcv) = async_std::future::timeout(Duration::from_millis(500), receiver.recv()).await
        else {
            bail!("Timeout")
        };
        rcv.map_err(|_| anyhow!("Channel receive error"))
    }
}

async fn dispatch_all(
    pending_requests: Arc<Mutex<HashMap<u32, Sender<Message>>>>,
    socket: UdpSocket,
    logger: Logger,
) -> Result<()> {
    let mut buf = vec![0; 1024];
    loop {
        let bytes_read = socket.recv(&mut buf).await?;

        let Ok(msg) = Message::decode(&mut Decoder::new(&buf[0..bytes_read])) else {
            warn!(logger, "Failed to decode message to DHCP client port");
            continue;
        };

        let transaction = pending_requests.lock().await.remove(&msg.xid());
        if let Some(s) = transaction {
            s.send(msg).await?;
        } else {
            warn!(
                logger,
                "Received DHCP message with unknown transaction {}",
                msg.xid()
            );
        }
    }
}

// The DHCP lease object maintains a DHCP lease until cancelled.  Each DHCP lease has a
// task with a reference to a DhcpClient that periodically makes requests to renew the lease.
struct DhcpLease {
    pub ip: Ipv4Addr,
}
impl DhcpLease {
    pub async fn new(client: &DhcpClient) -> Result<Self> {
        // TODO - try putting the IMSI as the DHCP client ID
        let (xid, discover) = discover(&client.local_mac)?;
        println!("Sending DHCP discover");
        let offer = client.send(xid, &discover).await?;
        if offer.opts().msg_type() != Some(MessageType::Offer) {
            bail!("Expected DHCP Offer");
        };
        println!("Got DHCP offer with IP address {}", offer.yiaddr());
        todo!();

        // check offer
        //ensure!(offer == OFFER, "Expected OFFER");
        // let request = vec![];
        // let ack = client.send(1, request).await?;
        // ensure!(ack == ACK, "Expected ACK");

        //let addr = ack.address;
        let ip = Ipv4Addr::new(1, 1, 1, 1);

        // All good.  TODO.  Spawn the task to keep the lease.
        let cancel_sender = 1;

        Ok(Self { ip })
    }
    pub async fn cancel(self) {
        todo!()
    }
}

// TODO - have lease drop() spawn a task to carry out the lease cancel procedure?

fn discover(local_mac: &[u8; 6]) -> Result<(u32, Vec<u8>)> {
    let mut msg = v4::Message::default();
    msg.set_flags(v4::Flags::default().set_broadcast()) // set broadcast to true
        .set_chaddr(local_mac) // set chaddr
        .opts_mut()
        .insert(v4::DhcpOption::MessageType(v4::MessageType::Discover)); // set msg type

    msg.opts_mut()
        .insert(v4::DhcpOption::ClientIdentifier(local_mac.to_vec()));

    msg.opts_mut()
        .insert(v4::DhcpOption::ParameterRequestList(vec![
            v4::OptionCode::SubnetMask,
            v4::OptionCode::Router,
            v4::OptionCode::DomainNameServer,
            v4::OptionCode::DomainName,
        ]));
    let xid = msg.xid();
    let mut buf = Vec::new();
    let mut e = Encoder::new(&mut buf);
    let Ok(()) = msg.encode(&mut e) else {
        bail!("Failed");
    };
    Ok((xid, buf))
}
