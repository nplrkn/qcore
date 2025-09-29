use crate::{data::UeIpAllocationConfig, userplane::netlink_route::NetlinkRouteProgrammer};
use anyhow::{Result, anyhow, bail};
use async_std::{
    channel::{Receiver, Sender},
    sync::Mutex,
};
use dhcproto::{
    Decodable, Decoder, Encodable, Encoder,
    v4::{self, Message, MessageType},
};
use slog::{Logger, debug, info, warn};
use smol::net::UdpSocket;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddrV4},
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
        let netlink = NetlinkRouteProgrammer::new(ue_network_if_index)?;

        let mode = match config {
            UeIpAllocationConfig::RoutedUeSubnet(subnet) => {
                UeIpAllocationMode::RoutedUeSubnet(subnet)
            }
            UeIpAllocationConfig::Dhcp(if_index) => {
                // Start the DHCP client
                info!(
                    logger,
                    "DHCP address allocation on LAN connected over if index {}", if_index
                );
                let (ip, mac) = netlink.get_link_addr_info(if_index).await?;
                UeIpAllocationMode::Dhcp(Arc::new(DhcpClient::new(mac, ip, logger).await?))
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
                let mut ue_addr_octets = ue_subnet.octets();
                ue_addr_octets[3] = idx;
                Ipv4Addr::from(ue_addr_octets)
            }
            UeIpAllocationMode::Dhcp(dhcp_client) => {
                dhcp_client
                    .obtain_lease(dhcp_client_identifier, logger)
                    .await?
            }
        };

        // Program a host route for it (which enables Linux proxy ARP + UE packet reception by ebpf).
        self.netlink_route_programmer
            .add_host_route(addr, logger)
            .await?;

        Ok(addr)
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

// The DhcpClient appears on the network as a DHCP relay, and need to be configured
// with an IP address and MAC address of the external interface.
//
// It binds a UDP socket listening on port 67, the DHCP server port (because it is a relay, not a client).
//
// The reason for QCore to act a a DHCP relay is to make use of the existing IP address.
// If QCore was a DHCP client it would have to send packets from 0.0.0.0, which is not possible
// using a UdpSocket.  (RFC2131: " DHCP messages broadcast by a client prior to that client obtaining
// its IP address must have the source address field in the IP header set to 0.")
//
// Addresses obtained with this client should be explicitly released.
//
// It can cope with multiple parallel transactions from different clients.
#[derive(Clone)]
struct DhcpClient {
    socket: UdpSocket,
    local_mac: [u8; 6],
    local_ipv4: Ipv4Addr,
    pending_requests: Arc<Mutex<HashMap<Xid, Sender<Message>>>>,
    leases: Arc<Mutex<HashMap<Ipv4Addr, Sender<()>>>>,
}
type Xid = u32;

const DHCP_RESPONSE_TIMEOUT_MS: u64 = 1000;
const DHCP_SERVER_PORT: u16 = 67;

impl DhcpClient {
    async fn new(local_mac: [u8; 6], local_ipv4: Ipv4Addr, logger: &Logger) -> Result<Self> {
        info!(
            logger,
            "Bind DHCP relay socket to {}:{}", local_ipv4, DHCP_SERVER_PORT
        );
        let socket = UdpSocket::bind(SocketAddrV4::new(local_ipv4, DHCP_SERVER_PORT)).await?;
        socket.set_broadcast(true)?;

        // Spawn the reader task.
        let pending_requests = Arc::new(Mutex::new(HashMap::new()));
        let socket_clone = socket.clone();
        let pending_requests_clone = pending_requests.clone();
        let logger_clone = logger.clone();
        let _ = async_std::task::spawn(async {
            dispatch_all(pending_requests_clone, socket_clone, logger_clone).await
        });

        Ok(Self {
            socket,
            local_mac,
            local_ipv4,
            pending_requests,
            leases: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    // Send a request and get back the response with a given transaction ID, or timeout.
    async fn send(&self, msg: Message) -> Result<Message> {
        let xid = msg.xid();
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        msg.encode(&mut e)?;
        let (sender, receiver) = async_std::channel::bounded::<Message>(1);
        self.pending_requests.lock().await.insert(xid, sender);
        self.socket
            .send_to(
                &buf,
                SocketAddrV4::new(Ipv4Addr::BROADCAST, DHCP_SERVER_PORT),
            )
            .await?;
        let Ok(rcv) = async_std::future::timeout(
            Duration::from_millis(DHCP_RESPONSE_TIMEOUT_MS),
            receiver.recv(),
        )
        .await
        else {
            bail!("Timeout")
        };
        rcv.map_err(|_| anyhow!("Channel receive error"))
    }

    // Obtain and hold a DHCP lease until cancelled.
    pub async fn obtain_lease(
        &self,
        client_identifier: Vec<u8>,
        logger: &Logger,
    ) -> Result<Ipv4Addr> {
        let mut base = Message::default();
        base.set_chaddr(&self.local_mac)
            .set_giaddr(self.local_ipv4)
            .opts_mut()
            // RFC2131: If the client uses a 'client identifier' in one message, it MUST use that
            // same identifier in all subsequent messages, to ensure that all servers correctly
            // identify the client.
            .insert(v4::DhcpOption::ClientIdentifier(client_identifier));

        debug!(logger, ">> DHCPDISCOVER");
        let discover = discover(base.clone());
        let offer = self.send(discover).await?;
        if offer.opts().msg_type() != Some(MessageType::Offer) {
            bail!("Expected DHCPOFFER in response to DHCPDISCOVER");
        };
        debug!(logger, "<< DHCPOFFER");
        let request = request_from_offer(base.clone(), &offer)?;
        debug!(logger, ">> DHCPREQUEST");
        let ack = self.send(request).await?;
        if ack.opts().msg_type() != Some(MessageType::Ack) {
            bail!("Expected DHCPACK in response to DHCPREQUEST");
        };
        debug!(logger, "<< DHCPACK");
        let Some(v4::DhcpOption::AddressLeaseTime(lease_time)) =
            ack.opts().get(v4::OptionCode::AddressLeaseTime)
        else {
            // RFC2131, table 3
            bail!("Missing mandatory IP lease time parameter in DHCPACK")
        };
        if *lease_time == 0 {
            bail!("Zero lease time in DHCPACK")
        };

        // All good.  Spawn the task to keep the lease.
        let (sender, receiver) = async_std::channel::bounded::<()>(1);
        self.leases.lock().await.insert(offer.yiaddr(), sender);
        //let self_clone = Arc::new(self)
        let logger_clone = logger.clone();
        let self_clone = self.clone();
        async_std::task::spawn(async { keep_lease(receiver, ack, self_clone, logger_clone).await });
        Ok(offer.yiaddr())
    }

    pub async fn cancel_lease(&self, addr: &Ipv4Addr) -> Result<()> {
        match self.leases.lock().await.remove(addr) {
            None => bail!("Lease not found"),
            Some(sender) => sender.send(()).await?,
        }
        Ok(())
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
            warn!(logger, "Failed to decode message to DHCP port");
            continue;
        };

        let transaction = pending_requests.lock().await.remove(&msg.xid());
        if let Some(s) = transaction {
            s.send(msg).await?;
        } else {
            warn!(
                logger,
                "Ignoring DHCP message with unknown xid {:x}",
                msg.xid()
            );
        }
    }
}

async fn keep_lease(cancel: Receiver<()>, ack: Message, _client: DhcpClient, logger: Logger) {
    let lease_time_secs = match ack.opts().get(v4::OptionCode::AddressLeaseTime) {
        Some(v4::DhcpOption::AddressLeaseTime(lease_time)) => *lease_time,
        _ => 3600, // unhittable - we already checked in the caller
    };

    // Renew when half the time is up (DHCP timer T1)
    let renewal_interval = Duration::from_millis(lease_time_secs as u64 * 500);
    debug!(
        logger,
        "DHCP renewal interval {}ms",
        lease_time_secs as u64 * 500
    );

    loop {
        match async_std::future::timeout(renewal_interval, cancel.recv()).await {
            Err(_) => {
                // Timeout - renew lease
                // TODO - note this is unicast and is going to be sent to the UE if we're not careful
                println!("Lease renewal not yet implemented!!!")

                // TODO see RFC2131 4.4.5 which has some quite complex behavior around retrying + rebinding
                // if the ACK does not arrive.
            }
            Ok(_) => {
                // Cancel future completed - end lease
                // TODO: Probably ok not to implement this for now
                println!("DHCPRELEASE not yet implemented");

                // Exit this task
                break;
            }
        }
    }
}

fn discover(mut msg: Message) -> Message {
    msg.opts_mut()
        .insert(v4::DhcpOption::MessageType(v4::MessageType::Discover)); // set msg type

    msg.opts_mut()
        .insert(v4::DhcpOption::ParameterRequestList(vec![
            v4::OptionCode::SubnetMask,
            v4::OptionCode::Router,
            v4::OptionCode::DomainNameServer,
            v4::OptionCode::DomainName,
        ]));
    msg
}

fn request_from_offer(mut msg: Message, offer: &Message) -> Result<Message> {
    // RFC 2131
    // The client broadcasts a DHCPREQUEST message
    // that MUST include the 'server identifier' option to indicate which
    // server it has selected, and that MAY include other options
    // specifying desired configuration values.
    let Some(server_identifier) = offer.opts().get(v4::OptionCode::ServerIdentifier) else {
        // See RFC2131, table 3
        bail!("Mandatory option ServerIdentifier missing from DHCP Offer")
    };

    msg.opts_mut()
        .insert(v4::DhcpOption::MessageType(v4::MessageType::Request));

    // 3.1 "The 'requested IP address' option MUST be set to the value of 'yiaddr' in the
    // DHCPOFFER message from the server.
    msg.opts_mut().insert(server_identifier.clone());
    msg.opts_mut()
        .insert(v4::DhcpOption::RequestedIpAddress(offer.yiaddr()));

    // Table 5: "'xid' from server DHCPOFFER message"
    msg.set_xid(offer.xid());

    Ok(msg)
}
