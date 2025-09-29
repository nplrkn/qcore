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
use slog::{Logger, debug, warn};
use smol::net::UdpSocket;
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
                println!("Using imaginary MAC!");
                let local_mac = [0x02, 0x02, 0x02, 0x02, 0x02, 0x02];
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
            UeIpAllocationMode::Dhcp(dhcp_client) => dhcp_client.obtain_lease(logger).await?,
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

// The DHCP client owns a UDP socket listening on port 68.
// It sends requests over its socket and routes responses back to the requester.
// It can cope with multiple parallel transactions from different clients.
#[derive(Clone)]
struct DhcpClient {
    socket: UdpSocket,
    local_mac: [u8; 6],
    pending_requests: Arc<Mutex<HashMap<Xid, Sender<Message>>>>,
    leases: Arc<Mutex<HashMap<Ipv4Addr, Sender<()>>>>,
}
type Xid = u32;

const DHCP_RESPONSE_TIMEOUT_MS: u64 = 1000;

impl DhcpClient {
    async fn new(local_mac: [u8; 6], logger: &Logger) -> Result<Self> {
        // Surely this is going to clash with other DHCP clients?  Test

        // This is the DHCP server port - because we are going to act as a DHCP relay.
        let socket = UdpSocket::bind(" 192.168.1.14:67").await?;
        socket.set_broadcast(true)?;
        println!("Bound DHCP socket to UDP 67 and set broadcast");
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
            pending_requests,
            leases: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    // Send a request and get back the response with a given transaction ID, or timeout.
    pub async fn send(&self, msg: Message) -> Result<Message> {
        let xid = msg.xid();
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        msg.encode(&mut e)?;
        let (sender, receiver) = async_std::channel::bounded::<Message>(1);
        self.pending_requests.lock().await.insert(xid, sender);
        self.socket
            .send_to(&buf, SocketAddr::from(([255, 255, 255, 255], 67)))
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
    pub async fn obtain_lease(&self, logger: &Logger) -> Result<Ipv4Addr> {
        println!("Sending DHCP discover");
        let offer = self.send(discover(&self.local_mac)?).await?;
        if offer.opts().msg_type() != Some(MessageType::Offer) {
            bail!("Expected DHCPOFFER in response to DHCPDISCOVER");
        };
        println!("Got DHCP offer with IP address {}", offer.yiaddr());

        let request = request_from_offer(&self.local_mac, &offer)?;
        let ack = self.send(request).await?;
        if ack.opts().msg_type() != Some(MessageType::Ack) {
            bail!("Expected DHCPACK in response to DHCPREQUEST");
        };
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
            warn!(logger, "Failed to decode message to DHCP client port");
            continue;
        };

        let transaction = pending_requests.lock().await.remove(&msg.xid());
        if let Some(s) = transaction {
            s.send(msg).await?;
        } else {
            warn!(
                logger,
                "Received DHCP message with unknown transaction {:x}",
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

// TODO - have lease drop() spawn a task to carry out the lease cancel procedure?

fn discover(local_mac: &[u8; 6]) -> Result<Message> {
    let mut msg = v4::Message::default();
    msg.set_flags(v4::Flags::default()) //.set_broadcast()) // set broadcast to true
        .set_chaddr(local_mac) // set chaddr
        .set_giaddr(Ipv4Addr::new(192, 168, 1, 14))
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
    Ok(msg)
}

fn request_from_offer(local_mac: &[u8; 6], offer: &Message) -> Result<Message> {
    // RFC 2131
    // The client broadcasts a DHCPREQUEST message
    // that MUST include the 'server identifier' option to indicate which
    // server it has selected, and that MAY include other options
    // specifying desired configuration values.  The 'requested IP
    // address' option MUST be set to the value of 'yiaddr' in the
    // DHCPOFFER message from the server.
    let Some(server_identifier) = offer.opts().get(v4::OptionCode::ServerIdentifier) else {
        // See RFC2131, table 3
        bail!("Mandatory option ServerIdentifier missing from DHCP Offer")
    };

    let mut msg = v4::Message::default();
    msg.set_flags(v4::Flags::default()) //.set_broadcast())
        .set_chaddr(local_mac)
        .set_giaddr(Ipv4Addr::new(192, 168, 1, 14))
        .opts_mut()
        .insert(v4::DhcpOption::MessageType(v4::MessageType::Request));

    msg.opts_mut().insert(server_identifier.clone());
    msg.opts_mut()
        .insert(v4::DhcpOption::RequestedIpAddress(offer.yiaddr()));

    // The XID must match that set by the server on the offer
    msg.set_xid(offer.xid());

    Ok(msg)
}
