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
pub struct DhcpClient {
    socket: UdpSocket,
    local_mac: [u8; 6],
    local_ipv4: Ipv4Addr,
    pending_requests: Transactions,
    leases: Arc<Mutex<HashMap<Ipv4Addr, Sender<()>>>>,

    // DHCP server address.  Normally set to the broadcast address.
    // A unicast server address is used for testing purposes and potentially also has real life uses.
    server: Ipv4Addr,
}
type Xid = u32;
type Transactions = Arc<Mutex<HashMap<Xid, Sender<Message>>>>;

const DHCP_RESPONSE_TIMEOUT_MS: u64 = 1000;
const DHCP_SERVER_PORT: u16 = 67;

impl DhcpClient {
    pub async fn new(
        local_mac: [u8; 6],
        local_ipv4: Ipv4Addr,
        server: Option<Ipv4Addr>,
        logger: &Logger,
    ) -> Result<Self> {
        info!(
            logger,
            "Bind DHCP relay socket to {}:{}", local_ipv4, DHCP_SERVER_PORT
        );
        let socket = UdpSocket::bind(SocketAddrV4::new(local_ipv4, DHCP_SERVER_PORT)).await?;
        socket.set_broadcast(true)?;

        let pending_requests = Arc::new(Mutex::new(HashMap::new()));
        Self::spawn_receive_task(&socket, &pending_requests, &logger);

        Ok(Self {
            socket,
            local_mac,
            local_ipv4,
            pending_requests,
            leases: Arc::new(Mutex::new(HashMap::new())),
            server: server.unwrap_or(Ipv4Addr::BROADCAST),
        })
    }

    fn spawn_receive_task(socket: &UdpSocket, pending_requests: &Transactions, logger: &Logger) {
        let socket_clone = socket.clone();
        let pending_requests_clone = pending_requests.clone();
        let logger_clone = logger.clone();
        let _ = async_std::task::spawn(async {
            dhcp_receive_task(socket_clone, pending_requests_clone, logger_clone).await
        });
    }

    async fn send(&self, msg: Message) -> Result<Message> {
        let xid = msg.xid();

        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        msg.encode(&mut e)?;

        let (sender, receiver) = async_std::channel::bounded::<Message>(1);
        self.pending_requests.lock().await.insert(xid, sender);

        self.socket
            .send_to(&buf, SocketAddrV4::new(self.server, DHCP_SERVER_PORT))
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

    pub async fn obtain_lease(
        &self,
        client_identifier: Vec<u8>,
        logger: &Logger,
    ) -> Result<Ipv4Addr> {
        let mut common = Message::default();
        common
            .set_chaddr(&self.local_mac)
            .set_giaddr(self.local_ipv4)
            .opts_mut()
            .insert(v4::DhcpOption::ClientIdentifier(client_identifier));

        debug!(logger, "Dhcp Discover >>");
        let discover = discover(common.clone());
        let offer = self.send(discover).await?;
        self.check_offer(&offer)?;
        debug!(logger, "Dhcp Offer <<");

        let request = request_from_offer(common.clone(), &offer)?;
        debug!(logger, "Dhcp Request >>");
        let ack = self.send(request).await?;
        self.check_ack(&ack)?;
        debug!(logger, "Dhcp Ack <<");

        let lease = self.keep_lease(ack, logger).await;
        self.leases.lock().await.insert(offer.yiaddr(), lease);

        Ok(offer.yiaddr())
    }

    async fn keep_lease(&self, ack: Message, logger: &Logger) -> Sender<()> {
        let (sender, receiver) = async_std::channel::bounded::<()>(1);
        let logger_clone = logger.clone();
        let self_clone = self.clone();
        async_std::task::spawn(async {
            keep_lease_task(receiver, ack, self_clone, logger_clone).await
        });
        sender
    }

    pub async fn cancel_lease(&self, addr: &Ipv4Addr) -> Result<()> {
        match self.leases.lock().await.remove(addr) {
            None => bail!("Lease not found"),
            Some(sender) => sender.send(()).await?,
        }
        Ok(())
    }

    fn check_offer(&self, offer: &Message) -> Result<()> {
        if offer.opts().msg_type() != Some(MessageType::Offer) {
            bail!("Expected DHCPOFFER in response to DHCPDISCOVER");
        };
        Ok(())
    }

    fn check_ack(&self, ack: &Message) -> Result<()> {
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

        Ok(())
    }
}

async fn dhcp_receive_task(
    socket: UdpSocket,
    pending_requests: Arc<Mutex<HashMap<u32, Sender<Message>>>>,
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

async fn keep_lease_task(cancel: Receiver<()>, ack: Message, _client: DhcpClient, logger: Logger) {
    let mut lease_time_secs = match ack.opts().get(v4::OptionCode::AddressLeaseTime) {
        Some(v4::DhcpOption::AddressLeaseTime(lease_time)) => *lease_time,
        _ => 0,
    };

    if lease_time_secs == 0 {
        warn!(logger, "DHCP server supplied 0s lease time - use 1hr");
        lease_time_secs = 3600;
    }

    // Renew when half the time is up (DHCP timer T1)
    let renewal_interval = Duration::from_millis(lease_time_secs as u64 * 500);
    debug!(
        logger,
        "DHCP renewal interval for leased address {} = {}ms",
        ack.yiaddr(),
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
                // Cancel future completed - end lease + exit task
                // TODO: explicitly release lease via DHCPRELEASE.  Right now, we just let it time out.
                debug!(logger, "Exit DHCP lease task for {}", ack.yiaddr());

                break;
            }
        }
    }
}

fn discover(mut msg: Message) -> Message {
    msg.opts_mut()
        .insert(v4::DhcpOption::MessageType(v4::MessageType::Discover));

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
