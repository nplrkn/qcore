use anyhow::{Context, Result, anyhow, bail};
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

use crate::data::DhcpConfig;

// The DhcpClient appears on the network as a DHCP relay, and need to be configured
// with the local IP address and MAC address of the external interface.
//
// It binds a UDP socket listening on port 67, the DHCP server port (because it is a relay, not a client).
//
// The reason for QCore to act a a DHCP relay is to make use of the existing IP address.
// If QCore was a DHCP client it would have to send packets from 0.0.0.0, which is not possible
// using a UdpSocket.  (RFC2131: "DHCP messages broadcast by a client prior to that client obtaining
// its IP address must have the source address field in the IP header set to 0.")
//
// Addresses obtained with this client should be explicitly released.
#[derive(Clone)]
pub struct DhcpClient {
    socket: UdpSocket,
    local_mac: [u8; 6],
    local_ipv4: Ipv4Addr,
    pending_requests: Arc<Mutex<HashMap<Xid, Sender<Message>>>>,
    leases: Arc<Mutex<HashMap<Ipv4Addr, Sender<()>>>>,

    // DHCP server address.  Normally set to the broadcast address.
    // A unicast server address is used for testing purposes and potentially also has real life uses.
    server: Ipv4Addr,
}
type Xid = u32;

// DHCP servers have multi-second response times.
const DHCP_RESPONSE_TIMEOUT_MS: u64 = 4000;
const DHCP_SERVER_PORT: u16 = 67;

impl DhcpClient {
    pub async fn new(config: &DhcpConfig, logger: &Logger) -> Result<Self> {
        info!(
            logger,
            "My DHCP relay port  : {}:{}", config.local_ip, DHCP_SERVER_PORT
        );
        let socket = UdpSocket::bind(SocketAddrV4::new(config.local_ip, DHCP_SERVER_PORT))
            .await
            .context("binding DHCP relay port")?;
        socket.set_broadcast(true)?;
        let pending_requests = Arc::new(Mutex::new(HashMap::new()));
        let client = DhcpClient {
            socket,
            local_mac: config.local_mac.clone(),
            local_ipv4: config.local_ip,
            pending_requests,
            leases: Arc::new(Mutex::new(HashMap::new())),
            server: config.dhcp_server_ip.unwrap_or(Ipv4Addr::BROADCAST),
        };

        let client_clone = client.clone();
        let logger = logger.clone();
        async_std::task::spawn(async move { client_clone.dhcp_receive_task(logger).await });

        Ok(client)
    }

    pub async fn obtain_lease(
        &self,
        client_identifier: Vec<u8>,
        logger: &Logger,
    ) -> Result<Ipv4Addr> {
        // See the comment on ue_dhcp_identifier() for background on why we are formatting like this.
        debug!(
            logger,
            "Get DHCP lease for client identifier {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            client_identifier[0],
            client_identifier[1],
            client_identifier[2],
            client_identifier[3],
            client_identifier[4],
            client_identifier[5]
        );
        let ack = self
            .get_address_procedure(client_identifier.clone(), logger)
            .await?;
        let address = ack.yiaddr();
        debug!(
            logger,
            "Got lease for {} from server {}",
            address,
            server_ip_from_ack(&ack)?
        );

        let lease_cancel_handle = self.keep_lease(ack, client_identifier, logger).await;
        let existing_lease = self
            .leases
            .lock()
            .await
            .insert(address, lease_cancel_handle);
        if existing_lease.is_some() {
            warn!(logger, "Lease already existed for {}", address)
        }

        Ok(address)
    }

    pub async fn cancel_lease(&self, addr: &Ipv4Addr) -> Result<()> {
        match self.leases.lock().await.remove(addr) {
            None => bail!("Lease not found"),
            Some(lease_cancel_handle) => lease_cancel_handle.send(()).await?,
        }
        Ok(())
    }

    // Sanity check the allocation and renewal flows with the DHCP server
    // Notably this validates whether the server tolerates our nonstandard behaviour
    // of supplying a giaddr on a renewal.
    pub async fn self_test(&self, logger: &Logger) -> Result<()> {
        let client_identifier = b"QCORE TEST".to_vec();
        let ack = self
            .get_address_procedure(client_identifier.clone(), logger)
            .await?;
        debug!(
            logger,
            "------ DHCP ADDRESS ALLOCATION OK (got {})",
            ack.yiaddr()
        );

        let ack = self
            .renew_lease_procedure(&ack, client_identifier.clone(), logger)
            .await?;
        debug!(logger, "------ DHCP RENEWAL OK");

        self.relinquish_lease_procedure(&ack, client_identifier, logger)
            .await
    }

    // Send a message and get back a reply with the same Xid.
    async fn send_req(&self, msg: Message, ip: &Ipv4Addr) -> Result<Message> {
        let xid = msg.xid();
        let (sender, receiver) = async_std::channel::bounded::<Message>(1);
        self.pending_requests.lock().await.insert(xid, sender);

        self.send(msg, ip).await?;

        // TODO: retransmision on timeout. See RFC2131 4.1 para
        // beginning "DHCP clients are responsible for all message retransmission"

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

    async fn send(&self, msg: Message, ip: &Ipv4Addr) -> Result<()> {
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        msg.encode(&mut e)?;

        let _bytes_sent = self
            .socket
            .send_to(&buf, SocketAddrV4::new(*ip, DHCP_SERVER_PORT))
            .await;

        Ok(())
    }

    // This long-running task reads from the DhcpClient's socket and sends transaction responses down the
    // appropriate channel back to whichever task sent the request.
    async fn dhcp_receive_task(self, logger: Logger) -> Result<()> {
        let mut buf = vec![0; 1024];
        loop {
            let bytes_read = self.socket.recv(&mut buf).await?;
            let Ok(msg) = Message::decode(&mut Decoder::new(&buf[0..bytes_read])) else {
                warn!(logger, "Failed to decode message to DHCP port");
                continue;
            };

            let transaction = self.pending_requests.lock().await.remove(&msg.xid());
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

    async fn get_address_procedure(
        &self,
        client_identifier: Vec<u8>,
        logger: &Logger,
    ) -> Result<Message> {
        let mut common = Message::default();
        common
            .set_chaddr(&self.local_mac)
            .set_giaddr(self.local_ipv4)
            .opts_mut()
            .insert(v4::DhcpOption::ClientIdentifier(client_identifier.clone()));

        debug!(logger, "Dhcp Discover >>");
        let discover = discover(common.clone());
        let offer = self
            .send_req(discover, &self.server)
            .await
            .context("waiting for DHCPOFFER")?;
        check_offer(&offer)?;
        debug!(logger, "Dhcp Offer <<");

        let request = request_from_offer(common.clone(), &offer)?;
        debug!(logger, "Dhcp Request >>");
        let ack = self
            .send_req(request, &self.server)
            .await
            .context("waiting for DHCPACK")?;
        check_ack(&ack)?;
        debug!(logger, "Dhcp Ack <<");
        Ok(ack)
    }

    async fn renew_lease_procedure(
        &self,
        ack: &Message,
        client_identifier: Vec<u8>,
        logger: &Logger,
    ) -> Result<Message> {
        let server_ip = server_ip_from_ack(ack)?;
        let mut request = renewal_request(ack, client_identifier.clone(), &self.local_mac);

        // We are not meant to set giaddr() on a renewal but, from experimentation, DHCP servers will cope with this.
        // The correct alternative - sending and receiving DHCP on the UE's IP address - is quite difficult.
        request.set_giaddr(self.local_ipv4);

        debug!(logger, "Dhcp Request (renew) >>");
        let ack = self
            .send_req(request, &server_ip)
            .await
            .context("waiting for renewal DHCPACK")?;
        check_ack(&ack)?;
        debug!(logger, "Dhcp Ack <<");
        Ok(ack)
    }

    async fn relinquish_lease_procedure(
        &self,
        ack: &Message,
        client_identifier: Vec<u8>,
        logger: &Logger,
    ) -> Result<()> {
        let server_ip = server_ip_from_ack(ack)?;
        let mut release = release(ack, client_identifier.clone(), &self.local_mac);

        // Same comment as above about giaddr.
        release.set_giaddr(self.local_ipv4);

        debug!(logger, "Dhcp Release >>");
        self.send(release, &server_ip).await?;
        Ok(())
    }

    async fn keep_lease(
        &self,
        ack: Message,
        client_identifier: Vec<u8>,
        logger: &Logger,
    ) -> Sender<()> {
        let (sender, receiver) = async_std::channel::bounded::<()>(1);
        let logger_clone = logger.clone();
        let self_clone = self.clone();
        async_std::task::spawn(async move {
            if let Err(e) = self_clone
                .keep_lease_task(receiver, ack, client_identifier, &logger_clone)
                .await
            {
                warn!(logger_clone, "Lease task exited with error {e}");
            }
        });
        sender
    }

    // This task is per lease (= IP PDU session), and renews the lease on a timer.  To cancel it,
    // send to the channel in the `cancel` param.
    async fn keep_lease_task(
        self,
        cancel: Receiver<()>,
        mut ack: Message,
        client_identifier: Vec<u8>,
        logger: &Logger,
    ) -> Result<()> {
        loop {
            let mut lease_time_secs = match ack.opts().get(v4::OptionCode::AddressLeaseTime) {
                Some(v4::DhcpOption::AddressLeaseTime(lease_time)) => *lease_time,
                _ => 0,
            };
            if lease_time_secs == 0 {
                warn!(logger, "DHCP server supplied 0s lease time - use 1hr");
                lease_time_secs = 3600;
            }
            let renewal_interval = Duration::from_millis(lease_time_secs as u64 * 500);
            debug!(
                logger,
                "DHCP renewal interval for leased address {} = {}ms",
                ack.yiaddr(),
                lease_time_secs as u64 * 500
            );

            match async_std::future::timeout(renewal_interval, cancel.recv()).await {
                Err(_) => {
                    // Timeout - renew lease
                    ack = self
                        .renew_lease_procedure(&ack, client_identifier.clone(), logger)
                        .await?;

                    // TODO see RFC2131 4.4.5 which has some quite complex behavior around retrying + rebinding
                    // if the ACK does not arrive.

                    // TODO cope with the case where the server does not renew.  This ought to provoke network initiated
                    // session teardown (TS29.561).
                }
                Ok(_) => {
                    // Cancellation received
                    debug!(logger, "Exit DHCP lease task for {}", ack.yiaddr());

                    // It is debatable whether we should relinquish the lease here. From RFC2131:
                    // "Only in the case where the client explicitly needs to relinquish its lease, e.g., the client
                    //  is about to be moved to a different subnet, will the client send a DHCPRELEASE message"

                    return Ok(());
                }
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

    msg.opts_mut().insert(server_identifier.clone());

    // 3.1 "The 'requested IP address' option MUST be set to the value of 'yiaddr' in the
    // DHCPOFFER message from the server.
    msg.opts_mut()
        .insert(v4::DhcpOption::RequestedIpAddress(offer.yiaddr()));

    // Table 5: "'xid' from server DHCPOFFER message"
    msg.set_xid(offer.xid());

    Ok(msg)
}

fn renewal_request(ack: &Message, client_identifier: Vec<u8>, chaddr: &[u8]) -> Message {
    let mut msg = Message::default();
    msg.set_chaddr(chaddr).set_ciaddr(ack.yiaddr());

    msg.opts_mut()
        .insert(v4::DhcpOption::ClientIdentifier(client_identifier));

    msg.opts_mut()
        .insert(v4::DhcpOption::MessageType(v4::MessageType::Request));

    msg
}

fn release(ack: &Message, client_identifier: Vec<u8>, chaddr: &[u8]) -> Message {
    let mut msg = Message::default();
    msg.set_chaddr(chaddr).set_ciaddr(ack.yiaddr());

    msg.opts_mut()
        .insert(v4::DhcpOption::ClientIdentifier(client_identifier));

    msg.opts_mut()
        .insert(v4::DhcpOption::MessageType(v4::MessageType::Release));

    msg
}

fn server_ip_from_ack(ack: &Message) -> Result<Ipv4Addr> {
    let Some(v4::DhcpOption::ServerIdentifier(server_ip)) =
        ack.opts().get(v4::OptionCode::ServerIdentifier)
    else {
        // See RFC2131, table 3
        bail!("Mandatory option ServerIdentifier missing from DHCP Ack")
    };
    Ok(*server_ip)
}

fn check_offer(offer: &Message) -> Result<()> {
    if offer.opts().msg_type() != Some(MessageType::Offer) {
        bail!("Expected DHCPOFFER in response to DHCPDISCOVER");
    };
    Ok(())
}

fn check_ack(ack: &Message) -> Result<()> {
    if ack.opts().msg_type() != Some(MessageType::Ack) {
        bail!("Expected DHCPACK in response to DHCPREQUEST");
    };

    let Some(v4::DhcpOption::AddressLeaseTime(_)) =
        ack.opts().get(v4::OptionCode::AddressLeaseTime)
    else {
        // RFC2131, table 3
        bail!("Missing mandatory IP lease time parameter in DHCPACK")
    };

    Ok(())
}
