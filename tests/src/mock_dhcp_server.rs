use anyhow::{Result, ensure};
use async_net::UdpSocket;
use dhcproto::{
    Decodable, Decoder, Encodable, Encoder,
    v4::{self, Message, MessageType, OptionCode},
};
use slog::{Logger, info};
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

pub struct MockDhcpServer {
    socket: UdpSocket,
    pub ip: Ipv4Addr,
    logger: Logger,
}

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

impl MockDhcpServer {
    pub async fn new(ip: Ipv4Addr, logger: Logger) -> Result<Self> {
        let socket = UdpSocket::bind(SocketAddrV4::new(ip, DHCP_SERVER_PORT)).await?;
        Ok(Self { socket, ip, logger })
    }

    pub async fn hand_out_address(&self, addr: Ipv4Addr, lease_time_secs: u32) -> Result<()> {
        let discover = self.receive_discover().await?;
        self.send_offer(addr, &discover).await?;
        let request = self.receive_request().await?;
        self.send_ack(&request, lease_time_secs).await
    }

    pub async fn handle_renewal(&self, _addr: Ipv4Addr) -> Result<()> {
        let request = self.receive_request().await?;
        self.send_ack(&request, 30).await
    }

    async fn receive(&self) -> Result<Message> {
        let mut buf = vec![0; 1024];
        let bytes_read =
            async_std::future::timeout(Duration::from_millis(500), self.socket.recv(&mut buf))
                .await??;
        Ok(Message::decode(&mut Decoder::new(&buf[0..bytes_read]))?)
    }

    async fn send(&self, msg: Message) -> Result<()> {
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        msg.encode(&mut e)?;

        let (dst_ip, port) = if msg.giaddr().is_unspecified() {
            (msg.yiaddr(), DHCP_CLIENT_PORT) // not actually hittable with current QCore implementation
        } else {
            (msg.giaddr(), DHCP_SERVER_PORT) // case where QCore is acting as a relay
        };

        self.socket
            .send_to(&buf, SocketAddrV4::new(dst_ip, port))
            .await?;
        Ok(())
    }

    async fn receive_discover(&self) -> Result<Message> {
        let msg = self.receive().await?;
        ensure!(
            msg.opts().msg_type() == Some(MessageType::Discover),
            "Not DHCPDISCOVER"
        );
        info!(self.logger, ">> Dhcp Discover");
        Ok(msg)
    }

    async fn receive_request(&self) -> Result<Message> {
        let msg = self.receive().await?;
        ensure!(
            msg.opts().msg_type() == Some(MessageType::Request),
            "Not Request"
        );
        info!(self.logger, ">> Dhcp Request");
        Ok(msg)
    }

    async fn send_offer(&self, addr: Ipv4Addr, discover: &Message) -> Result<()> {
        let offer = self.build_offer_from_discover(addr, discover);
        info!(self.logger, "<< Dhcp Offer");
        self.send(offer).await
    }

    async fn send_ack(&self, request: &Message, lease_time_secs: u32) -> Result<()> {
        let ack = self.build_ack_from_request(request, lease_time_secs)?;
        info!(self.logger, "<< Dhcp Ack");
        self.send(ack).await
    }

    fn build_offer_from_discover(&self, yiaddr: Ipv4Addr, discover: &Message) -> Message {
        let mut offer = Message::default();
        offer
            .set_opcode(v4::Opcode::BootReply)
            .set_chaddr(discover.chaddr())
            .set_giaddr(discover.giaddr())
            .set_yiaddr(yiaddr)
            .set_xid(discover.xid());

        offer
            .opts_mut()
            .insert(v4::DhcpOption::MessageType(v4::MessageType::Offer));

        offer
            .opts_mut()
            .insert(v4::DhcpOption::ServerIdentifier(self.ip));

        offer
            .opts_mut()
            .insert(v4::DhcpOption::AddressLeaseTime(30));

        offer
    }

    fn build_ack_from_request(&self, request: &Message, lease_time_secs: u32) -> Result<Message> {
        // This covers both the initial discovery case, where the requested address is an option, and
        // the renewal case, where the client puts their existing address in ciaddr.
        let requested_address = match request.opts().get(OptionCode::RequestedIpAddress) {
            Some(v4::DhcpOption::RequestedIpAddress(requested_address)) => requested_address,
            _ => &request.ciaddr(),
        };

        let mut ack = Message::default();
        ack.set_opcode(v4::Opcode::BootReply)
            .set_chaddr(request.chaddr())
            .set_giaddr(request.giaddr())
            .set_yiaddr(*requested_address)
            .set_xid(request.xid());

        ack.opts_mut()
            .insert(v4::DhcpOption::MessageType(v4::MessageType::Ack));

        ack.opts_mut()
            .insert(v4::DhcpOption::ServerIdentifier(self.ip));

        ack.opts_mut()
            .insert(v4::DhcpOption::AddressLeaseTime(lease_time_secs));

        Ok(ack)
    }
}
