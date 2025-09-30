use anyhow::{Result, bail, ensure};
use async_net::UdpSocket;
use dhcproto::{
    Decodable, Decoder, Encodable, Encoder,
    v4::{self, Message, MessageType, OptionCode},
};
use slog::{Logger, info};
use std::net::{Ipv4Addr, SocketAddrV4};

pub struct MockDhcpServer {
    socket: UdpSocket,
    pub ip: Ipv4Addr,
    logger: Logger,
}

const DHCP_SERVER_PORT: u16 = 67;

impl MockDhcpServer {
    pub async fn new(ip: Ipv4Addr, logger: Logger) -> Result<Self> {
        let socket = UdpSocket::bind(SocketAddrV4::new(ip, DHCP_SERVER_PORT)).await?;
        Ok(Self { socket, ip, logger })
    }

    pub async fn hand_out_address(&self, addr: Ipv4Addr) -> Result<()> {
        let discover = self.receive_discover().await?;
        self.send_offer(addr, &discover).await?;
        let request = self.receive_request().await?;
        self.send_ack(&request).await
    }

    async fn receive(&self) -> Result<Message> {
        let mut buf = vec![0; 1024];
        let bytes_read = self.socket.recv(&mut buf).await?;
        Ok(Message::decode(&mut Decoder::new(&buf[0..bytes_read]))?)
    }

    async fn send(&self, msg: Message) -> Result<()> {
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        msg.encode(&mut e)?;
        let dst_ip = msg.giaddr();
        self.socket
            .send_to(&buf, SocketAddrV4::new(dst_ip, DHCP_SERVER_PORT))
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
            "Not DHCPDISCOVER"
        );
        info!(self.logger, ">> Dhcp Request");
        Ok(msg)
    }

    async fn send_offer(&self, addr: Ipv4Addr, discover: &Message) -> Result<()> {
        let offer = self.build_offer_from_discover(addr, discover);
        info!(self.logger, "<< Dhcp Offer");
        self.send(offer).await
    }

    async fn send_ack(&self, request: &Message) -> Result<()> {
        let ack = self.build_ack_from_request(request)?;
        info!(self.logger, "<< Dhcp Ack");
        self.send(ack).await
    }

    fn build_offer_from_discover(&self, yiaddr: Ipv4Addr, discover: &Message) -> Message {
        let mut offer = Message::default();
        offer
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

    fn build_ack_from_request(&self, request: &Message) -> Result<Message> {
        let Some(v4::DhcpOption::RequestedIpAddress(requested_address)) =
            request.opts().get(OptionCode::RequestedIpAddress)
        else {
            bail!("Missing Requested Ip Address on DHCPREQUEST");
        };

        let mut ack = Message::default();
        ack.set_chaddr(request.chaddr())
            .set_giaddr(request.giaddr())
            .set_yiaddr(*requested_address)
            .set_xid(request.xid());

        ack.opts_mut()
            .insert(v4::DhcpOption::MessageType(v4::MessageType::Ack));

        ack.opts_mut()
            .insert(v4::DhcpOption::ServerIdentifier(self.ip));

        ack.opts_mut().insert(v4::DhcpOption::AddressLeaseTime(30));

        Ok(ack)
    }
}
