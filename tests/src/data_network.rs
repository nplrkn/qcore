use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use anyhow::Result;
use async_net::{AsyncToSocketAddrs, UdpSocket};
use async_std::future;
use slog::{Logger, info, o};

use crate::mock_dhcp_server::MockDhcpServer;

pub struct DataNetwork {
    logger: Logger,
    udp_socket: UdpSocket,
    dhcp_server: MockDhcpServer,
}

impl DataNetwork {
    const DHCP_SERVER_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 255, 0, 1);

    pub async fn new(logger: &Logger) -> Result<Self> {
        // Mock up a UDP server running in the DN for UEs to send packets to.
        let Ok(IpAddr::V4(udp_server_ip)) = local_ip_address::local_ip() else {
            panic!("Couldn't get local IPv4");
        };
        let udp_server_port = 23215;
        let bind_addr = SocketAddr::new(IpAddr::V4(udp_server_ip), udp_server_port);
        let udp_socket = UdpSocket::bind(&bind_addr).await?;

        // Have the mock DHCP server listen on an arbitrary local address.
        let dhcp_server = MockDhcpServer::new(Self::DHCP_SERVER_ADDRESS, logger.clone()).await?;

        Ok(DataNetwork {
            logger: logger.new(o!("dn" => 1)),
            udp_socket,
            dhcp_server,
        })
    }

    pub fn dhcp_server(&self) -> &MockDhcpServer {
        &self.dhcp_server
    }

    pub fn udp_server_addr(&self) -> SocketAddr {
        self.udp_socket.local_addr().unwrap()
    }

    pub async fn send_n6_udp_packet<A: AsyncToSocketAddrs>(&self, ue_addr_port: A) -> Result<()> {
        info!(self.logger, "Send N6 packet");
        self.udp_socket.send_to(&[0; 10], ue_addr_port).await?;
        Ok(())
    }

    pub async fn receive_n6_udp_packet(&self) -> Result<()> {
        let mut buf = [0; 2000];
        let future_result = self.udp_socket.recv(&mut buf);
        let _bytes_received = future::timeout(Duration::from_secs(50), future_result).await??;
        info!(&self.logger, ">> Uplink packet from UE");
        Ok(())
    }
}
