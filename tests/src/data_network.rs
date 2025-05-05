use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::Result;
use async_net::{AsyncToSocketAddrs, UdpSocket};
use async_std::future;
use slog::{Logger, info, o};

pub struct DataNetwork {
    logger: Logger,
    udp_socket: UdpSocket,
}

impl DataNetwork {
    pub async fn new(logger: &Logger) -> Self {
        // Mock up a UDP server running in the DN for UEs to send packets to.
        // For this purpose we can't use a 127.0.0.0/8 address, because from the
        // p.o.v. of Linux routing UE packets arrive over the UE tun interface and are treated as if they come
        // from a remote host - which is not allowed to talk to loopback addresses.
        let Ok(IpAddr::V4(udp_server_ip)) = local_ip_address::local_ip() else {
            panic!("Couldn't get local IPv4");
        };
        let udp_server_port = 23215;
        let bind_addr = SocketAddr::new(IpAddr::V4(udp_server_ip), udp_server_port);
        let udp_socket = UdpSocket::bind(&bind_addr).await.unwrap();

        DataNetwork {
            logger: logger.new(o!("dn" => 1)),
            udp_socket,
        }
    }

    pub fn udp_server_addr(&self) -> SocketAddr {
        self.udp_socket.local_addr().unwrap()
    }

    pub async fn send_n6_udp_packet<A: AsyncToSocketAddrs>(&self, ue_addr_port: A) -> Result<()> {
        self.udp_socket.send_to(&[0; 10], ue_addr_port).await?;
        info!(self.logger, "Sent in N6 packet");
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
