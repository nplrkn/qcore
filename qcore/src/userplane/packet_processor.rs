#![allow(clippy::unusual_byte_groupings)]
use super::{
    DownlinkForwardingTable, DownlinkPipeline, GTPU_PORT, MAX_UES, UplinkForwardingTable,
    UplinkPipeline,
};
use crate::UserplaneSession;
use anyhow::{Context, Result, bail, ensure};
use async_std::{fs::File, net::IpAddr, sync::Mutex};
use async_tun::{Tun, TunBuilder};
use index_pool::IndexPool;
use rand::RngCore;
use slog::{Logger, info};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::Arc;
use xxap::{GtpTeid, GtpTunnel};

#[derive(Clone)]
pub struct PacketProcessor {
    index_pool: Arc<Mutex<IndexPool>>,
    downlink_forwarding_table: DownlinkForwardingTable,
    uplink_forwarding_table: UplinkForwardingTable,
    ue_subnet: Ipv4Addr,
}

impl PacketProcessor {
    pub async fn new(
        local_ip: IpAddr,
        n6_tun_dev_name: &str,
        ue_subnet: Ipv4Addr,
        logger: &Logger,
    ) -> Result<Self> {
        // Create the packet source/sinks.
        let f1u_socket = create_f1u_socket(local_ip, logger)?;
        let f1u_socket_clone = f1u_socket.try_clone()?;
        let n6_tun = open_n6_tun_device(n6_tun_dev_name, logger).await?;
        let n6_tun_clone = unsafe { File::from_raw_fd(n6_tun.as_raw_fd()) };

        // Initialize the forwarding tables.
        let downlink_forwarding_table = DownlinkForwardingTable::new();
        let uplink_forwarding_table = UplinkForwardingTable::new();

        // Start the downlink pipeline (N6 -> F1U).
        let downlink_pipeline =
            DownlinkPipeline::new(f1u_socket.into(), n6_tun, downlink_forwarding_table.clone());
        let _downlink_task = downlink_pipeline.run();

        // Start the uplink pipeline (F1U -> N6).
        let uplink_pipeline = UplinkPipeline::new(
            f1u_socket_clone.into(),
            n6_tun_clone,
            uplink_forwarding_table.clone(),
        );
        let _uplink_task = uplink_pipeline.run(logger.clone());

        let mut index_pool = IndexPool::new();
        // Take the 0 slot, so that the first UE gets an IP address ending in .1.
        let _ = index_pool.request_id(0);
        let index_pool = Arc::new(Mutex::new(index_pool));

        Ok(PacketProcessor {
            index_pool,
            downlink_forwarding_table,
            uplink_forwarding_table,
            ue_subnet,
        })
    }

    pub async fn reserve_userplane_session(&self, _logger: &Logger) -> Result<UserplaneSession> {
        let idx = self.index_pool.lock().await.new_id();
        ensure!(idx < MAX_UES, "No more slots available");
        let idx = idx as u8;

        // Randomize the top part of the TEID.  It is meant to be unpredictable.
        let mut teid = (idx as u32).to_be_bytes();
        rand::rng().fill_bytes(&mut teid[0..3]);
        teid[3] = idx as u8;

        // Generate a UE IP.  We currently hardcode assumptions of 1 PDU session
        // per UE, and max 254 UEs.
        let mut ue_addr_octets = self.ue_subnet.octets().clone();
        ue_addr_octets[3] = idx;
        let ue_ipv4_addr = Ipv4Addr::from(ue_addr_octets);
        //info!(self.logger, "Allocated UE IP address {:?}", ue_ipv4_addr);

        // Create the uplink forwarding rule.
        self.uplink_forwarding_table
            .add_rule(ue_ipv4_addr, teid)
            .await;

        Ok(UserplaneSession {
            uplink_gtp_teid: GtpTeid(teid),
            ue_ip_addr: IpAddr::V4(ue_ipv4_addr),
            qfi: 0,
        })
    }

    pub async fn commit_userplane_session(
        &self,
        session: &UserplaneSession,
        remote_tunnel_info: GtpTunnel,
        logger: &Logger,
    ) -> Result<()> {
        // TODO: Once we implement downlink buffering, could split this into a command that starts buffering downlink packets, and
        // then a second one that flushes the buffer (after the RRC Reconfiguration Complete).  Otherwise, the UE could
        // receive a packet before it has confirmed setup of the new DRB.
        let IpAddr::V4(ue_ipv4) = session.ue_ip_addr else {
            bail!("IPv6 not implemented");
        };
        info!(
            logger,
            "Set up userplane session {}, remote {}-{}",
            session,
            remote_tunnel_info.transport_layer_address,
            remote_tunnel_info.gtp_teid,
        );

        self.downlink_forwarding_table
            .add_rule(remote_tunnel_info, ue_ipv4)
            .await;

        Ok(())
    }

    pub async fn delete_userplane_session(&self, session: &UserplaneSession, logger: &Logger) {
        if let IpAddr::V4(ue_ipv4) = session.ue_ip_addr {
            self.downlink_forwarding_table.remove_rule(ue_ipv4).await;
        };
        self.uplink_forwarding_table
            .remove_rule(session.uplink_gtp_teid.0)
            .await;

        info!(logger, "Deleted userplane session {}", session);
    }
}

fn create_f1u_socket(local_ip: IpAddr, logger: &Logger) -> Result<std::net::UdpSocket> {
    let transport_address = SocketAddr::new(local_ip, GTPU_PORT);
    let domain = match local_ip {
        IpAddr::V4(_) => Domain::IPV4,
        IpAddr::V6(_) => Domain::IPV6,
    };
    ensure!(matches!(local_ip, IpAddr::V4(_)));

    // On the RAN side (F1-U reference point), we open a GTP UDP socket.
    let gtpu_socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    gtpu_socket.set_reuse_port(true)?;
    gtpu_socket
        .bind(&transport_address.into())
        .context(format!("Failed to bind {}", transport_address))?;
    info!(logger, "Serving GTP-U on {transport_address}");
    Ok(gtpu_socket.into())
}

// TODO: we probably don't need TunBuilder and can just open this synchronously
async fn open_n6_tun_device(tun_device_name: &str, logger: &Logger) -> Result<Tun> {
    match TunBuilder::new()
        .name(tun_device_name)
        .tap(false)
        .packet_info(false)
        .try_build()
        .await
    {
        Ok(tun) => {
            info!(logger, "Opened tun device '{tun_device_name}' for N6");
            Ok(tun)
        }
        Err(e) => bail!(
            "Failed to open TUN device '{tun_device_name}' - have you followed the instructions in the QCore readme?  
Device open eError code: {e}
 EPERM: may indicate that the device doesn't exist or is not owned by the current user
 EINVAL: may indicate that the device is actually a tap device rather than a tun device
 EBUSY: another process, e.g. another qcore instance, has the device open"
        ),
    }
}
