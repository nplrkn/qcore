#![allow(clippy::unusual_byte_groupings)]
use super::downlink_pipeline::DownlinkCounters;
use super::uplink_pipeline::UplinkCounters;
use super::{
    DownlinkForwardingTable, DownlinkPipeline, GTPU_PORT, MAX_UES, UplinkForwardingTable,
    UplinkPipeline,
};
use crate::UserplaneSession;
use anyhow::{Context, Result, bail, ensure};
use async_std::{fs::File, net::IpAddr, sync::Mutex};
use async_tun::{Tun, TunBuilder};
use atomic_counter::AtomicCounter;
use index_pool::IndexPool;
use rand::RngCore;
use slog::{Logger, info, warn};
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
        let downlink_counters = Arc::new(DownlinkCounters::default());
        let downlink_pipeline = DownlinkPipeline::new(
            f1u_socket.into(),
            n6_tun,
            downlink_forwarding_table.clone(),
            downlink_counters.clone(),
        );
        let _downlink_task = downlink_pipeline.run();

        // Start the uplink pipeline (F1U -> N6).
        let uplink_counters = Arc::new(UplinkCounters::default());
        let uplink_pipeline = UplinkPipeline::new(
            f1u_socket_clone.into(),
            n6_tun_clone,
            uplink_forwarding_table.clone(),
            uplink_counters.clone(),
        );
        let _uplink_task = uplink_pipeline.run(logger.clone());

        let mut index_pool = IndexPool::new();
        // Take the 0 slot, so that the first UE gets an IP address ending in .1.
        let _ = index_pool.request_id(0);
        let index_pool = Arc::new(Mutex::new(index_pool));

        // Spawn the stats task
        let _stats_task = async_std::task::spawn(dump_stats(
            logger.clone(),
            downlink_counters,
            uplink_counters,
        ));

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

use super::downlink_pipeline::downlink_counter_indices::*;
use super::uplink_pipeline::uplink_counter_indices::*;

async fn dump_stats(logger: Logger, dl: Arc<DownlinkCounters>, ul: Arc<UplinkCounters>) {
    let mut last_dl = [0usize; DL_NUM_COUNTERS];
    let mut last_ul = [0usize; UL_NUM_COUNTERS];
    const FIRST_DL_WARN_IDX: usize = DL_DROP_TOO_SHORT;
    const FIRST_UL_WARN_IDX: usize = UL_DROP_TOO_SHORT;

    loop {
        async_std::task::sleep(std::time::Duration::new(5, 0)).await;

        if dl[DL_RX_PKTS].get() != last_dl[DL_RX_PKTS]
            || ul[UL_RX_PKTS].get() != last_ul[UL_RX_PKTS]
        {
            last_dl[DL_RX_PKTS] = dl[DL_RX_PKTS].get();
            last_dl[DL_RX_BYTES] = dl[DL_RX_BYTES].get();
            last_ul[UL_RX_PKTS] = ul[UL_RX_PKTS].get();
            last_ul[UL_RX_BYTES] = ul[UL_RX_BYTES].get();

            info!(
                &logger,
                "DL pkts={} bytes={} UL pkts={} bytes={} ",
                last_dl[DL_RX_PKTS],
                last_dl[DL_RX_BYTES],
                last_ul[UL_RX_PKTS],
                last_ul[UL_RX_BYTES]
            );
        }

        let mut dl_warn_needed = false;
        for idx in FIRST_DL_WARN_IDX..DL_NUM_COUNTERS {
            if last_dl[idx] != dl[idx].get() {
                dl_warn_needed = true;
            }
            last_dl[idx] = dl[idx].get();
        }
        let mut ul_warn_needed = false;
        for idx in FIRST_UL_WARN_IDX..UL_NUM_COUNTERS {
            if last_ul[idx] != ul[idx].get() {
                ul_warn_needed = true;
            }
            last_ul[idx] = ul[idx].get();
        }

        if dl_warn_needed {
            warn!(
                &logger,
                "DL DROPS too_short={} bad_ip={}",
                last_dl[DL_DROP_TOO_SHORT],
                last_dl[DL_DROP_UNKNOWN_IP_1] + last_dl[DL_DROP_UNKNOWN_IP_2]
            );
        }

        if ul_warn_needed {
            warn!(
                &logger,
                "UL DROPS too_short={} gtp_type={} too_short_ext={} pdcp_ctrl={} sdap_ctrl={} ip_type={} bad_teid={}",
                last_ul[UL_DROP_TOO_SHORT],
                last_ul[UL_DROP_GTP_MESSAGE_TYPE],
                last_ul[UL_DROP_TOO_SHORT_EXT],
                last_ul[UL_DROP_PDCP_CONTROL],
                last_ul[UL_DROP_SDAP_CONTROL],
                last_ul[UL_DROP_NOT_IPV4],
                last_ul[UL_DROP_UNKNOWN_TEID_1] + last_ul[UL_DROP_UNKNOWN_TEID_2]
            );
        }
    }
}
