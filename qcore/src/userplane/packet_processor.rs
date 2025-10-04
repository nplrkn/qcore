#![allow(clippy::unusual_byte_groupings)]
use super::MAX_UES;
//use super::aya_log::EbpfLogger;
use super::stats::dump_stats;
use crate::UserplaneSession;
use crate::data::{
    EthernetSesssionParams, Ipv4SessionParams, Payload, PdcpSequenceNumberLength,
    UeIpAllocationConfig,
};
use crate::userplane::get_if_index;
use crate::userplane::ue_ip_allocator::UeIpAllocator;
use anyhow::{Result, bail, ensure};
use async_std::{net::IpAddr, sync::Mutex};
use aya::maps::{Array, MapData, PerCpuArray};
use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags, tc};
use aya::{Ebpf, EbpfLoader};
use ebpf_common::*;
use index_pool::IndexPool;
use rand::RngCore;
use slog::{Logger, info, warn};
use std::sync::Arc;
use xxap::GtpTeid;

#[derive(Clone)]
pub struct PacketProcessor {
    index_pool: Arc<Mutex<IndexPool>>,
    uplink_forwarding_table: Arc<Mutex<UplinkForwardingTable>>,
    downlink_forwarding_table: Arc<Mutex<DownlinkForwardingTable>>,
    eth_if_index_lookup_table: Arc<Mutex<EthIndexLookupTable>>,
    pub ue_ip_allocator: UeIpAllocator,

    // This is a list of available ethernet interface indices for ethernet
    // PDU sessions.  When an ethernet session is allocated, we pop an
    // item out of this list, and, when it is freed, we put it back.
    ethernet_interface_indices: Arc<Mutex<InterfaceIndices>>,
}

type UplinkForwardingTable = Array<MapData, UlForwardingEntry>;
type DownlinkForwardingTable = Array<MapData, DlForwardingEntry>;
type EthIndexLookupTable = Array<MapData, u16>;
type InterfaceIndices = Vec<u32>;

impl PacketProcessor {
    pub fn install_ebpf(
        ngap_mode: bool,
        local_ip: IpAddr,
        ran_if_name: &str,
        n6_if_name: &str,
        tun_if_name: &str,
        logger: &Logger,
    ) -> Result<(Ebpf, InterfaceIndices)> {
        let gtpu_local_ipv4 = match local_ip {
            IpAddr::V4(addr) => addr.octets(),
            _ => bail!("Ipv6 not supported"),
        };

        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        // let rlim = libc::rlimit {
        //     rlim_cur: libc::RLIM_INFINITY,
        //     rlim_max: libc::RLIM_INFINITY,
        // };
        // let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        // if ret != 0 {
        //     warn!(
        //         &logger,
        //         "remove limit on locked memory failed, ret is: {ret}"
        //     );
        // }

        let tun_if_index = get_if_index(tun_if_name)?;

        let data = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/ebpf-userplane-program"));
        let mut ebpf = EbpfLoader::new()
            .set_global("GTPU_LOCAL_IPV4", &gtpu_local_ipv4, true)
            .set_global("TUN_IF_INDEX", &tun_if_index, true)
            .load(data)?;

        // if let Err(e) = EbpfLogger::init_with_logger(&mut ebpf, logger.clone()) {
        //     warn!(logger, "failed to initialize eBPF logger: {e}");
        // }

        let (uplink_program, ip_downlink_program) = if ngap_mode {
            ("xdp_uplink_n3", "tc_downlink_n3")
        } else {
            ("xdp_uplink_f1u", "tc_downlink_f1u")
        };

        // XDP uplink program.
        let program: &mut Xdp = ebpf.program_mut(uplink_program).unwrap().try_into()?;
        program.load()?;
        program.attach(ran_if_name, XdpFlags::default())?;

        // TC uplink redirect program.   The XDP uplink program passes IP packets through to this.
        let _ = tc::qdisc_add_clsact(ran_if_name);
        let tc_uplink_program: &mut SchedClassifier =
            ebpf.program_mut("tc_uplink_redirect").unwrap().try_into()?;
        tc_uplink_program.load()?;
        tc_uplink_program.attach(ran_if_name, TcAttachType::Ingress)?;

        // TC downlink program
        let tc_ip_downlink_program: &mut SchedClassifier =
            ebpf.program_mut(ip_downlink_program).unwrap().try_into()?;
        tc_ip_downlink_program.load()?;

        let _ = tc::qdisc_add_clsact(n6_if_name);
        tc_ip_downlink_program.attach(n6_if_name, TcAttachType::Ingress)?;

        // XDP and TC downlink eth programs get attached to every UE ethernet interface.
        // At the same time, we build up a list of inteface indices to allocate to ethernet PDU sessions.
        let tc_downlink_eth_program: &mut SchedClassifier = ebpf
            .program_mut("tc_downlink_eth_redirect")
            .unwrap()
            .try_into()?;
        tc_downlink_eth_program.load()?;

        let mut ethernet_session_if_indices = vec![];
        for ue_id in 1..MAX_UES {
            let eth_interface_name = format!("veth_ue_{}_a", ue_id);

            let Ok(if_index) = get_if_index(&eth_interface_name) else {
                // Stop looking after the first failure.  In other words, we can't support
                // gaps in the naming (e.g. 'veth_ue_2_a' won't get picked up unless 'veth_ue_1_a'
                // is visible in our network namespace).
                break;
            };

            // Attach the TC program.
            let _ = tc::qdisc_add_clsact(&eth_interface_name);
            tc_downlink_eth_program.attach(&eth_interface_name, TcAttachType::Ingress)?;

            ethernet_session_if_indices.push(if_index);
        }

        // Go back through the interface again, attaching the XDP program.
        let xdp_downlink_eth_program: &mut Xdp = ebpf
            .program_mut("xdp_downlink_n3_eth")
            .unwrap()
            .try_into()?;
        xdp_downlink_eth_program.load()?;
        for if_index in &ethernet_session_if_indices {
            xdp_downlink_eth_program.attach_to_if_index(*if_index, XdpFlags::default())?;
        }

        info!(
            logger,
            "Found {} ethernet devices to use for Ethernet PDU sessions",
            ethernet_session_if_indices.len()
        );

        Ok((ebpf, ethernet_session_if_indices))
    }

    pub async fn new(
        ue_ip_allocation_config: UeIpAllocationConfig,
        ebpf: &mut Ebpf,
        userplane_stats: bool,
        if_indices: InterfaceIndices,
        logger: &Logger,
    ) -> Result<Self> {
        let mut index_pool = IndexPool::new();
        // Take the 0 and 1 slots, so that the first UE gets an IP address ending in .2.
        let _ = index_pool.request_id(0);
        let _ = index_pool.request_id(1);
        let index_pool = Arc::new(Mutex::new(index_pool));

        let counters = PerCpuArray::try_from(ebpf.take_map("COUNTERS").unwrap())?;
        let ul_forwarding_table = Array::try_from(ebpf.take_map("UL_FORWARDING_TABLE").unwrap())?;
        let dl_forwarding_table = Array::try_from(ebpf.take_map("DL_FORWARDING_TABLE").unwrap())?;
        let eth_index_lookup_table =
            Array::try_from(ebpf.take_map("DL_ETH_IF_INDEX_LOOKUP").unwrap())?;

        // Spawn the stats task
        if userplane_stats {
            let _stats_task = async_std::task::spawn(dump_stats(logger.clone(), counters));
        }

        // TODO: don't hardcode name
        let ue_network_if_index = get_if_index("veth0")?;
        let ue_ip_allocator =
            UeIpAllocator::new(ue_network_if_index, ue_ip_allocation_config, logger).await?;

        Ok(PacketProcessor {
            index_pool,
            uplink_forwarding_table: Arc::new(Mutex::new(ul_forwarding_table)),
            downlink_forwarding_table: Arc::new(Mutex::new(dl_forwarding_table)),
            eth_if_index_lookup_table: Arc::new(Mutex::new(eth_index_lookup_table)),
            ethernet_interface_indices: Arc::new(Mutex::new(if_indices)),
            ue_ip_allocator,
        })
    }

    /// Allocates a userplane session including TEID.
    /// If `ipv4`` is true, allocates an IPv4 PDU session, otherwise an Ethernet PDU session.
    pub async fn allocate_userplane_session(
        &self,
        five_qi: u8,
        pdcp_sn_length: PdcpSequenceNumberLength,
        ipv4: bool,
        ue_dhcp_identifier: Vec<u8>,
        logger: &Logger,
    ) -> Result<UserplaneSession> {
        // Allocate a UE index
        let idx = self.index_pool.lock().await.new_id();
        ensure!(idx < MAX_UES, "No more slots available");
        let idx = idx as u8;

        // Create a TEID - randomized, since it is meant to be unpredictable.
        let mut teid = (idx as u32).to_be_bytes();
        rand::rng().fill_bytes(&mut teid[0..3]);
        teid[3] = idx as u8;

        let payload = if ipv4 {
            // Get an IP address for the UE
            let ue_ip_addr = self
                .ue_ip_allocator
                .allocate(idx, ue_dhcp_identifier, logger)
                .await?;

            Payload::Ipv4(Ipv4SessionParams { ue_ip_addr })
        } else {
            // Allocate a spare Ethernet interface.
            let Some(if_index) = self.ethernet_interface_indices.lock().await.pop() else {
                bail!("No Ethernet interfaces currently available")
            };
            Payload::Ethernet(EthernetSesssionParams { if_index })
        };

        Ok(UserplaneSession {
            uplink_gtp_teid: GtpTeid(teid),
            payload,
            qfi: 1,
            five_qi,
            pdcp_sn_length,
            remote_tunnel_info: None,
        })
    }

    pub async fn commit_userplane_session(
        &self,
        session: &UserplaneSession,
        logger: &Logger,
    ) -> Result<()> {
        let Some(remote_tunnel_info) = session.remote_tunnel_info.clone() else {
            bail!("Missing tunnel info");
        };

        info!(
            logger,
            "Activate userplane session {}, local teid {:08}, remote {}-{:08}, 5QI={}",
            session.payload,
            session.uplink_gtp_teid,
            remote_tunnel_info.transport_layer_address,
            remote_tunnel_info.gtp_teid,
            session.five_qi,
        );

        let pdcp_header_length = match session.pdcp_sn_length {
            PdcpSequenceNumberLength::TwelveBits => 2,
            PdcpSequenceNumberLength::EighteenBits => 3,
        };

        let eth_if_idx = match session.payload {
            Payload::Ethernet(EthernetSesssionParams { if_index }) => if_index,
            _ => 0,
        };

        // Program the uplink pipeline.

        // We use the least significant byte of the TEID as the uplink forwarding table index.
        let uplink_forwarding_idx = session.uplink_gtp_teid.0[3];

        let v = UlForwardingEntry {
            teid_top_bytes: session.uplink_gtp_teid.0[0..3].try_into().unwrap(),
            pdcp_header_length,
            egress_if_index: eth_if_idx,
        };
        let mut array = self.uplink_forwarding_table.lock().await;
        array.set(uplink_forwarding_idx as u32, v, 0)?;

        // Program the downlink pipeline.

        // For IP, we use the low byte of the IP address as the index.  Otherwise we will indirect
        // via the ethernet if index lookup and we can just reuse the uplink idx.
        let downlink_forwarding_idx =
            if let Payload::Ipv4(Ipv4SessionParams { ue_ip_addr }) = session.payload {
                ue_ip_addr.octets()[3]
            } else {
                uplink_forwarding_idx
            };

        let gtp_remote_ip: IpAddr = remote_tunnel_info.transport_layer_address.try_into()?;
        let IpAddr::V4(gtp_remote_ipv4) = gtp_remote_ip else {
            bail!("IPv6 not implemented for GTP");
        };
        let remote_gtp_addr = u32::from_be_bytes(gtp_remote_ipv4.octets());
        // TODO: broaden this to check for more invalid addresses.
        ensure!(
            remote_gtp_addr != 0xffffffff,
            "All 1s address not allowed for remote GTP address"
        );

        let v = DlForwardingEntry {
            next_pdcp_seq_num: 0,
            next_nr_seq_num: 0,
            teid: u32::from_be_bytes(remote_tunnel_info.gtp_teid.0),
            remote_gtp_addr,
            pdcp_header_length,
        };
        let mut array = self.downlink_forwarding_table.lock().await;
        if let Err(e) = array.set(downlink_forwarding_idx as u32, v, 0) {
            warn!(
                logger,
                "Failed to set downlink forwarding {} - {}", downlink_forwarding_idx, e
            )
        }

        // For an Ethernet PDU session, set up the interface lookup table to point to the forwarding table entry.
        if eth_if_idx != 0 {
            let mut array = self.eth_if_index_lookup_table.lock().await;
            if let Err(e) = array.set(eth_if_idx, downlink_forwarding_idx as u16, 0) {
                warn!(logger, "Failed to set eth lookup {} - {}", eth_if_idx, e)
            }
        }

        Ok(())
    }

    // Deactivating the userplane session returns it to the reserved state.  It can be
    // reactivated by calling commit_userplane_session().
    // Currently, the local TEID of the session is retained across de/reactivation.
    pub async fn deactivate_userplane_session(&self, session: &UserplaneSession, logger: &Logger) {
        let idx = session.uplink_gtp_teid.0[3] as u32;

        let mut array = self.downlink_forwarding_table.lock().await;
        if let Err(e) = array.set(idx, DlForwardingEntry::deactivated(), 0) {
            warn!(
                logger,
                "Error deactivating downlink forwarding entry {} - {}", idx, e
            )
        }
        info!(logger, "Deactivated userplane session {}", session);
    }

    pub async fn delete_userplane_session(&self, session: &UserplaneSession, logger: &Logger) {
        info!(logger, "Delete userplane session {}", session.payload);
        let idx = session.uplink_gtp_teid.0[3] as u32;
        self.clear_forwarding_entries(idx, logger).await;

        // Note there is no 'linger' function right now, so there might be timing windows
        // where a new UE session could immediately obtain the IP address / ethernet link of whatever old UE
        // session we are deleting here and potentially receive and receive the final packets on the old session.
        match session.payload {
            Payload::Ethernet(EthernetSesssionParams { if_index }) => {
                // Return the ethernet interface index to the pool of available indices.
                self.ethernet_interface_indices.lock().await.push(if_index);
            }
            Payload::Ipv4(Ipv4SessionParams { ue_ip_addr }) => {
                self.ue_ip_allocator.release(ue_ip_addr, logger).await
            }
        }

        if let Err(e) = self.index_pool.lock().await.return_id(idx as usize) {
            warn!(logger, "Error returning UE index {} - {}", idx, e)
        }
    }

    async fn clear_forwarding_entries(&self, idx: u32, logger: &Logger) {
        let mut array = self.downlink_forwarding_table.lock().await;
        if let Err(e) = array.set(idx, DlForwardingEntry::default(), 0) {
            warn!(
                logger,
                "Error clearing downlink forwarding entry {} - {}", idx, e
            )
        }

        let mut array = self.uplink_forwarding_table.lock().await;
        if let Err(e) = array.set(idx, UlForwardingEntry::default(), 0) {
            warn!(
                logger,
                "Error clearing uplink forwarding entry {} - {}", idx, e
            )
        }
    }
}
