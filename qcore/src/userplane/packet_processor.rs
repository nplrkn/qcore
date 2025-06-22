#![allow(clippy::unusual_byte_groupings)]
use super::stats::dump_stats;
//use super::aya_log::EbpfLogger;
use super::MAX_UES;
use crate::UserplaneSession;
use crate::data::PdcpSequenceNumberLength;
use anyhow::{Result, anyhow, bail, ensure};
use async_std::{net::IpAddr, sync::Mutex};
use aya::maps::{Array, MapData, PerCpuArray};
use aya::programs::{SchedClassifier, TcAttachType, tc};
use aya::{Ebpf, EbpfLoader};
use ebpf_common::*;
use index_pool::IndexPool;
use libc::if_nametoindex;
use rand::RngCore;
use slog::{Logger, info, warn};
use std::ffi::CString;
use std::net::Ipv4Addr;
use std::sync::Arc;
use xxap::GtpTeid;

#[derive(Clone)]
pub struct PacketProcessor {
    index_pool: Arc<Mutex<IndexPool>>,
    ue_subnet: Ipv4Addr,
    uplink_forwarding_table: Arc<Mutex<UplinkForwardingTable>>,
    downlink_forwarding_table: Arc<Mutex<DownlinkForwardingTable>>,
}

type UplinkForwardingTable = Array<MapData, UlForwardingEntry>;
type DownlinkForwardingTable = Array<MapData, DlForwardingEntry>;

impl PacketProcessor {
    pub async fn new(ue_subnet: Ipv4Addr, ebpf: &mut Ebpf, logger: &Logger) -> Result<Self> {
        let mut index_pool = IndexPool::new();
        // Take the 0 slot, so that the first UE gets an IP address ending in .1.
        let _ = index_pool.request_id(0);
        let index_pool = Arc::new(Mutex::new(index_pool));

        let counters = PerCpuArray::try_from(ebpf.take_map("COUNTERS").unwrap())?;
        let ul_forwarding_table = Array::try_from(ebpf.take_map("UL_FORWARDING_TABLE").unwrap())?;
        let dl_forwarding_table = Array::try_from(ebpf.take_map("DL_FORWARDING_TABLE").unwrap())?;

        // Spawn the stats task
        let _stats_task = async_std::task::spawn(dump_stats(logger.clone(), counters));

        Ok(PacketProcessor {
            index_pool,
            ue_subnet,
            uplink_forwarding_table: Arc::new(Mutex::new(ul_forwarding_table)),
            downlink_forwarding_table: Arc::new(Mutex::new(dl_forwarding_table)),
        })
    }

    pub fn install_ebpf(
        ngap_mode: bool,
        local_ip: IpAddr,
        f1u_if_name: &str,
        n6_if_name: &str,
        tun_if_name: &str,
        _logger: &Logger,
    ) -> Result<Ebpf> {
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

        let (uplink_program, downlink_program) = if ngap_mode {
            ("tc_uplink_n3", "tc_downlink_n3")
        } else {
            ("tc_uplink_f1u", "tc_downlink_f1u")
        };

        let _ = tc::qdisc_add_clsact(f1u_if_name);
        let program: &mut SchedClassifier = ebpf.program_mut(uplink_program).unwrap().try_into()?;
        program.load()?;
        program.attach(f1u_if_name, TcAttachType::Ingress)?;

        let _ = tc::qdisc_add_clsact(n6_if_name);
        let program: &mut SchedClassifier =
            ebpf.program_mut(downlink_program).unwrap().try_into()?;
        program.load()?;
        program.attach(n6_if_name, TcAttachType::Ingress)?;

        Ok(ebpf)
    }

    pub async fn reserve_userplane_session(
        &self,
        five_qi: u8,
        pdcp_sn_length: PdcpSequenceNumberLength,
        _logger: &Logger,
    ) -> Result<UserplaneSession> {
        let idx = self.index_pool.lock().await.new_id();
        ensure!(idx < MAX_UES, "No more slots available");
        let idx = idx as u8;

        // Randomize the top part of the TEID.  It is meant to be unpredictable.
        let mut teid = (idx as u32).to_be_bytes();
        rand::rng().fill_bytes(&mut teid[0..3]);
        teid[3] = idx as u8;

        // Generate a UE IP.  We currently hardcode assumptions of 1 PDU session
        // per UE, and max 254 UEs.
        let mut ue_addr_octets = self.ue_subnet.octets();
        ue_addr_octets[3] = idx;
        let ue_ipv4_addr = Ipv4Addr::from(ue_addr_octets);

        let pdcp_header_length = match pdcp_sn_length {
            PdcpSequenceNumberLength::TwelveBits => 2,
            PdcpSequenceNumberLength::EighteenBits => 3,
        };

        let v = UlForwardingEntry {
            teid_top_bytes: teid[0..3].try_into().unwrap(),
            pdcp_header_length,
        };
        let mut array = self.uplink_forwarding_table.lock().await;
        array.set(idx as u32, v, 0)?;

        Ok(UserplaneSession {
            uplink_gtp_teid: GtpTeid(teid),
            ue_ip_addr: IpAddr::V4(ue_ipv4_addr),
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
        let remote_tunnel_info = session
            .remote_tunnel_info
            .clone()
            .ok_or(anyhow!("Missing tunnel info"))?;

        info!(
            logger,
            "Set up userplane session {}, remote {}-{}, 5QI={}, sn-length={}",
            session,
            remote_tunnel_info.transport_layer_address,
            remote_tunnel_info.gtp_teid,
            session.five_qi,
            session.pdcp_sn_length
        );

        // TODO: Once we implement downlink buffering, could split this into a command that starts buffering downlink packets, and
        // then a second one that flushes the buffer (after the RRC Reconfiguration Complete).  Otherwise, the UE could
        // receive a packet before it has confirmed setup of the new DRB.

        let IpAddr::V4(ue_ipv4) = session.ue_ip_addr else {
            bail!("IPv6 not implemented for UE");
        };
        let gtp_remote_ip: IpAddr = remote_tunnel_info.transport_layer_address.try_into()?;
        let IpAddr::V4(gtp_remote_ipv4) = gtp_remote_ip else {
            bail!("IPv6 not implemented for GTP");
        };

        // We use the least significant byte of the UE address as the index.
        let idx = ue_ipv4.octets()[3];

        let pdcp_header_length = match session.pdcp_sn_length {
            PdcpSequenceNumberLength::TwelveBits => 2,
            PdcpSequenceNumberLength::EighteenBits => 3,
        };

        let v = DlForwardingEntry {
            next_pdcp_seq_num: 0,
            next_nr_seq_num: 0,
            teid: u32::from_be_bytes(remote_tunnel_info.gtp_teid.0),
            remote_gtp_addr: u32::from_be_bytes(gtp_remote_ipv4.octets()),
            pdcp_header_length,
        };
        let mut array = self.downlink_forwarding_table.lock().await;
        if let Err(e) = array.set(idx as u32, v, 0) {
            warn!(
                logger,
                "Error storing downlink forwarding entry {} - {}", idx, e
            )
        }

        Ok(())
    }

    pub async fn delete_userplane_session(&self, session: &UserplaneSession, logger: &Logger) {
        let idx = session.uplink_gtp_teid.0[3] as u32;

        if let Err(e) = self.index_pool.lock().await.return_id(idx as usize) {
            warn!(logger, "Error returning UE index {} - {}", idx, e)
        }

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

        info!(logger, "Deleted userplane session {}", session);
    }
}

fn get_if_index(interface_name: &str) -> Result<u32> {
    let c_str_if_name = CString::new(interface_name)?;
    let c_if_name = c_str_if_name.as_ptr();
    let if_index = unsafe { if_nametoindex(c_if_name) };
    if if_index == 0 {
        bail!(
            "Interface {} does not exist - did you run the setup-routing script?",
            interface_name
        )
    }
    Ok(if_index)
}
