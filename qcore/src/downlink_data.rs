use anyhow::{Result, bail};
use async_std::{
    io::{ReadExt, WriteExt},
    sync::Mutex,
    task::JoinHandle,
};
use async_trait::async_trait;
use async_tun::{Tun, TunBuilder};
use std::{net::IpAddr, sync::Arc};

use crate::data::UePagingInfo;

#[async_trait]
pub trait DlBufferBase: Send + Sync + 'static {
    async fn page_ue(&self, paging_info: &UePagingInfo);
}

#[derive(Default, Clone)]
pub struct UeInfo {
    paging_info: UePagingInfo,
    queued_packet: Option<Vec<u8>>,
}

struct DownlinkBufferTask<T: DlBufferBase> {
    base: T,
    ues: Arc<Vec<Mutex<UeInfo>>>,
}

#[derive(Clone)]
pub struct DownlinkBuffer {
    ues: Arc<Vec<Mutex<UeInfo>>>,
    tun: Arc<Tun>,
}

impl DownlinkBuffer {
    pub async fn new(n6_tun_device_name: &str) -> Result<Self> {
        let tun = match TunBuilder::new()
            .name(n6_tun_device_name)
            .packet_info(false)
            .try_build()
            .await
        {
            Ok(t) => t,
            Err(e) => bail!("Failed to open {n6_tun_device_name} - {e}"),
        };

        let mut v = Vec::new();
        for _ in 0..255 {
            v.push(Mutex::new(UeInfo::default()))
        }

        Ok(DownlinkBuffer {
            ues: Arc::new(v),
            tun: Arc::new(tun),
        })
    }

    pub fn run<T: DlBufferBase>(&self, base: T) -> JoinHandle<()> {
        let mut dl_buffer = DownlinkBufferTask {
            base,
            ues: self.ues.clone(),
        };
        let tun_clone = self.tun.clone();
        async_std::task::spawn(async move {
            while dl_buffer
                .handle_next_downlink_packet(&tun_clone)
                .await
                .is_ok()
            {}
        })
    }

    pub async fn deactivate_ip(&self, ue_ip_address: &IpAddr, paging_info: &UePagingInfo) {
        let ue_index = ue_index(ue_ip_address);

        // critical section
        self.ues[ue_index as usize].lock().await.paging_info = paging_info.clone();
        // end critical section
    }

    pub async fn reactivate_ip(&self, ue_ip_address: &IpAddr) -> Result<()> {
        let ue_index = ue_index(ue_ip_address);

        // critical section
        let mut slot = self.ues[ue_index as usize].lock().await;
        let packet = slot.queued_packet.take();
        slot.paging_info.tmsi = [0, 0, 0, 0];
        // end critical section

        if let Some(packet) = packet {
            let _written = self.tun.writer().write(&packet).await?;

            println!("Sent downlink packet wrote {_written} bytes");
        }
        Ok(())
    }
}

fn ue_index(ue_ip_address: &IpAddr) -> u8 {
    match ue_ip_address {
        IpAddr::V4(ip) => ip.octets()[3],
        IpAddr::V6(ip) => ip.octets()[15],
    }
}

const MTU: usize = 1500;
impl<T: DlBufferBase> DownlinkBufferTask<T> {
    async fn handle_next_downlink_packet(&mut self, tun: &Tun) -> Result<()> {
        let mut v = vec![0u8; MTU];
        let bytes_read = tun.reader().read(&mut v).await?;

        if bytes_read < 19 {
            // TODO counter
            return Ok(());
        }
        v.resize(bytes_read, 0);

        // We use the least significant byte of the UE address as the index.
        let ue_ip_addr = &v.as_slice()[16..20];
        let ue_index = ue_ip_addr[3] as usize;

        // critical section
        let mut slot = self.ues[ue_index].lock().await;
        if slot.paging_info.tmsi == [0, 0, 0, 0] {
            // TODO should we write this back again?
            // Is there a danger of a infinite loop?  counter to prevent?
            // Timing window where packet is punted up simultaneously with reactivate_ip()
            return Ok(());
        }

        // We need to page the UE if not done already, i.e. if we are not already
        // storing a packet for it.
        let paging_needed = if slot.queued_packet.is_none() {
            Some(slot.paging_info.clone())
        } else {
            None
        };
        slot.queued_packet = Some(v);
        // end of critical section

        if let Some(paging_info) = paging_needed {
            self.base.page_ue(&paging_info).await
        }

        Ok(())
    }
}
