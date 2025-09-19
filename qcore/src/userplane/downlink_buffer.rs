use crate::{data::UePagingInfo, userplane::MAX_UES};
use anyhow::{Result, bail};
use async_std::{
    fs::File,
    io::{ReadExt, WriteExt},
    sync::Mutex,
    task::JoinHandle,
};
use async_trait::async_trait;
use async_tun::{Tun, TunBuilder};
use std::{
    net::IpAddr,
    os::fd::{AsRawFd, FromRawFd},
    sync::Arc,
};

#[async_trait]
pub trait PagingApi: Send + Sync + 'static {
    async fn page_ue(&self, paging_info: &UePagingInfo);
}

#[derive(Default, Clone)]
pub struct UeInfo {
    paging_info: UePagingInfo,
    queued_packet: Option<Vec<u8>>,
}

struct DownlinkBufferTask<T: PagingApi> {
    paging_provider: T,
    ues: Arc<Vec<Mutex<UeInfo>>>,
}

#[derive(Clone)]
pub struct DownlinkBufferController {
    ues: Arc<Vec<Mutex<UeInfo>>>,
    tun: Arc<Tun>,
}

impl DownlinkBufferController {
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

        Ok(DownlinkBufferController {
            ues: Arc::new(v),
            tun: Arc::new(tun),
        })
    }

    pub fn run<T: PagingApi>(&self, paging_provider: T) -> JoinHandle<()> {
        let mut dl_buffer = DownlinkBufferTask {
            paging_provider,
            ues: self.ues.clone(),
        };

        // TODO: surely there is a better way?
        // If we just clone the tun and use its reader(), then reactivate_ip()
        // hangs on writer.flush().  Presumably because a single File with a pending read
        // has its internal lock taken out and so can't also flush.
        let mut file = unsafe { File::from_raw_fd(self.tun.as_raw_fd()) };

        async_std::task::spawn(async move {
            while dl_buffer
                .handle_next_downlink_packet(&mut file)
                .await
                .is_ok()
            {}

            // The fd is actually owned by the Arc<Tun> in self so we must not free it if
            // the task below exits.
            std::mem::forget(file);
        })
    }

    pub async fn deactivate_ip(&self, ue_ip_address: &IpAddr, paging_info: &UePagingInfo) {
        if let Ok(ue_index) = ue_index(ue_ip_address) {
            // critical section
            self.ues[ue_index as usize].lock().await.paging_info = paging_info.clone();
            // end critical section
        }
    }

    // Returns true if there was a buffered packet.
    pub async fn reactivate_ip(&self, ue_ip_address: &IpAddr) -> Result<bool> {
        let ue_index = ue_index(ue_ip_address)?;

        // critical section
        let mut slot = self.ues[ue_index as usize].lock().await;
        let packet = slot.queued_packet.take();
        slot.paging_info.tmsi = [0, 0, 0, 0];
        // end critical section

        if let Some(packet) = packet {
            let mut writer = self.tun.writer();
            let _written = writer.write(&packet).await?;
            writer.flush().await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

fn ue_index(ue_ip_address: &IpAddr) -> Result<u8> {
    let idx = match ue_ip_address {
        IpAddr::V4(ip) => ip.octets()[3],
        IpAddr::V6(ip) => ip.octets()[15],
    };
    if (idx as usize) < MAX_UES {
        Ok(idx)
    } else {
        bail!("UE index {} out of range", idx)
    }
}

const MTU: usize = 1500;
impl<T: PagingApi> DownlinkBufferTask<T> {
    async fn handle_next_downlink_packet(&mut self, file: &mut File) -> Result<()> {
        let mut v = vec![0u8; MTU];
        let bytes_read = file.read(&mut v).await?;

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
            self.paging_provider.page_ue(&paging_info).await
        }

        Ok(())
    }
}
