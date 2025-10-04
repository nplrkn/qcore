use super::{DataNetwork, MockDu, MockUe};
use crate::{MockGnb, UeBuilder, mock_ue::Transport};
use anyhow::{Result, bail};
use pnet_base::MacAddr;
use qcore::{
    AmfIds, Config, NetworkDisplayName, PdcpSequenceNumberLength, ProgramHandle, QCore,
    SubscriberAuthParams, SubscriberDb, UeIpAllocationConfig, get_if_index,
};
use slog::{Drain, Logger, o};
use std::{
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use xxap::PlmnIdentity;

pub struct TestFrameworkBuilder<T> {
    logger: Logger,
    use_dhcp: Option<&'static str>,
    x: PhantomData<T>,
}

impl<T> TestFrameworkBuilder<T> {
    pub fn new() -> Self {
        Self {
            logger: init_logging(),
            use_dhcp: None,
            x: PhantomData,
        }
    }

    pub fn use_dhcp(mut self, if_name: &'static str) -> Self {
        self.use_dhcp = Some(if_name);
        self
    }

    async fn build_common(
        &self,
        ngap_mode: bool,
    ) -> Result<(ProgramHandle, DataNetwork, UeBuilder)> {
        exit_on_panic();
        let qc_ip = "127.0.0.1";
        let dn = DataNetwork::new(&self.logger).await?;
        let (subs, _) = SubscriberDb::new_from_sim_file("test_sims.toml", &self.logger)?;
        let mut config = qcore_default_test_config(qc_ip)?;
        if let Some(if_name) = &self.use_dhcp {
            let if_index = get_if_index(if_name)?;
            config.ip_allocation_method =
                UeIpAllocationConfig::Dhcp(if_index, Some(dn.dhcp_server().ip));
        }
        let qc = QCore::start(
            config,
            self.logger.new(o!("qcore"=> 1)),
            subs.clone(),
            ngap_mode,
            true,
        )
        .await?;

        let builder = UeBuilder::new(subs, *qc.ip_addr(), self.logger.clone());
        Ok((qc, dn, builder))
    }
}

impl<T> Default for TestFrameworkBuilder<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl TestFrameworkBuilder<MockDu> {
    pub async fn build(self) -> Result<(MockDu, ProgramHandle, DataNetwork, UeBuilder, Logger)> {
        let du_ip = "127.0.0.2";
        let mut du = MockDu::new(du_ip, &self.logger).await?;
        let (qc, dn, builder) = self.build_common(false).await?;
        du.perform_f1_setup(qc.ip_addr()).await?;
        Ok((du, qc, dn, builder, self.logger))
    }
}

impl TestFrameworkBuilder<MockGnb> {
    pub async fn build(self) -> Result<(MockGnb, ProgramHandle, DataNetwork, UeBuilder, Logger)> {
        let gnb_ip = "127.0.0.2";
        let mut gnb = MockGnb::new(gnb_ip, &self.logger).await?;
        let (qc, dn, builder) = self.build_common(true).await?;
        gnb.perform_ng_setup(qc.ip_addr()).await?;
        Ok((gnb, qc, dn, builder, self.logger))
    }
}

pub async fn init_f1ap() -> Result<(MockDu, ProgramHandle, DataNetwork, UeBuilder, Logger)> {
    TestFrameworkBuilder::<MockDu>::default().build().await
}

pub async fn init_ngap() -> Result<(MockGnb, ProgramHandle, DataNetwork, UeBuilder, Logger)> {
    TestFrameworkBuilder::<MockGnb>::default().build().await
}

pub async fn wait_until_idle(qc: &QCore) -> Result<()> {
    async_std::future::timeout(std::time::Duration::from_millis(500), qc.wait_until_idle()).await?;
    Ok(())
}

fn exit_on_panic() {
    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        orig_hook(panic_info);
        std::process::exit(1);
    }));
}

pub fn init_logging() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build();
    let drain = std::sync::Mutex::new(drain).fuse();
    let drain = slog_envlogger::new(drain);
    slog::Logger::root(drain, o!())
}

fn qcore_default_test_config(addr: &str) -> Result<Config> {
    Ok(Config {
        ip_addr: addr.parse()?,
        plmn: PlmnIdentity([0x00, 0xf1, 0x10]),
        amf_ids: AmfIds([0x01, 0x01, 0x00]),
        name: Some("QCore".to_string()),
        serving_network_name: "5G:mnc001.mcc001.3gppnetwork.org".to_string(),
        skip_ue_auts_check: true, // saves us having to implement AUTS signature in test framework
        sst: 1,
        ran_interface_name: "lo".to_string(),
        n6_interface_name: "veth1".to_string(),
        tun_interface_name: "qcoretun".to_string(),
        pdcp_sn_length: PdcpSequenceNumberLength::TwelveBits,
        five_qi: 7,
        network_display_name: NetworkDisplayName::new("QCoreTest")?,
        ip_allocation_method: UeIpAllocationConfig::RoutedUeSubnet(Ipv4Addr::new(10, 255, 0, 0)),
    })
}

pub async fn start_qcore(
    addr: &str,
    sub_db: SubscriberDb,
    logger: &Logger,
    ngap_mode: bool,
) -> Result<ProgramHandle> {
    QCore::start(
        qcore_default_test_config(addr)?,
        logger.new(o!("qcore"=> 1)),
        sub_db,
        ngap_mode,
        true,
    )
    .await
}

const TEST_UDP_PORT: u16 = 23215;

/// Send a downlink packet from the DN to an arbitrary UDP port on the UE.
pub async fn pass_through_downlink_ipv4<T: Transport>(
    dn: &DataNetwork,
    ue: &MockUe<T>,
) -> Result<()> {
    send_downlink_ipv4(dn, ue).await?;
    let _ip_packet = ue.recv_ue_data_packet().await?;
    Ok(())
}

pub async fn send_downlink_ipv4<T: Transport>(dn: &DataNetwork, ue: &MockUe<T>) -> Result<()> {
    dn.send_n6_udp_packet(SocketAddr::new(
        IpAddr::V4(ue.data.ipv4_addr),
        TEST_UDP_PORT,
    ))
    .await
}

pub async fn send_uplink_ipv4<T: Transport>(ue: &MockUe<T>, dn: &DataNetwork) -> Result<()> {
    let dst_udp_server = dn.udp_server_addr();
    let IpAddr::V4(dst_ip) = dst_udp_server.ip() else {
        bail!("Expected IPv4 address");
    };
    ue.send_userplane_udp(&dst_ip, TEST_UDP_PORT, dst_udp_server.port())
        .await
}

pub async fn send_uplink_ethernet_broadcast<T: Transport>(
    ue: &MockUe<T>,
    _dn: &DataNetwork,
) -> Result<()> {
    ue.send_userplane_ethernet_broadcast().await
}

pub async fn pass_through_uplink_ipv4<T: Transport>(
    ue: &MockUe<T>,
    dn: &DataNetwork,
) -> Result<()> {
    send_uplink_ipv4(ue, dn).await?;
    dn.receive_n6_udp_packet().await
}

pub async fn pass_through_uplink_ethernet_broadcast<T: Transport>(
    ue: &MockUe<T>,
    dn: &DataNetwork,
) -> Result<()> {
    send_uplink_ethernet_broadcast(ue, dn).await
    //dn.receive_n6_ethernet_broadcast().await
}

pub async fn pass_through_ue_to_ue_ipv4<T: Transport>(
    src_ue: &MockUe<T>,
    dst_ue: &MockUe<T>,
) -> Result<()> {
    src_ue
        .send_userplane_udp(&dst_ue.data.ipv4_addr, TEST_UDP_PORT, TEST_UDP_PORT)
        .await?;
    let _ip_packet = dst_ue.recv_ue_data_packet().await?;
    Ok(())
}

pub async fn pass_through_ue_to_ue_ethernet_unicast<T: Transport>(
    src_ue: &MockUe<T>,
    dst_ue: &MockUe<T>,
) -> Result<()> {
    let dst = MacAddr::new(2, 2, 2, 2, 2, 2);
    let src = MacAddr::new(2, 2, 2, 2, 2, 1);
    src_ue.send_userplane_ethernet_unicast(&src, &dst).await?;
    let _ethernet_packet = dst_ue.recv_ue_data_packet().await?;
    Ok(())
}

pub fn nth_imsi(n: usize, sub_db: &SubscriberDb) -> (String, SubscriberAuthParams) {
    sub_db
        .0
        .iter()
        .nth(n)
        .map(|(x, y)| (x.clone(), y.clone()))
        .unwrap()
}
