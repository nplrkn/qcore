use super::{DataNetwork, MockDu, MockUe};
use crate::{MockGnb, UeBuilder, mock_ue::Transport};
use anyhow::{Result, bail};
use pnet_base::MacAddr;
use qcore::{
    AmfIds, ClusterConfig, Config, DhcpConfig, NetworkDisplayName, PdcpSequenceNumberLength,
    ProgramHandle, QCore, SubscriberAuthParams, SubscriberDb, UeIpAllocationConfig,
};
use slog::{Drain, Logger, o};
use std::{
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use xxap::PlmnIdentity;

pub struct TestFrameworkBuilder<T> {
    logger: Logger,
    use_dhcp: bool,
    local_ip: Option<Ipv4Addr>,
    x: PhantomData<T>,
}

impl<T> TestFrameworkBuilder<T> {
    pub fn new() -> Self {
        Self {
            logger: init_logging(),
            use_dhcp: false,
            local_ip: None,
            x: PhantomData,
        }
    }

    pub fn use_dhcp(mut self) -> Self {
        self.use_dhcp = true;
        self
    }

    pub fn local_ip(mut self, ip: Ipv4Addr) -> Self {
        self.local_ip = Some(ip);
        self
    }

    async fn build_common(
        &self,
        ngap_mode: bool,
    ) -> Result<(ProgramHandle, DataNetwork, UeBuilder)> {
        exit_on_panic();
        let dn = DataNetwork::new(&self.logger).await?;
        let (subs, _) = SubscriberDb::new_from_sim_file("test_sims.toml", &self.logger)?;
        let dhcp_server = if self.use_dhcp {
            Some(dn.dhcp_server().ip)
        } else {
            None
        };

        let config = qcore_test_config(0, dhcp_server)?;

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
        let mut gnb = MockGnb::new(gnb_ip, self.logger.new(o!("gnb" => 1))).await?;
        let (qc, dn, builder) = self.build_common(true).await?;
        gnb.perform_ng_setup(qc.ip_addr()).await?;
        Ok((gnb, qc, dn, builder, self.logger))
    }

    pub async fn add_second_instance(
        ue_builder: &UeBuilder,
        dn: &DataNetwork,
        logger: &Logger,
    ) -> Result<(MockGnb, ProgramHandle)> {
        // This function is currently inflexible in various ways.
        // -  Always uses veth2 for the LAN interface.
        // -  Uses hardcoded IPs.
        // -  Always sets NGAP mode.
        let gnb_ip = "127.0.1.2";
        let mut gnb = MockGnb::new(gnb_ip, logger.new(o!("gnb" => 2))).await?;
        let config = qcore_test_config(1, Some(dn.dhcp_server().ip))?;
        let ngap_mode = true;

        let qc = QCore::start_second_instance_with_ebpf_reuse(
            config,
            logger.new(o!("qcore"=> 2)),
            ue_builder.sims.clone(),
            ngap_mode,
            true,
        )
        .await?;
        gnb.perform_ng_setup(qc.ip_addr()).await?;

        Ok((gnb, qc))
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

fn qcore_test_config(instance: u8, dhcp_server: Option<Ipv4Addr>) -> Result<Config> {
    let qc_ip = Ipv4Addr::new(127, 0, instance, 1);
    let qc_dhcp_mac = [2, 2, 2, 2, 2, 2];

    // This is the IP both for the DHCP relay and the clustering.  If VLAN support is added
    // then there will need to be an address per VLAN, with the DHCP relay on the data VLANs
    // and the clustering address on the management VLAN.
    let qc_lan_ip = Ipv4Addr::new(10, 255, 0, 200 + instance);
    let cluster_peer_ip = if instance == 0 {
        None
    } else {
        Some(IpAddr::V4(Ipv4Addr::new(10, 255, 0, 200)))
    };

    let ip_allocation_method = if let Some(dhcp_server_ip) = dhcp_server {
        UeIpAllocationConfig::Dhcp(DhcpConfig {
            local_mac: qc_dhcp_mac,
            local_ip: qc_lan_ip,
            dhcp_server_ip: Some(dhcp_server_ip),
        })
    } else {
        UeIpAllocationConfig::RoutedUeSubnet(Ipv4Addr::new(10, 255, 0, 0))
    };

    let mut tun_interface_name = "qcoretun".to_string();
    if instance != 0 {
        tun_interface_name = format!("{tun_interface_name}{instance}");
    }

    Ok(Config {
        ip_addr: IpAddr::V4(qc_ip),
        plmn: PlmnIdentity([0x00, 0xf1, 0x10]),
        amf_ids: AmfIds([0x01, 0x01, 0x00]),
        name: Some("QCore".to_string()),
        serving_network_name: "5G:mnc001.mcc001.3gppnetwork.org".to_string(),
        skip_ue_auts_check: true, // saves us having to implement AUTS signature in test framework
        sst: 1,
        ran_interface_name: "lo".to_string(),
        n6_interface_name: "veth1".to_string(),
        tun_interface_name,
        pdcp_sn_length: PdcpSequenceNumberLength::TwelveBits,
        five_qi: 7,
        network_display_name: NetworkDisplayName::new("QCoreTest")?,
        ip_allocation_method,
        cluster_config: Some(ClusterConfig {
            local_ip: IpAddr::V4(qc_lan_ip),
            cluster_tcp_port: 22127,
            peer_ip: cluster_peer_ip,
        }),
    })
}

pub async fn start_qcore(
    sub_db: SubscriberDb,
    ngap_mode: bool,
    logger: &Logger,
) -> Result<ProgramHandle> {
    QCore::start(
        qcore_test_config(0, None)?,
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
