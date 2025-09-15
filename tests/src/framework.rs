use super::{DataNetwork, MockDu, MockUe};
use crate::{MockGnb, mock_ue::Transport};
use anyhow::{Result, bail};
use qcore::{
    AmfIds, Config, NetworkDisplayName, PdcpSequenceNumberLength, ProgramHandle, QCore,
    SubscriberAuthParams, SubscriberDb,
};
use slog::{Drain, Logger, o};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use xxap::PlmnIdentity;

pub async fn init_f1ap() -> Result<(MockDu, ProgramHandle, DataNetwork, SubscriberDb, Logger)> {
    let logger = init_logging();
    let du_ip = "127.0.0.2";
    let du = MockDu::new(du_ip, &logger).await?;
    init_common(du, false, logger).await
}

pub async fn init_ngap() -> Result<(MockGnb, ProgramHandle, DataNetwork, SubscriberDb, Logger)> {
    let logger = init_logging();
    let gnb_ip = "127.0.0.2";
    let gnb = MockGnb::new(gnb_ip, &logger).await?;
    init_common(gnb, true, logger).await
}

pub async fn init_ngap_with_subdb(
    sub_db: SubscriberDb,
) -> Result<(MockGnb, ProgramHandle, DataNetwork, SubscriberDb, Logger)> {
    let logger = init_logging();
    let gnb_ip = "127.0.0.2";
    let gnb = MockGnb::new(gnb_ip, &logger).await?;
    init_common_with_subdb(gnb, true, sub_db, logger).await
}

async fn init_common<T>(
    du_or_gnb: T,
    ngap_mode: bool,
    logger: Logger,
) -> Result<(T, ProgramHandle, DataNetwork, SubscriberDb, Logger)> {
    exit_on_panic();
    let qc_ip = "127.0.0.1";
    let dn = DataNetwork::new(&logger).await;
    let subs = SubscriberDb::new_from_sim_file("test_sims.toml", &logger)?;
    let qc = start_qcore(qc_ip, subs.clone(), &logger, ngap_mode).await?;
    Ok((du_or_gnb, qc, dn, subs, logger))
}

async fn init_common_with_subdb<T>(
    du_or_gnb: T,
    ngap_mode: bool,
    sub_db: SubscriberDb,
    logger: Logger,
) -> Result<(T, ProgramHandle, DataNetwork, SubscriberDb, Logger)> {
    exit_on_panic();
    let qc_ip = "127.0.0.1";
    let dn = DataNetwork::new(&logger).await;
    let qc = start_qcore(qc_ip, sub_db.clone(), &logger, ngap_mode).await?;
    Ok((du_or_gnb, qc, dn, sub_db, logger))
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

pub async fn start_qcore(
    addr: &str,
    sub_db: SubscriberDb,
    logger: &Logger,
    ngap_mode: bool,
) -> Result<ProgramHandle> {
    QCore::start(
        Config {
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
            ue_subnet: Ipv4Addr::new(10, 255, 0, 0),
            pdcp_sn_length: PdcpSequenceNumberLength::TwelveBits,
            five_qi: 7,
            network_display_name: NetworkDisplayName::new("QCoreTest")?,
        },
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
    ue.send_userplane_packet(&dst_ip, TEST_UDP_PORT, dst_udp_server.port())
        .await
}

pub async fn pass_through_uplink_ipv4<T: Transport>(
    ue: &MockUe<T>,
    dn: &DataNetwork,
) -> Result<()> {
    send_uplink_ipv4(ue, dn).await?;
    dn.receive_n6_udp_packet().await
}

pub async fn pass_through_ue_to_ue_ipv4<T: Transport>(
    src_ue: &MockUe<T>,
    dst_ue: &MockUe<T>,
) -> Result<()> {
    src_ue
        .send_userplane_packet(&dst_ue.data.ipv4_addr, TEST_UDP_PORT, TEST_UDP_PORT)
        .await?;
    let _ip_packet = dst_ue.recv_ue_data_packet().await?;
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
