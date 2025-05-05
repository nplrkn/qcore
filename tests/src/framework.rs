use super::{DataNetwork, MockDu, MockUe};
use anyhow::{Result, bail};
use qcore::{Config, QCore, SimTable};
use slog::{Drain, Logger, o};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub async fn init() -> Result<(MockDu, QCore, DataNetwork, &'static SimTable, Logger)> {
    exit_on_panic();
    let qc_ip = "127.0.0.1";
    let du_ip = "127.0.0.2";
    let logger = init_logging();
    let du = MockDu::new(du_ip, &logger).await?;
    let dn = DataNetwork::new(&logger).await;
    let sims = qcore::sims::load_sims_file("test_sims.toml", &logger)?;
    let qc = start_qcore(&qc_ip, &sims, &logger).await?;
    Ok((du, qc, dn, sims, logger))
}

fn exit_on_panic() {
    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        orig_hook(panic_info);
        std::process::exit(1);
    }));
}

fn init_logging() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build();
    let drain = std::sync::Mutex::new(drain).fuse();
    let drain = slog_envlogger::new(drain);
    slog::Logger::root(drain, o!())
}

async fn start_qcore(addr: &str, sims: &'static SimTable, logger: &Logger) -> Result<QCore> {
    QCore::start(
        Config {
            ip_addr: addr.parse()?,
            plmn: [0x2, 0xf8, 0x39],
            amf_ids: [0x01, 0x01, 0x00],
            name: Some("QCore".to_string()),
            serving_network_name: "5G:mnc093.mcc208.3gppnetwork.org".to_string(),
            skip_ue_authentication_check: true, // saves us having to implement milenage etc in test framework
            sst: 1,
            n6_tun_name: "ue".to_string(),
            ue_subnet: Ipv4Addr::new(10, 255, 0, 0),
        },
        logger.new(o!("qcore"=> 1)),
        sims,
    )
    .await
}

const TEST_UDP_PORT: u16 = 23215;

/// Send a downlink packet from the DN to an arbitrary UDP port on the UE.
pub async fn pass_through_downlink_ipv4<'a>(dn: &DataNetwork, ue: &MockUe<'a>) -> Result<()> {
    dn.send_n6_udp_packet(SocketAddr::new(IpAddr::V4(ue.ipv4_addr), TEST_UDP_PORT))
        .await?;
    let _ip_packet = ue.recv_f1u_data_packet().await?;
    Ok(())
}

pub async fn pass_through_uplink_ipv4<'a>(ue: &MockUe<'a>, dn: &DataNetwork) -> Result<()> {
    let dst_udp_server = dn.udp_server_addr();
    let IpAddr::V4(dst_ip) = dst_udp_server.ip() else {
        bail!("Expected IPv4 address");
    };
    ue.send_f1u_data_packet(&dst_ip, TEST_UDP_PORT, dst_udp_server.port())
        .await?;
    dn.receive_n6_udp_packet().await
}

pub async fn pass_through_ue_to_ue_ipv4<'a>(
    src_ue: &MockUe<'a>,
    dst_ue: &MockUe<'a>,
) -> Result<()> {
    src_ue
        .send_f1u_data_packet(&dst_ue.ipv4_addr, TEST_UDP_PORT, TEST_UDP_PORT)
        .await?;
    let _ip_packet = dst_ue.recv_f1u_data_packet().await?;
    Ok(())
}

pub fn nth_imsi(n: usize, sims: &SimTable) -> String {
    sims.keys().nth(n).unwrap().clone()
}
