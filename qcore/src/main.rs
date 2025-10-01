//! main - starts a single-instance combined CU-CP and CU-UP

#![allow(unused_parens)]
use anyhow::{Result, anyhow, bail, ensure};
use async_std::channel::Sender;
use async_std::prelude::*;
use clap::Parser;
use qcore::{
    AmfIds, Config, NetworkDisplayName, PdcpSequenceNumberLength, PlmnIdentity, QCore,
    SubscriberDb, UeIpAllocationConfig,
};
use signal_hook::consts::signal::*;
use signal_hook_async_std::Signals;
use slog::{Drain, Logger, o, warn};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Local IPv4 address of QCore.  Defaults to the first non-loopback address (e.g. of eth0).
    /// QCore binds SCTP port 38412 (for N2) and UDP port 2152 (for GTP-U) to this address.
    /// In F1 mode, it instead uses SCTP port 38472 (for F1-C).
    #[arg(long, default_value_t = local_ip_address::local_ip().unwrap())]
    local_ip: IpAddr,

    /// Mobile Country Code part of the PLMN ID (Public Land Mobile Network ID).  
    /// A string of three decimal digits.
    #[arg(long)]
    mcc: String,

    /// Mobile Network Code part of the PLMN ID (Public Land Mobile Network ID).  
    /// A string of two or three decimal digits.
    #[arg(long)]
    mnc: String,

    /// Name of the Linux Ethernet device on which uplink packets from UEs will arrive via the DU or gNB.  
    /// If you are running the gNB/DU locally, this should be set to "lo".
    #[arg(long, default_value = "eth0")]
    ran_interface_name: String,

    /// Name of the Linux Ethernet device on which downlink packets to UEs will arrive.  
    #[arg(long, default_value = "veth1")]
    n6_interface_name: String,

    /// Name of the Linux tun device to open for transmitting userplane packets.
    #[arg(long, default_value = "qcoretun")]
    tun_interface_name: String,

    /// Whether to use DHCP to obtain UE IP addresses.
    #[arg(long, default_value_t = false)]
    use_dhcp: bool,

    // TODO - use same model for RAN interface
    /// Name of the Linux Ethernet device that connects to the LAN on which UEs should appear.  This is
    /// only used if use-dhcp is true.  If unspecified, this will be set to whatever interface is index 2
    /// in `ip link show` (often eth0).
    #[arg(long)]
    lan_interface_name: Option<String>,

    /// UE subnet.  Only relevant if use-dhcp is false.  This is the network address of a /24 IPv4
    /// subnet in dotted demical notation.  The final byte must be 0.  UEs are allocated host numbers 2-254.
    #[arg(long, default_value_t = Ipv4Addr::new(10,255,0,0))]
    ue_subnet: Ipv4Addr,

    /// SIM credentials file to load.
    #[arg(long, default_value = "./sims.toml")]
    sim_cred_file: String,

    /// Slice SST to support.  (SD is always set to 0.)  This is signalled as the allowed SST on NAS Registration Accept
    /// and Nssai on PDU session establishment accept.
    #[arg(long, default_value_t = 1)]
    sst: u8,

    /// 5QI value to use.
    #[arg(long, default_value_t = 7)]
    five_qi: u8,

    /// PDCP sequence number length: 18-bit (false) or 12-bit (true).
    /// Only meaningful in F1 mode.
    #[arg(long, default_value_t = false)]
    pdcp_12bit_sn: bool,

    /// F1 mode - act as a combined 5G Core / gNB-CU and connect to a gNB-DU on the F1 reference point.
    #[arg(long, default_value_t = false)]
    f1_mode: bool,

    /// Network display name to send to UEs in NAS Configuration Update Command.
    #[arg(long, default_value = "QCore")]
    network_display_name: String,

    /// Output userplane stats.
    #[arg(long, default_value_t = false)]
    userplane_stats: bool,
}

#[async_std::main]
async fn main() -> Result<()> {
    exit_on_panic();
    let logger = init_logging();

    let args = Args::parse();
    let (plmn, serving_network_name) = convert_mcc_mnc(&args.mcc, &args.mnc).unwrap();
    check_local_ip(&args.local_ip)?;

    let sub_db = SubscriberDb::new_from_sim_file(&args.sim_cred_file, &logger)?;

    let ip_allocation_method = if args.use_dhcp {
        let lan_if_index = if let Some(lan_interface_name) = args.lan_interface_name {
            qcore::get_if_index(&lan_interface_name)?
        } else {
            2
        };

        // The 'None' here means that QCore will broadcast its DHCP requests.
        UeIpAllocationConfig::Dhcp(lan_if_index, None)
    } else {
        check_ue_subnet(&args.ue_subnet)?;
        UeIpAllocationConfig::RoutedUeSubnet(args.ue_subnet)
    };
    let qc = QCore::start(
        Config {
            ip_addr: args.local_ip,
            plmn: PlmnIdentity(plmn),
            amf_ids: AmfIds([0x01, 0x00, 0x80]),
            name: Some("QCore".to_string()),
            serving_network_name,
            skip_ue_auts_check: false,
            sst: args.sst,
            ran_interface_name: args.ran_interface_name,
            n6_interface_name: args.n6_interface_name,
            tun_interface_name: args.tun_interface_name,
            pdcp_sn_length: if args.pdcp_12bit_sn {
                PdcpSequenceNumberLength::TwelveBits
            } else {
                PdcpSequenceNumberLength::EighteenBits
            },
            five_qi: args.five_qi,
            network_display_name: NetworkDisplayName::new(&args.network_display_name)?,
            ip_allocation_method,
        },
        logger.clone(),
        sub_db,
        !args.f1_mode,
        args.userplane_stats,
    )
    .await?;

    if args.use_dhcp {
        if let Err(e) = (*qc).test_dhcp().await {
            warn!(logger, "DHCP self test failed - {:#}", e);
            bail!("Self test failure");
        }
    }
    wait_for_signal().await?;

    Ok(())
}

fn init_logging() -> Logger {
    // Use info level logging by default
    if std::env::var("RUST_LOG").is_err() {
        unsafe { std::env::set_var("RUST_LOG", "info") }
    }
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let drain = slog_envlogger::new(drain);
    slog::Logger::root(drain, o!())
}

fn exit_on_panic() {
    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        orig_hook(panic_info);
        std::process::exit(1);
    }));
}

fn check_ue_subnet(ue_subnet: &Ipv4Addr) -> Result<()> {
    ensure!(
        ue_subnet.octets()[3] == 0,
        "Final byte of UE subnet must be 0"
    );
    Ok(())
}

fn check_local_ip(ip: &IpAddr) -> Result<()> {
    ensure!(
        !ip.is_unspecified(),
        "Unspecific IP address 0.0.0.0 not allowed for local IP - this must be an address that the DU can send to"
    );
    Ok(())
}

fn convert_mcc_mnc(mcc: &str, mnc: &str) -> Result<([u8; 3], String)> {
    ensure!(mcc.len() == 3, "MCC must be three digits");
    ensure!(
        mnc.len() == 2 || mnc.len() == 3,
        "MNC must be two or three digits"
    );
    let mut digits = mcc
        .chars()
        .map(|c| c.to_digit(10))
        .collect::<Option<Vec<_>>>()
        .ok_or(anyhow!("MCC contained a non digit"))?;
    if mnc.len() == 2 {
        digits.push(0x0f)
    };
    let mut mnc_digits = mnc
        .chars()
        .map(|c| c.to_digit(10))
        .collect::<Option<Vec<_>>>()
        .ok_or(anyhow!("MNC contained a non digit"))?;
    digits.append(&mut mnc_digits);

    let mut plmn = [0u8; 3];
    for ii in 0..3 {
        plmn[ii] = ((digits[ii * 2 + 1] << 4) | (digits[ii * 2])) as u8
    }

    let serving_network_name = format!("5G:mnc{:0>3}.mcc{}.3gppnetwork.org", mnc, mcc);
    Ok((plmn, serving_network_name))
}

async fn wait_for_signal() -> Result<i32> {
    let signals = Signals::new([SIGHUP, SIGTERM, SIGINT, SIGQUIT])?;
    let handle = signals.handle();
    let (sig_sender, sig_receiver) = async_std::channel::unbounded();
    let signals_task = async_std::task::spawn(handle_signals(signals, sig_sender));
    let signal = sig_receiver.recv().await;
    handle.close();
    signals_task.await;
    Ok(signal?)
}

async fn handle_signals(signals: Signals, sig_sender: Sender<i32>) {
    let mut signals = signals.fuse();
    while let Some(signal) = signals.next().await {
        match signal {
            SIGHUP => {
                // Reload configuration
                // Reopen the log file
            }
            SIGTERM | SIGINT | SIGQUIT => {
                // Shutdown the system;
                let _ = sig_sender.send(signal).await;
            }
            _ => unreachable!(),
        }
    }
}
