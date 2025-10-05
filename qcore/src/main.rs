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
use slog::{Drain, Logger, info, o, warn};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Local IPv4 address of QCore.  Defaults to the first non-loopback address (e.g. of eth0).
    /// QCore binds SCTP port 38412 (for N2) and UDP port 2152 (for GTP-U) to this address.
    /// In F1 mode, it instead uses SCTP port 38472 (for F1-C).
    #[arg(long, default_value_t = local_ip_address::local_ip().unwrap())]
    local_ip: IpAddr,

    /// SIM credentials file to load.
    #[arg(long, default_value = "./sims.toml")]
    sim_cred_file: String,

    /// Mobile Country Code part of the PLMN ID (Public Land Mobile Network ID).  
    /// A string of three decimal digits.
    /// If this parameter is not supplied, then QCore will derive MCC from the lowest
    /// numbered IMSI in the SIM file.
    #[arg(long)]
    mcc: Option<String>,

    /// Mobile Network Code part of the PLMN ID (Public Land Mobile Network ID).  
    /// A string of two or three decimal digits.
    /// If this parameter is not supplied, then QCore will derive a 2-digit MNC from the lowest
    /// numbered IMSI in the SIM file.
    #[arg(long)]
    mnc: Option<String>,

    /// Name of the Linux Ethernet device on which uplink packets from UEs will arrive via the DU or gNB.  
    /// If not set, QCore will look up this link based on the value of local-ip.
    #[arg(long)]
    ran_interface_name: Option<String>,

    /// Whether to disable DHCP.  By default, DHCP is enabled over the <lan-interface-name>.
    /// When disabled, QCore will allocate UE addresses from the the <ue-subnet>.
    #[arg(long, default_value_t = false)]
    no_dhcp: bool,

    /// Name of the Linux Ethernet device that connects to the LAN on which UEs should appear.  Only
    /// relevant if DHCP is enabled (that is, --no-dhcp is not specified).  If unspecified, this will
    /// be set to whatever interface is index 2 in `ip link show` (often eth0).
    ///
    /// Linux Proxy ARP must be enabled on this interface (see the `setup-routing` script).
    #[arg(long)]
    lan_interface_name: Option<String>,

    /// UE subnet.  Only relevant if --no-dhcp is specified.  This is the network address of a /24 IPv4
    /// subnet in dotted demical notation.  The final byte must be 0.  UEs are allocated host numbers 2-254.
    #[arg(long, default_value_t = Ipv4Addr::new(10,255,0,0))]
    ue_subnet: Ipv4Addr,

    /// Slice SST to support.  This is signalled as the allowed SST (with and without SD 0) on NAS Registration Accept
    /// and as the Nssai on PDU session establishment accept.
    #[arg(long, default_value_t = 1)]
    sst: u8,

    /// 5QI value to use.
    #[arg(long, default_value_t = 7)]
    five_qi: u8,

    /// Network display name to send to UEs in NAS Configuration Update Command.
    #[arg(long, default_value = "QCore")]
    network_display_name: String,

    /// Output userplane stats as periodic INFO / WARN logs.
    #[arg(long, default_value_t = false)]
    userplane_stats: bool,

    /// Name of the Linux Ethernet device on which downlink packets to UEs will arrive.  
    #[arg(long, default_value = "veth1")]
    n6_interface_name: String,

    /// Name of the Linux tun device to open for transmitting userplane packets and receiving
    /// downlink packets for buffering.
    #[arg(long, default_value = "qcoretun")]
    tun_interface_name: String,

    /// F1 mode - act as a combined 5G Core / gNB-CU and communicate with a gNB-DU on the F1 reference point.
    #[arg(long, default_value_t = false)]
    f1_mode: bool,

    /// PDCP sequence number length: 18-bit (false) or 12-bit (true).
    /// Only meaningful in F1 mode.
    #[arg(long, default_value_t = false)]
    pdcp_12bit_sn: bool,
}

const DEFAULT_MCC_MNC: &str = "00101";

#[async_std::main]
async fn main() -> Result<()> {
    exit_on_panic();
    let logger = init_logging();

    let args = Args::parse();

    let (sub_db, first_imsi) = SubscriberDb::new_from_sim_file(&args.sim_cred_file, &logger)?;

    let (plmn, serving_network_name) = pick_mcc_mnc(
        args.mcc.as_deref(),
        args.mnc.as_deref(),
        first_imsi.as_deref(),
        &logger,
    )
    .unwrap();

    let local_ip = check_local_ip(args.local_ip)?;
    info!(logger, "Local IP            : {local_ip}");
    let ran_interface_name =
        pick_ran_interface(&local_ip, args.ran_interface_name, &logger).await?;

    let use_dhcp = !args.no_dhcp;
    let ip_allocation_method = if use_dhcp {
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
            ip_addr: IpAddr::V4(local_ip),
            plmn: PlmnIdentity(plmn),
            amf_ids: AmfIds([0x01, 0x00, 0x80]),
            name: Some("QCore".to_string()),
            serving_network_name,
            skip_ue_auts_check: false,
            sst: args.sst,
            ran_interface_name,
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

    if use_dhcp {
        if let Err(e) = (*qc).test_dhcp().await {
            warn!(
                logger,
                "DHCP self test failed.  Pass --no-dhcp to switch to self-managed UE IP addresses"
            );
            warn!(logger, "Error occurred {:#}", e);
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

fn check_local_ip(ip: IpAddr) -> Result<Ipv4Addr> {
    ensure!(
        !ip.is_unspecified(),
        "Unspecific IP address 0.0.0.0 not allowed for local IP - this must be an address that the DU can send to"
    );
    let IpAddr::V4(ip) = ip else {
        bail!("Local IP must be IPv4")
    };
    Ok(ip)
}

async fn pick_ran_interface(
    local_ip: &Ipv4Addr,
    ran_interface_name_arg: Option<String>,
    logger: &Logger,
) -> Result<String> {
    let (name, source) = match ran_interface_name_arg {
        Some(name) => (name, "from command line"),
        None => {
            if local_ip.is_loopback() {
                ("lo".to_string(), "local IP is loopback")
            } else {
                let netlink = qcore::Netlink::new(0)?;
                match netlink.get_if_name_from_ipv4(local_ip).await {
                    Some(name) => (name, "from local IP"),
                    None => {
                        warn!(
                            logger,
                            "Failed to look up interface name from local IP {}", local_ip
                        );
                        bail!("RAN inteface name could not be identified")
                    }
                }
            }
        }
    };
    info!(logger, "Interface to RAN    : {name} ({source})");
    Ok(name)
}

fn pick_mcc_mnc(
    mcc_arg: Option<&str>,
    mnc_arg: Option<&str>,
    first_imsi: Option<&str>,
    logger: &Logger,
) -> Result<([u8; 3], String)> {
    let imsi = first_imsi.unwrap_or(DEFAULT_MCC_MNC);
    let mcc = mcc_arg.unwrap_or(&imsi[0..3]);
    let mnc = mnc_arg.unwrap_or(&imsi[3..5]);

    let source = |x: Option<&str>| match (x.is_some(), first_imsi.is_some()) {
        (false, true) => "from SIM file",
        (false, false) => "defaulted",
        (true, _) => "from command line",
    };
    info!(
        logger,
        "MCC                 : {} ({})",
        mcc,
        source(mcc_arg)
    );
    info!(
        logger,
        "MNC                 : {} ({})",
        mnc,
        source(mnc_arg)
    );

    convert_mcc_mnc(mcc, mnc)
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
