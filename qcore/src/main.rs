//! main - starts a single-instance combined CU-CP and CU-UP

#![allow(unused_parens)]
use anyhow::anyhow;
use anyhow::{Result, ensure};
use async_std::channel::Sender;
use async_std::prelude::*;
use clap::Parser;
use local_ip_address;
use qcore::{Config, QCore};
use signal_hook::consts::signal::*;
use signal_hook_async_std::Signals;
use slog::{Drain, Logger, o};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Local IPv4 address of QCore.  QCore binds SCTP port 38472 (for F1-C)
    /// and UDP port 2152 (for F1-U) on this address.  Defaults to
    /// the eth0 address.
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

    /// Name of the Linux tun device to open for routing userplane packet to/from UEs on the N6 reference point.
    #[arg(long, default_value = "ue")]
    n6_tun_name: String,

    /// UE subnet.  This is the network address of a /24 IPv4 subnet in dotted demical notation.  
    /// The final byte must be 0.  UEs are allocated host numbers 1-254.
    #[arg(long, default_value_t = Ipv4Addr::new(10,255,0,0))]
    ue_subnet: Ipv4Addr,
}

#[async_std::main]
async fn main() -> Result<()> {
    exit_on_panic();
    let logger = init_logging();

    let args = Args::parse();
    let (plmn, serving_network_name) = convert_mcc_mnc(&args.mcc, &args.mnc).unwrap();
    check_ue_subnet(&args.ue_subnet)?;
    check_local_ip(&args.local_ip)?;
    slog::info!(&logger, "Serving network name {}", serving_network_name);

    let sims = Box::new(qcore::sims::load_sims_file("sims.toml", &logger)?);

    let qc = QCore::start(
        Config {
            ip_addr: args.local_ip,
            plmn,
            amf_ids: [0x01, 0x00, 0x80],
            name: Some("QCore".to_string()),
            serving_network_name,
            skip_ue_authentication_check: false,
            sst: 1,
            n6_tun_name: args.n6_tun_name,
            ue_subnet: args.ue_subnet,
        },
        logger,
        Box::leak(sims),
    )
    .await?;

    wait_for_signal().await?;
    qc.graceful_shutdown().await;

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
