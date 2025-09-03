use anyhow::Result;
use clap::Parser;
use qcore_tests::load_test::generate_load_test_sims;
use slog::{Drain, Logger, o};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// AMF NGAP IP address
    #[arg(long, default_value_t = Ipv4Addr::new(127,0,0,1))]
    amf_ip: Ipv4Addr,
}

// Whereas tests/tests/load_test.rs runs a single process load test with QCore as a subtask, this
// executable allows the load test to be run against a separate 5G core, which could be QCore
// or another core such as Open5GS.

#[async_std::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    const UE_COUNT: usize = 200;
    let sims = generate_load_test_sims(UE_COUNT);
    let logger = init_logging();
    qcore_tests::load_test::load_test(&IpAddr::V4(args.amf_ip), &sims, &logger).await
}

// Copy/pasted from qcore/src/main.rs.
fn init_logging() -> Logger {
    if std::env::var("RUST_LOG").is_err() {
        unsafe { std::env::set_var("RUST_LOG", "info") }
    }
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let drain = slog_envlogger::new(drain);
    slog::Logger::root(drain, o!())
}
