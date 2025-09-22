use qcore_tests::{framework::*, load_test::generate_load_test_sims};

// This test passes several thousand control plane messages through QCore for performance profiling purposes.
// The call flow used is: registration, session establishment, context release, service request.
// To run this: `cargo test --release --test load_test -- --ignored --nocapture`
#[ignore = "to speed up normal test runs"]
#[async_std::test]
async fn load_test() -> anyhow::Result<()> {
    const UE_COUNT: usize = 200;
    let sims = generate_load_test_sims(UE_COUNT);
    let logger = init_logging();
    let qc_ip = "127.0.0.1";
    let _qc = start_qcore(qc_ip, sims.clone(), &logger, true).await?;
    qcore_tests::load_test::load_test(qc_ip.parse()?, sims, logger).await
}
