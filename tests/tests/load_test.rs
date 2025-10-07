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
    let qc = start_qcore(sims.clone(), true, &logger).await?;
    qcore_tests::load_test::load_test(*qc.ip_addr(), sims, logger).await
}
