use qcore_tests::{MockUe, framework::*};

#[async_std::test]
async fn guti_registration() -> anyhow::Result<()> {
    let (mut du, qc, _dn, sims, logger) = init().await?;

    // Register a UE
    du.perform_f1_setup(qc.ip_addr()).await?;
    let mut ue = MockUe::new(nth_imsi(0, &sims), 1, &du, qc.ip_addr(), &logger).await?;
    ue.perform_rrc_setup().await?;
    ue.handle_nas_authentication().await?;
    ue.handle_nas_security_mode().await?;
    ue.handle_rrc_security_mode().await?;
    ue.handle_nas_registration_accept().await?;

    Ok(())
}
