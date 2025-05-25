use qcore_tests::{MockUe, framework::*};

#[async_std::test]
async fn registration_failure_unknown_guti() -> anyhow::Result<()> {
    let (mut du, qc, _dn, sims, logger) = init().await?;
    du.perform_f1_setup(qc.ip_addr()).await?;
    let mut ue = MockUe::new(nth_imsi(0, &sims), 1, &du, qc.ip_addr(), &logger).await?;

    // Unknown GUTI - bad AMF IDs
    ue.use_guti([0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    ue.perform_rrc_setup().await?;
    ue.receive_nas_registration_reject().await?;

    // Unknown GUTI - AMF IDs ok but bad PLMN
    ue.use_guti([0, 0, 0, 1, 1, 0, 0, 0, 0, 0]);
    ue.perform_rrc_setup().await?;
    ue.receive_nas_registration_reject().await?;

    // Unknown GUTI - AMF IDs + PLMN ok, but bad TMSI
    ue.use_guti([2, 248, 57, 1, 1, 0, 0, 0, 0, 0]);
    ue.perform_rrc_setup().await?;
    ue.receive_nas_registration_reject().await?;

    Ok(())
}
