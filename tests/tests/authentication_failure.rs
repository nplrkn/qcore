use qcore_tests::{MockUeF1ap, NGKSI_IN_USE, SYNCH_FAILURE, framework::*};

#[async_std::test]
async fn authentication_failure() -> anyhow::Result<()> {
    let (mut du, qc, _dn, sims, logger) = init().await?;
    du.perform_f1_setup(qc.ip_addr()).await?;
    let mut ue = MockUeF1ap::new(nth_imsi(0, &sims), 1, &du, qc.ip_addr(), &logger).await?;
    ue.perform_rrc_setup().await?;
    ue.fail_nas_authentication(NGKSI_IN_USE).await?;
    ue.fail_nas_authentication(SYNCH_FAILURE).await?;
    ue.handle_nas_authentication().await?;
    ue.handle_nas_security_mode().await?;
    ue.handle_rrc_security_mode().await?;
    ue.handle_capability_enquiry().await?;
    ue.handle_nas_registration_accept().await?;

    Ok(())
}
