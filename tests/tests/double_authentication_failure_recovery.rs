use qcore_tests::{NGKSI_IN_USE, SYNCH_FAILURE, framework::*};

#[async_std::test]
async fn double_authentication_failure_recovery() -> anyhow::Result<()> {
    let (du, _qc, _dn, builder, _logger) = init_f1ap().await?;
    let mut ue = builder.f1ap_ue(&du).build().await?;
    ue.perform_rrc_setup().await?;
    ue.fail_nas_authentication(NGKSI_IN_USE).await?;
    ue.fail_nas_authentication(SYNCH_FAILURE).await?;
    ue.handle_nas_authentication().await?;
    ue.handle_nas_security_mode().await?;
    ue.handle_rrc_security_mode().await?;
    ue.handle_capability_enquiry().await?;
    ue.handle_nas_registration_accept().await?;
    ue.handle_nas_configuration_update().await
}
