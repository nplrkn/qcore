use qcore_tests::{SYNCH_FAILURE, framework::*};

#[async_std::test]
async fn synchronization_failure_recovery() -> anyhow::Result<()> {
    let (du, _qc, _dn, builder, _logger) = init_f1ap().await?;
    let mut ue = builder.f1ap_ue(&du).build().await?;

    // This is a test of synchronization failure recovery from TS33.501, 6.1.3.3.
    // Synchronization failure occurs when the UE and QCore disagree about the SQN parameters used
    // in 5G-AKA authentication.

    ue.perform_rrc_setup().await?;

    // When UE rejects authentication with a 'Synch failure' cause and an AUTS value.
    ue.fail_nas_authentication(SYNCH_FAILURE).await?;

    // Then QCore retries authentication with an updated SQN and registration completes successfully.
    ue.handle_nas_authentication().await?;
    ue.handle_nas_security_mode().await?;
    ue.handle_rrc_security_mode().await?;
    ue.handle_capability_enquiry().await?;
    ue.handle_nas_registration_accept().await?;
    ue.handle_nas_configuration_update().await?;

    // And if the UE reregisters during the lifetime of QCore, it gets the SQN right this time, and there
    // is no need for another synchronization.
    ue.perform_nas_deregistration().await?;
    du.handle_ue_context_release(ue.du_ue_context()).await?;

    ue.perform_rrc_setup().await?;
    ue.handle_nas_authentication().await
}
