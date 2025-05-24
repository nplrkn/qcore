use qcore_tests::{MockUe, framework::*};

#[async_std::test]
async fn synchronization_failure_recovery() -> anyhow::Result<()> {
    let (mut du, qc, _dn, sims, logger) = init().await?;

    // This is a test of synchronization failure recovery from TS33.501, 6.1.3.3.
    // Synchronization failure occurs when the UE and QCore disagree about the SQN parameters used
    // in 5G-AKA authentication.

    // Given a UE that is trying to register
    du.perform_f1_setup(qc.ip_addr()).await?;
    let mut ue = MockUe::new(nth_imsi(0, &sims), 1, &du, qc.ip_addr(), &logger).await?;
    ue.perform_rrc_setup().await?;

    // When UE rejects authentication with a 'Synch failure' cause and an AUTS value.
    ue.handle_nas_authentication_sync_failure().await?;

    // Then QCore retries authentication with an updated SQN and registration completes successfully.
    ue.handle_nas_authentication().await?;
    ue.handle_nas_security_mode().await?;
    ue.handle_rrc_security_mode().await?;
    ue.handle_nas_registration_accept().await?;

    // And if the UE reregisters during the lifetime of QCore, it gets the SQN right this time, and there
    // is no need for another synchronization.
    ue.send_nas_deregistration_request().await?;
    du.handle_ue_context_release(&ue.du_ue_context).await?;

    ue.perform_rrc_setup().await?;
    ue.handle_nas_authentication().await?;

    Ok(())
}
