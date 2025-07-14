use qcore_tests::{MockUeF1ap, framework::*};

#[async_std::test]
async fn guti_registration_f1ap() -> anyhow::Result<()> {
    let (mut du, qc, _dn, sims, logger) = init().await?;

    // Register a UE
    du.perform_f1_setup(qc.ip_addr()).await?;
    let mut ue = MockUeF1ap::new(nth_imsi(0, &sims), 1, &du, qc.ip_addr(), &logger).await?;
    ue.perform_rrc_setup().await?;
    ue.handle_nas_authentication().await?;
    ue.handle_nas_security_mode().await?;
    ue.handle_rrc_security_mode().await?;
    ue.handle_capability_enquiry().await?;
    ue.handle_nas_registration_accept().await?;
    ue.receive_nas_configuration_update().await?;

    // In the first variant, the UE message handler is not running.

    // Drop the UE context causing the message handler to exit and park the NAS context.
    du.send_ue_context_release_request(ue.du_ue_context())
        .await?;
    du.handle_ue_context_release(ue.du_ue_context()).await?;

    // UE does a security protected initial registration with GUTI.
    // QCore skip NAS authentication + security and moves straight to RRC security.
    ue.perform_rrc_setup().await?;
    ue.handle_rrc_security_mode().await?;
    ue.handle_capability_enquiry().await?;
    ue.handle_nas_registration_accept().await?;
    ue.receive_nas_configuration_update().await?;

    // In the second variant, the UE message handler is running.

    // This is the case where the UE resets and its GUTI registration comes in using a new F1AP ID.
    ue.perform_rrc_setup().await?;

    // QCore cleans up the old SRB from the previous Rrc Setup.
    du.handle_ue_context_release(ue.du_ue_context()).await?;

    ue.handle_rrc_security_mode().await?;
    ue.handle_capability_enquiry().await?;
    ue.handle_nas_registration_accept().await?;
    ue.receive_nas_configuration_update().await?;

    Ok(())
}
