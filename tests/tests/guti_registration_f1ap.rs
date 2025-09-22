use qcore_tests::framework::*;

#[async_std::test]
async fn guti_registration_f1ap() -> anyhow::Result<()> {
    let (du, _qc, _dn, builder, _logger) = init_f1ap().await?;
    let mut ue = builder.f1ap_ue(&du).registered().await?;

    // In the first variant, the UE message handler is not running.

    // Drop the UE context causing the message handler to exit and park the core context.
    du.send_ue_context_release_request(ue.du_ue_context())
        .await?;
    du.handle_ue_context_release(ue.du_ue_context()).await?;

    // UE does a security protected initial registration with GUTI.
    // QCore skip NAS authentication + security and moves straight to RRC security.
    ue.perform_rrc_setup().await?;
    ue.handle_rrc_security_mode().await?;
    ue.handle_capability_enquiry().await?;
    ue.handle_nas_registration_accept().await?;
    ue.handle_nas_configuration_update().await?;

    // In the second variant, the UE message handler is running.

    // This is the case where the UE resets and its GUTI registration comes in using a new F1AP ID.
    ue.perform_rrc_setup().await?;

    // QCore cleans up the old SRB from the previous Rrc Setup.
    du.handle_ue_context_release(ue.du_ue_context()).await?;

    ue.handle_rrc_security_mode().await?;
    ue.handle_capability_enquiry().await?;
    ue.handle_nas_registration_accept().await?;
    ue.handle_nas_configuration_update().await?;

    Ok(())
}
