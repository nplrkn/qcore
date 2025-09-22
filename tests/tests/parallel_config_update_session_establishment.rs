use qcore_tests::framework::*;

#[async_std::test]
async fn parallel_config_update_session_establishment() -> anyhow::Result<()> {
    let (gnb, qc, _dn, builder, _logger) = init_ngap().await?;
    let mut ue = builder.ngap_ue(&gnb).build().await?;

    // See the design doc on 'ue serialization' for some background here.

    ue.send_nas_register_request().await?;
    ue.handle_nas_authentication().await?;
    ue.handle_nas_security_mode().await?;
    gnb.handle_initial_context_setup(ue.gnb_ue_context())
        .await?;
    gnb.send_ue_radio_capability_info(ue.gnb_ue_context())
        .await?;
    ue.handle_nas_registration_accept().await?;

    // Receive but don't respond yet to the ConfigurationUpdateCommand.
    ue.receive_nas_configuration_update_command().await?;

    // Carry out a session establishment.
    ue.send_nas_pdu_session_establishment_request().await?;
    gnb.handle_pdu_session_resource_setup(ue.gnb_ue_context())
        .await?;
    ue.receive_nas_session_accept().await?;

    // Finally, send ConfigurationUpdateComplete.
    ue.send_nas_configuration_update_complete().await?;

    wait_until_idle(&qc).await
}
