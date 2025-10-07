use qcore_tests::framework::*;

#[async_std::test]
async fn ngap_attach() -> anyhow::Result<()> {
    let (gnb, qc, dn, builder, _logger) = init_ngap().await?;
    let mut ue = builder.ngap_ue(&gnb).build().await?;

    ue.send_nas_register_request().await?;
    ue.handle_nas_authentication().await?;
    ue.handle_nas_security_mode().await?;
    gnb.handle_initial_context_setup(&mut ue).await?;
    gnb.send_ue_radio_capability_info(&mut ue).await?;
    ue.handle_nas_registration_accept().await?;
    ue.handle_nas_configuration_update().await?;

    // UE establishes PDU session
    ue.send_nas_pdu_session_establishment_request().await?;
    gnb.handle_pdu_session_resource_setup(&mut ue).await?;
    ue.receive_nas_session_accept().await?;
    wait_until_idle(&qc).await?;

    pass_through_uplink_ipv4(&ue, &dn).await?;
    pass_through_downlink_ipv4(&dn, &ue).await
}
