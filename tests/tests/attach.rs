use qcore_tests::framework::*;

#[async_std::test]
async fn attach() -> anyhow::Result<()> {
    let (du, _qc, dn, builder, _logger) = init_f1ap().await?;

    // This test carries out the attach flow - see docs/attach.md.

    // UE registers
    let mut ue = builder.f1ap_ue(&du).build().await?;
    ue.perform_rrc_setup().await?;
    ue.handle_nas_authentication().await?;
    ue.handle_nas_security_mode().await?;
    ue.handle_rrc_security_mode().await?;
    ue.handle_capability_enquiry().await?;
    ue.handle_nas_registration_accept().await?;
    ue.handle_nas_configuration_update().await?;

    // UE establishes PDU session
    ue.send_nas_pdu_session_establishment_request().await?;
    du.handle_f1_ue_context_setup(ue.du_ue_context()).await?;
    ue.handle_rrc_reconfiguration_with_added_session().await?;
    ue.receive_nas_session_accept().await?;

    // Userplane packet passthrough
    pass_through_uplink_ipv4(&ue, &dn).await?;
    pass_through_downlink_ipv4(&dn, &ue).await
}
