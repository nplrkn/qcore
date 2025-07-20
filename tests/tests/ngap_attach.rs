use qcore_tests::{MockUeNgap, framework::*};

#[async_std::test]
async fn ngap_attach() -> anyhow::Result<()> {
    let (mut gnb, qc, dn, sims, logger) = init_ngap().await?;

    // This test carries out the attach flow - see docs/attach.md.

    gnb.perform_ng_setup(qc.ip_addr()).await?;

    // UE registers
    let mut ue = MockUeNgap::new(nth_imsi(0, &sims), 1, &gnb, qc.ip_addr(), &logger).await?;
    ue.send_nas_register_request().await?;
    ue.handle_nas_authentication().await?;
    ue.handle_nas_security_mode().await?;
    gnb.handle_initial_context_setup(ue.gnb_ue_context())
        .await?;
    gnb.send_ue_radio_capability_info(ue.gnb_ue_context())
        .await?;
    ue.handle_nas_registration_accept().await?;
    ue.handle_nas_configuration_update().await?;

    // UE establishes PDU session
    ue.send_nas_pdu_session_establishment_request().await?;
    gnb.handle_pdu_session_resource_setup(ue.gnb_ue_context())
        .await?;
    ue.receive_nas_session_accept().await?;
    qc.wait_until_idle().await;

    pass_through_uplink_ipv4(&ue, &dn).await?;
    pass_through_downlink_ipv4(&dn, &ue).await
}
