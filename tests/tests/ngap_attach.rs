use qcore_tests::{MockUeNgap, framework::*};

#[async_std::test]
async fn ngap_attach() -> anyhow::Result<()> {
    let (mut gnb, qc, dn, sims, logger) = init_ngap().await?;

    // This test carries out the attach flow - see docs/attach.md.

    // DU connects to CU
    gnb.perform_ng_setup(qc.ip_addr()).await?;

    // UE registers
    let mut ue = MockUeNgap::new(nth_imsi(0, &sims), 1, &gnb, qc.ip_addr(), &logger).await?;
    ue.send_nas_register_request().await?;
    ue.handle_nas_authentication().await?;
    ue.handle_nas_security_mode().await?;
    gnb.handle_initial_context_setup(ue.gnb_ue_context())
        .await?;
    ue.handle_nas_registration_accept().await?;

    // UE establishes PDU session
    ue.send_nas_pdu_session_establishment_request().await?;
    let nas_accept = gnb
        .handle_pdu_session_resource_setup_with_session_accept(ue.gnb_ue_context())
        .await?;
    ue.handle_session_accept(nas_accept)?;

    // Userplane packet passthrough
    pass_through_uplink_ipv4(&ue, &dn).await?;

    // There is a timing window here, where the core hasn't yet processed our PDU session
    // resource setup response so drops the downlink packet.
    async_std::task::sleep(std::time::Duration::new(0, 5000000)).await;
    pass_through_downlink_ipv4(&dn, &ue).await
}
