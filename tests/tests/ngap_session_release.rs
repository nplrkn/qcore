use qcore_tests::{MockUeNgap, framework::*};

#[async_std::test]
async fn ngap_session_release() -> anyhow::Result<()> {
    let (mut gnb, qc, _dn, sims, logger) = init_ngap().await?;
    gnb.perform_ng_setup(qc.ip_addr()).await?;
    let mut ue = MockUeNgap::new(nth_imsi(0, &sims), 1, &gnb, qc.ip_addr(), &logger).await?;
    ue.send_nas_register_request().await?;
    ue.handle_nas_authentication().await?;
    ue.handle_nas_security_mode().await?;
    gnb.handle_initial_context_setup(ue.gnb_ue_context())
        .await?;
    gnb.send_ue_radio_capability_info(ue.gnb_ue_context())
        .await?;
    ue.handle_nas_registration_accept().await?;
    ue.receive_nas_configuration_update().await?;
    ue.send_nas_pdu_session_establishment_request().await?;
    let nas_accept = gnb
        .handle_pdu_session_resource_setup_with_session_accept(ue.gnb_ue_context())
        .await?;
    ue.handle_session_accept(nas_accept)?;

    ue.send_nas_pdu_session_release_request().await?;

    let nas = gnb
        .handle_pdu_session_resource_release(ue.gnb_ue_context())
        .await?;
    ue.handle_session_release(nas).await?;

    qc.wait_until_idle().await;
    Ok(())
}
