use qcore_tests::{MockUeNgap, framework::*};

#[async_std::test]
async fn ngap_ethernet_session_not_enough_devices() -> anyhow::Result<()> {
    let (mut gnb, qc, _dn, sims, logger) = init_ngap().await?;

    gnb.perform_ng_setup(qc.ip_addr()).await?;

    // Attach two UEs

    // TODO - use builder pattern so that we can do 'use_ethernet' and 'ue_with_session'.
    let mut ue1 = MockUeNgap::new(nth_imsi(0, &sims), 1, &gnb, qc.ip_addr(), &logger).await?;
    ue1.send_nas_register_request().await?;
    ue1.handle_nas_authentication().await?;
    ue1.handle_nas_security_mode().await?;
    gnb.handle_initial_context_setup(ue1.gnb_ue_context())
        .await?;
    gnb.send_ue_radio_capability_info(ue1.gnb_ue_context())
        .await?;
    ue1.handle_nas_registration_accept().await?;
    ue1.handle_nas_configuration_update().await?;
    ue1.use_ethernet();
    ue1.send_nas_pdu_session_establishment_request().await?;
    gnb.handle_pdu_session_resource_setup(ue1.gnb_ue_context())
        .await?;
    ue1.receive_nas_session_accept().await?;
    wait_until_idle(&qc).await?;

    let mut ue2 = MockUeNgap::new(nth_imsi(0, &sims), 2, &gnb, qc.ip_addr(), &logger).await?;
    ue2.send_nas_register_request().await?;
    ue2.handle_nas_authentication().await?;
    ue2.handle_nas_security_mode().await?;
    gnb.handle_initial_context_setup(ue2.gnb_ue_context())
        .await?;
    gnb.send_ue_radio_capability_info(ue2.gnb_ue_context())
        .await?;
    ue2.handle_nas_registration_accept().await?;
    ue2.handle_nas_configuration_update().await?;
    ue2.use_ethernet();
    ue2.send_nas_pdu_session_establishment_request().await?;
    gnb.handle_pdu_session_resource_setup(ue2.gnb_ue_context())
        .await?;
    ue2.receive_nas_session_accept().await?;
    wait_until_idle(&qc).await?;

    // The third one won't work and we will get a session establishment reject.

    let mut ue3 = MockUeNgap::new(nth_imsi(0, &sims), 2, &gnb, qc.ip_addr(), &logger).await?;
    ue3.send_nas_register_request().await?;
    ue3.handle_nas_authentication().await?;
    ue3.handle_nas_security_mode().await?;
    gnb.handle_initial_context_setup(ue3.gnb_ue_context())
        .await?;
    gnb.send_ue_radio_capability_info(ue3.gnb_ue_context())
        .await?;
    ue3.handle_nas_registration_accept().await?;
    ue3.handle_nas_configuration_update().await?;
    ue3.use_ethernet();
    ue3.send_nas_pdu_session_establishment_request().await?;
    ue3.receive_nas_session_reject().await?;
    wait_until_idle(&qc).await
}
