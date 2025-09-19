use qcore_tests::{MockUeNgap, framework::*};

#[async_std::test]
async fn ngap_ethernet_session() -> anyhow::Result<()> {
    let (mut gnb, qc, dn, sims, logger) = init_ngap().await?;

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

    // UE 1 sends a broadcast from 2:2:2:2:2:2 causing the bridge to learn this MAC.
    pass_through_uplink_ethernet_broadcast(&ue1, &dn).await?;

    // UE 2 sends a unicast frame to 2:2:2:2:2:2 causing the bridge to forward it to UE 1.
    pass_through_ue_to_ue_ethernet_unicast(&ue2, &ue1).await
}
