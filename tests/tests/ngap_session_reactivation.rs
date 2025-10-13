use qcore_tests::{MockUeNgap, framework::*};

#[async_std::test]
async fn ngap_session_reactivation() -> anyhow::Result<()> {
    let (mut gnb, qc, dn, builder, logger) = init_ngap().await?;
    let ue = builder.ngap_ue(&gnb).with_session().await?;

    let mock_ue = ue.into();

    // Disconnect the TNLA, then re-establish the NG interface.
    gnb.perform_ng_reset().await?;
    gnb.disconnect().await;
    gnb.perform_ng_setup(qc.ip_addr()).await?;

    // UE sends a service request with GUTI to reactivate its previous session.
    let mut ue = MockUeNgap::new_from_base(mock_ue, 1, &gnb, qc.ip_addr(), &logger).await?;
    ue.send_nas_register_request().await?;
    gnb.handle_initial_context_setup_with_session(&mut ue)
        .await?;
    ue.handle_nas_registration_accept().await?;
    ue.handle_nas_configuration_update().await?;

    pass_through_uplink_ipv4(&ue, &dn).await?;
    pass_through_downlink_ipv4(&dn, &ue).await
}
