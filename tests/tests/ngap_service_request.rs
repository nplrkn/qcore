use qcore_tests::{MockUeNgap, framework::*};

#[async_std::test]
async fn ngap_service_request() -> anyhow::Result<()> {
    let (mut gnb, qc, dn, sims, logger) = init_ngap().await?;

    gnb.perform_ng_setup(qc.ip_addr()).await?;
    let ue =
        MockUeNgap::new_with_session(nth_imsi(0, &sims), 1, &gnb, qc.ip_addr(), &logger).await?;
    qc.wait_until_idle().await;

    let mock_ue = ue.into();

    // Disconnect the TNLA, then re-establish the NG interface.
    gnb.disconnect().await;

    // TODO - remove this - probably by replacing the above with an NgReset procedure
    async_std::task::sleep(std::time::Duration::from_secs(1)).await;
    gnb.perform_ng_setup(qc.ip_addr()).await?;

    // UE sends a service request with GUTI to reactivate its previous session.
    let mut ue = MockUeNgap::new_from_base(mock_ue, 1, &gnb, qc.ip_addr(), &logger).await?;
    ue.send_nas_service_request().await?;

    gnb.handle_initial_context_setup_with_session(ue.gnb_ue_context())
        .await?;
    ue.receive_nas_service_accept().await?;
    ue.handle_nas_configuration_update().await?;

    pass_through_uplink_ipv4(&ue, &dn).await?;
    pass_through_downlink_ipv4(&dn, &ue).await
}
