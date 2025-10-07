use qcore_tests::{MockUeNgap, framework::*};

#[async_std::test]
async fn ngap_service_request() -> anyhow::Result<()> {
    let (mut gnb, qc, dn, builder, logger) = init_ngap().await?;
    let ue = builder.ngap_ue(&gnb).with_session().await?;

    let mock_ue = ue.into();

    // Disconnect the TNLA, then re-establish the NG interface.
    gnb.disconnect().await;

    // TODO - remove this - probably by replacing the above with an NgReset procedure
    async_std::task::sleep(std::time::Duration::from_millis(500)).await;
    gnb.perform_ng_setup(qc.ip_addr()).await?;

    // UE sends a service request with GUTI to reactivate its previous session.
    let mut ue = MockUeNgap::new_from_base(mock_ue, 1, &gnb, qc.ip_addr(), &logger).await?;
    ue.send_nas_service_request().await?;

    gnb.handle_initial_context_setup_with_session(&mut ue)
        .await?;
    ue.receive_nas_service_accept().await?;
    wait_until_idle(&qc).await?;

    pass_through_uplink_ipv4(&ue, &dn).await?;
    pass_through_downlink_ipv4(&dn, &ue).await
}
