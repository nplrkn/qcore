use qcore_tests::{MockUeNgap, framework::*};

#[async_std::test]
async fn ngap_service_request_variants() -> anyhow::Result<()> {
    let (mut gnb, qc, _dn, builder, logger) = init_ngap().await?;
    let ue = builder.ngap_ue(&gnb).registered().await?;

    let mock_ue = ue.into();
    gnb.disconnect().await;
    async_std::task::sleep(std::time::Duration::from_millis(500)).await;
    gnb.perform_ng_setup(qc.ip_addr()).await?;

    // UE sends a service request without an inner container.
    let mut ue = MockUeNgap::new_from_base(mock_ue, 1, &gnb, qc.ip_addr(), &logger).await?;
    ue.send_nas_service_request_ext(true).await?;

    gnb.handle_initial_context_setup(ue.gnb_ue_context())
        .await?;
    ue.receive_nas_service_accept().await?;
    wait_until_idle(&qc).await
}
