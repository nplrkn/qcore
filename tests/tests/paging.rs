use qcore_tests::{MockUeNgap, framework::*};

#[async_std::test]
async fn paging() -> anyhow::Result<()> {
    let (mut gnb, qc, dn, sims, logger) = init_ngap().await?;

    gnb.perform_ng_setup(qc.ip_addr()).await?;
    let mut ue =
        MockUeNgap::new_with_session(nth_imsi(0, &sims), 1, &gnb, qc.ip_addr(), &logger).await?;

    gnb.send_ue_context_release_request(ue.gnb_ue_context())
        .await?;
    gnb.handle_ue_context_release(ue.gnb_ue_context()).await?;
    let _old_ue_context = gnb
        .reset_ue_context(ue.gnb_ue_context(), qc.ip_addr())
        .await?;
    wait_until_idle(&qc).await?;

    send_downlink_ipv4(&dn, &ue).await?;

    // Receive paging request with the UE's S-TMSI.
    gnb.receive_paging(&ue.data.guti.unwrap()[6..10]).await?;
    ue.send_nas_service_request().await?;

    gnb.handle_initial_context_setup_with_session(ue.gnb_ue_context())
        .await?;

    // Queued packet gets replayed.
    let _ip_packet = gnb.recv_n3_data_packet(ue.gnb_ue_context()).await?;

    ue.receive_nas_service_accept().await?;
    ue.handle_nas_configuration_update().await?;
    wait_until_idle(&qc).await
}
