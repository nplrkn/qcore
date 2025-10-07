use qcore_tests::framework::*;

#[async_std::test]
async fn paging() -> anyhow::Result<()> {
    let (gnb, qc, dn, builder, _logger) = init_ngap().await?;
    let mut ue = builder.ngap_ue(&gnb).with_session().await?;

    gnb.send_ue_context_release_request(&ue).await?;
    gnb.handle_ue_context_release(&ue).await?;
    let _old_ue_context = gnb.reset_ue_context(&mut ue, qc.ip_addr()).await?;
    wait_until_idle(&qc).await?;

    send_downlink_ipv4(&dn, &ue).await?;

    // Receive paging request with the UE's S-TMSI.
    gnb.receive_paging(&ue.data.guti.unwrap()[6..10]).await?;
    ue.send_nas_service_request().await?;

    gnb.handle_initial_context_setup_with_session(&mut ue)
        .await?;

    // Queued packet gets replayed.
    let _ip_packet = gnb.recv_n3_data_packet(&mut ue).await?;

    ue.receive_nas_service_accept().await?;
    ue.handle_nas_configuration_update().await?;
    wait_until_idle(&qc).await
}
