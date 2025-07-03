use qcore_tests::{MockUeF1ap, MockUeNgap, framework::*};

#[async_std::test]
async fn context_release_request_f1ap() -> anyhow::Result<()> {
    let (mut du, qc, _dn, sims, logger) = init().await?;

    // Given an established UE context at the DU
    du.perform_f1_setup(qc.ip_addr()).await?;
    let mut ue =
        MockUeF1ap::new_with_session(nth_imsi(0, &sims), 1, &du, qc.ip_addr(), &logger).await?;

    // When a DU sends a context release request
    du.send_ue_context_release_request(ue.du_ue_context())
        .await?;

    // Then QCore should release the context.
    du.handle_ue_context_release(ue.du_ue_context()).await?;
    Ok(())
}

#[async_std::test]
async fn context_release_request_ngap() -> anyhow::Result<()> {
    let (mut gnb, qc, _dn, sims, logger) = init_ngap().await?;

    gnb.perform_ng_setup(qc.ip_addr()).await?;
    let mut ue =
        MockUeNgap::new_with_session(nth_imsi(0, &sims), 1, &gnb, qc.ip_addr(), &logger).await?;
    qc.wait_until_idle().await;

    gnb.send_ue_context_release_request(ue.gnb_ue_context())
        .await?;

    gnb.handle_ue_context_release(ue.gnb_ue_context()).await?;
    qc.wait_until_idle().await;

    Ok(())
}
