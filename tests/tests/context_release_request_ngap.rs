use qcore_tests::{MockUeNgap, framework::*};

#[async_std::test]
async fn context_release_request_ngap() -> anyhow::Result<()> {
    let (mut gnb, qc, _dn, sims, logger) = init_ngap().await?;

    gnb.perform_ng_setup(qc.ip_addr()).await?;
    let mut ue =
        MockUeNgap::new_with_session(nth_imsi(0, &sims), 1, &gnb, qc.ip_addr(), &logger).await?;
    wait_until_idle(&qc).await?;

    gnb.send_ue_context_release_request(ue.gnb_ue_context())
        .await?;

    gnb.handle_ue_context_release(ue.gnb_ue_context()).await?;
    wait_until_idle(&qc).await
}
