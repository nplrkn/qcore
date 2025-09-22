use qcore_tests::framework::*;

#[async_std::test]
async fn context_release_request_ngap() -> anyhow::Result<()> {
    let (mut gnb, qc, _dn, mut builder, _logger) = init_ngap().await?;

    gnb.perform_ng_setup(qc.ip_addr()).await?;

    let mut ue = builder.with_session().new_ngap_ue(&gnb, &qc).await?;

    gnb.send_ue_context_release_request(ue.gnb_ue_context())
        .await?;

    gnb.handle_ue_context_release(ue.gnb_ue_context()).await?;
    wait_until_idle(&qc).await
}
