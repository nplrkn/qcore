use qcore_tests::framework::*;

#[async_std::test]
async fn context_release_request_ngap() -> anyhow::Result<()> {
    let (gnb, qc, _dn, builder, _logger) = init_ngap().await?;
    let mut ue = builder.ngap_ue(&gnb).with_session().await?;

    gnb.send_ue_context_release_request(ue.gnb_ue_context())
        .await?;

    gnb.handle_ue_context_release(ue.gnb_ue_context()).await?;
    wait_until_idle(&qc).await
}
