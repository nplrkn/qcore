use qcore_tests::framework::*;

#[async_std::test]
async fn ngap_session_release() -> anyhow::Result<()> {
    let (gnb, qc, _dn, builder, _logger) = init_ngap().await?;
    let mut ue = builder.ngap_ue(&gnb).with_session().await?;
    ue.send_nas_pdu_session_release_request().await?;
    gnb.handle_pdu_session_resource_release(ue.gnb_ue_context())
        .await?;
    ue.handle_nas_session_release().await?;
    wait_until_idle(&qc).await
}
