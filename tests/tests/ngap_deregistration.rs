use qcore_tests::framework::*;

#[async_std::test]
async fn ngap_deregistration() -> anyhow::Result<()> {
    let (gnb, qc, _dn, mut builder, _logger) = init_ngap().await?;
    let mut ue = builder.registered().new_ngap_ue(&gnb, &qc).await?;
    ue.perform_nas_deregistration().await?;
    gnb.handle_ue_context_release(ue.gnb_ue_context()).await
}
