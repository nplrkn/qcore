use qcore_tests::framework::*;

#[async_std::test]
async fn ngap_deregistration() -> anyhow::Result<()> {
    let (gnb, qc, _dn, builder, _logger) = init_ngap().await?;
    let mut ue = builder.ngap_ue(&gnb).registered().await?;
    wait_until_idle(&qc).await?;
    ue.perform_nas_deregistration().await?;
    gnb.handle_ue_context_release(&ue).await
}
