use qcore_tests::framework::*;

#[async_std::test]
async fn two_ues() -> anyhow::Result<()> {
    let (du, _qc, _dn, builder, _logger) = init_f1ap().await?;
    let ue1 = builder.f1ap_ue(&du).with_session().await?;
    let ue2 = builder.f1ap_ue(&du).with_session().await?;
    pass_through_ue_to_ue_ipv4(&ue1, &ue2).await?;
    pass_through_ue_to_ue_ipv4(&ue2, &ue1).await
}
