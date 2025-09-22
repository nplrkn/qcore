use qcore_tests::framework::*;

#[async_std::test]
async fn two_ues() -> anyhow::Result<()> {
    let (du, qc, _dn, mut builder, _logger) = init_f1ap2().await?;
    let ue1 = builder.with_session().new_f1ap_ue(&du, &qc).await?;
    let ue2 = builder.with_session().new_f1ap_ue(&du, &qc).await?;
    pass_through_ue_to_ue_ipv4(&ue1, &ue2).await?;
    pass_through_ue_to_ue_ipv4(&ue2, &ue1).await
}
