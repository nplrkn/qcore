use qcore_tests::{MockGnb, framework::*};

#[async_std::test]
async fn reregistration() -> anyhow::Result<()> {
    let (gnb, qc, dn, mut builder, _logger) = TestFrameworkBuilder::<MockGnb>::default()
        .use_dhcp()
        .build()
        .await?;
    let mut ue = builder.ngap_ue(&gnb).with_dhcp_session(&dn).await?;
    wait_until_idle(&qc).await?;
    ue.perform_nas_deregistration().await?;
    gnb.handle_ue_context_release(&ue).await?;

    builder.reset_ue_index().await;
    let ue = builder.ngap_ue(&gnb).with_dhcp_session(&dn).await?;
    wait_until_idle(&qc).await?;
    pass_through_uplink_ipv4(&ue, &dn).await?;
    pass_through_downlink_ipv4(&dn, &ue).await
}
