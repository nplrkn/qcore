use qcore_tests::framework::*;

#[async_std::test]
async fn guti_registration_ngap() -> anyhow::Result<()> {
    let (gnb, qc, _dn, builder, _logger) = init_ngap().await?;
    let mut ue = builder.ngap_ue(&gnb).registered().await?;

    // UE reconnects
    let old_ue_context = gnb
        .reset_ue_context(ue.gnb_ue_context(), qc.ip_addr())
        .await?;
    ue.send_nas_register_request().await?;

    // QCore cleans up the old RAN context.
    gnb.handle_ue_context_release(&old_ue_context).await?;

    gnb.handle_initial_context_setup(ue.gnb_ue_context())
        .await?;
    ue.handle_nas_registration_accept().await?;
    ue.handle_nas_configuration_update().await
}
