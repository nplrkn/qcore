use qcore_tests::framework::*;

#[async_std::test]
async fn f1_removal() -> anyhow::Result<()> {
    let (mut du, qc, _dn, mut builder, _logger) = init_f1ap().await?;
    let ue = builder.f1ap_ue(&du).with_session().await?;

    // When a DU instigates F1 removal
    // Then QCore should respond and and clear resources such as UE F1AP IDs.
    let _first_allocated_ue_ip = ue.data.ipv4_addr;
    du.perform_f1_removal().await?;
    du.disconnect().await;

    du.perform_f1_setup(qc.ip_addr()).await?;
    builder.reset_ue_index().await;
    let mut _ue = builder.f1ap_ue(&du).with_session().await?;

    // QCore ought to recycle the UE IP address.
    //assert_eq!(first_allocated_ue_ip, ue.data.ipv4_addr);

    Ok(())
}
