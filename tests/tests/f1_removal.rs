use qcore_tests::framework::*;

#[async_std::test]
async fn f1_removal() -> anyhow::Result<()> {
    let (mut du, qc, _dn, mut builder, _logger) = init_f1ap2().await?;
    let ue = builder.with_session().new_f1ap_ue(&du, &qc).await?;

    // When a DU instigates F1 removal
    // Then QCore should respond and and clear resources such as UE F1AP IDs.
    let _first_allocated_ue_ip = ue.data.ipv4_addr;
    du.perform_f1_removal().await?;
    du.disconnect().await;

    du.perform_f1_setup(qc.ip_addr()).await?;
    builder.reset_ue_index().await;
    let mut _ue = builder.with_session().new_f1ap_ue(&du, &qc).await?;

    // QCore ought to recycle the UE IP address.
    //assert_eq!(first_allocated_ue_ip, ue.data.ipv4_addr);

    Ok(())
}
