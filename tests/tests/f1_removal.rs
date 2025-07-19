use qcore_tests::{MockUeF1ap, framework::*};

#[async_std::test]
async fn f1_removal() -> anyhow::Result<()> {
    let (mut du, qc, _dn, sims, logger) = init_f1ap().await?;

    // Given an established PDU session
    du.perform_f1_setup(qc.ip_addr()).await?;
    let ue =
        MockUeF1ap::new_with_session(nth_imsi(0, &sims), 1, &du, qc.ip_addr(), &logger).await?;

    // When a DU instigates F1 removal
    // Then QCore should respond and and clear resources such as UE F1AP IDs.
    let _first_allocated_ue_ip = ue.data.ipv4_addr;
    du.perform_f1_removal().await?;
    du.disconnect().await;

    du.perform_f1_setup(qc.ip_addr()).await?;
    let _ue =
        MockUeF1ap::new_with_session(nth_imsi(0, &sims), 1, &du, qc.ip_addr(), &logger).await?;

    // QCore ought to recycle the UE IP address.
    //assert_eq!(first_allocated_ue_ip, ue.data.ipv4_addr);

    Ok(())
}
