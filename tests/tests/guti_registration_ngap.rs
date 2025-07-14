use qcore_tests::{MockUeNgap, framework::*};

#[async_std::test]
async fn guti_registration_ngap() -> anyhow::Result<()> {
    let (mut gnb, qc, _dn, sims, logger) = init_ngap().await?;

    gnb.perform_ng_setup(qc.ip_addr()).await?;
    let mut ue =
        MockUeNgap::new_registered(nth_imsi(0, &sims), 1, &gnb, qc.ip_addr(), &logger).await?;
    qc.wait_until_idle().await;

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
    ue.receive_nas_configuration_update().await?;

    Ok(())
}
