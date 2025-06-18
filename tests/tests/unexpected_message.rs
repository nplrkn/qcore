use qcore_tests::{MockUeF1ap, framework::*};

#[async_std::test]
async fn unexpected_release_during_registration() -> anyhow::Result<()> {
    let (mut du, qc, _dn, sims, logger) = init().await?;

    du.perform_f1_setup(qc.ip_addr()).await?;

    // UE registers
    let mut ue = MockUeF1ap::new(nth_imsi(0, &sims), 1, &du, qc.ip_addr(), &logger).await?;
    ue.perform_rrc_setup().await?;
    let _ = ue.receive_nas_authentication_request().await?;
    du.send_ue_context_release_request(ue.du_ue_context())
        .await?;
    du.handle_ue_context_release(ue.du_ue_context()).await?;

    Ok(())
}
