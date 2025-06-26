use qcore_tests::{MockUeF1ap, framework::*};

#[async_std::test]
async fn session_release() -> anyhow::Result<()> {
    let (mut du, qc, _dn, sims, logger) = init().await?;

    // This test carries out the attach flow - see docs/attach.md.

    // DU connects to CU
    du.perform_f1_setup(qc.ip_addr()).await?;

    // UE registers
    let mut ue =
        MockUeF1ap::new_with_session(nth_imsi(0, &sims), 1, &du, qc.ip_addr(), &logger).await?;

    // Userplane packet passthrough
    ue.send_nas_pdu_session_release_request().await?;
    du.handle_ue_context_modification(ue.du_ue_context())
        .await?;
    ue.handle_rrc_reconfiguration_with_session_release().await?;

    qc.wait_until_idle().await;
    Ok(())
}
