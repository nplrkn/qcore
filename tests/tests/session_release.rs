use qcore_tests::{MockUeF1ap, framework::*};

#[async_std::test]
async fn session_release() -> anyhow::Result<()> {
    let (mut du, qc, _dn, sims, logger) = init().await?;

    // This test carries out the attach flow - see docs/attach.md.

    // DU connects to CU
    du.perform_f1_setup(qc.ip_addr()).await?;

    // UE registers
    let mut ue = MockUeF1ap::new(nth_imsi(0, &sims), 1, &du, qc.ip_addr(), &logger).await?;
    ue.perform_rrc_setup().await?;
    ue.handle_nas_authentication().await?;
    ue.handle_nas_security_mode().await?;
    ue.handle_rrc_security_mode().await?;
    ue.handle_nas_registration_accept().await?;

    // UE establishes PDU session
    ue.send_nas_pdu_session_establishment_request().await?;
    du.handle_f1_ue_context_setup(ue.du_ue_context()).await?;
    ue.handle_rrc_reconfiguration_with_session_accept().await?;

    // Userplane packet passthrough
    ue.send_nas_pdu_session_release().await?;
    du.handle_ue_context_modification(ue.du_ue_context())
        .await?;
    ue.handle_rrc_reconfiguration_with_session_release().await?;

    qc.wait_until_idle().await;
    Ok(())
}
