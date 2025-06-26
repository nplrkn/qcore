use qcore_tests::{MockUeF1ap, framework::*};

#[async_std::test]
async fn sequential_sessions() -> anyhow::Result<()> {
    let (mut du, qc, _dn, sims, logger) = init().await?;

    du.perform_f1_setup(qc.ip_addr()).await?;
    let mut ue =
        MockUeF1ap::new_with_session(nth_imsi(0, &sims), 1, &du, qc.ip_addr(), &logger).await?;
    ue.send_nas_pdu_session_release_request().await?;
    du.handle_ue_context_modification(ue.du_ue_context())
        .await?;
    let nas = ue.handle_rrc_reconfiguration(None, Some(1)).await?;

    // Send a new PDU session establishment request before processing the release
    // so that QCore receives messages in an unexpected order.
    ue.send_nas_pdu_session_establishment_request().await?;
    ue.handle_session_release(nas).await?;

    du.handle_f1_ue_context_setup(ue.du_ue_context()).await?;
    ue.handle_rrc_reconfiguration_with_session_accept().await
}
