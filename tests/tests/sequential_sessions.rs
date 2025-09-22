use qcore_tests::framework::*;

#[async_std::test]
async fn sequential_sessions() -> anyhow::Result<()> {
    let (du, qc, _dn, mut builder, _logger) = init_f1ap2().await?;
    let mut ue = builder.with_session().new_f1ap_ue(&du, &qc).await?;

    ue.send_nas_pdu_session_release_request().await?;
    du.handle_ue_context_modification(ue.du_ue_context())
        .await?;
    ue.handle_rrc_reconfiguration_with_released_session()
        .await?;

    // Send a new PDU session establishment request before processing the release
    // so that QCore receives messages in an unexpected order.
    ue.send_nas_pdu_session_establishment_request().await?;
    ue.handle_nas_session_release().await?;

    du.handle_f1_ue_context_setup(ue.du_ue_context()).await?;
    ue.handle_rrc_reconfiguration_with_added_session().await?;
    ue.receive_nas_session_accept().await
}
