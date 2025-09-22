use qcore_tests::framework::*;

#[async_std::test]
async fn session_release() -> anyhow::Result<()> {
    let (du, qc, _dn, mut builder, _logger) = init_f1ap2().await?;
    let mut ue = builder.with_session().new_f1ap_ue(&du, &qc).await?;
    ue.send_nas_pdu_session_release_request().await?;
    du.handle_ue_context_modification(ue.du_ue_context())
        .await?;
    ue.handle_rrc_reconfiguration_with_released_session()
        .await?;
    ue.handle_nas_session_release().await?;

    wait_until_idle(&qc).await
}
