use qcore_tests::framework::*;

#[async_std::test]
async fn context_release_request_f1ap() -> anyhow::Result<()> {
    let (du, _qc, _dn, builder, _logger) = init_f1ap().await?;
    let mut ue = builder.f1ap_ue(&du).with_session().await?;

    // When a DU sends a context release request
    du.send_ue_context_release_request(ue.du_ue_context())
        .await?;

    // Then QCore should release the context.
    du.handle_ue_context_release(ue.du_ue_context()).await
}
