use qcore_tests::framework::*;

#[async_std::test]
async fn context_release_request_f1ap() -> anyhow::Result<()> {
    let (du, qc, _dn, mut builder, _logger) = init_f1ap2().await?;
    let mut ue = builder.with_session().new_f1ap_ue(&du, &qc).await?;

    // When a DU sends a context release request
    du.send_ue_context_release_request(ue.du_ue_context())
        .await?;

    // Then QCore should release the context.
    du.handle_ue_context_release(ue.du_ue_context()).await?;
    Ok(())
}
