use qcore_tests::framework::*;

#[async_std::test]
async fn f1ap_deregistration() -> anyhow::Result<()> {
    let (du, qc, _dn, mut builder, _logger) = init_f1ap2().await?;
    let mut ue = builder.with_session().new_f1ap_ue(&du, &qc).await?;

    // When a UE deregisters
    ue.send_nas_deregistration_request().await?;
    ue.receive_nas_deregistration_accept().await?;

    // Then QCore should release the context and accept the deregistration.
    du.handle_ue_context_release(ue.du_ue_context()).await?;

    Ok(())
}
