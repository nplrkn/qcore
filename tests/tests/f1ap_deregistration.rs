use qcore_tests::framework::*;

#[async_std::test]
async fn f1ap_deregistration() -> anyhow::Result<()> {
    let (du, _qc, _dn, builder, _logger) = init_f1ap().await?;
    let mut ue = builder.f1ap_ue(&du).with_session().await?;

    // When a UE deregisters
    ue.send_nas_deregistration_request().await?;
    ue.receive_nas_deregistration_accept().await?;

    // Then QCore should release the context and accept the deregistration.
    du.handle_ue_context_release(ue.du_ue_context()).await
}
