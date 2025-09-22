use qcore_tests::framework::*;

#[async_std::test]
async fn unexpected_release_during_registration() -> anyhow::Result<()> {
    let (du, qc, _dn, builder, _logger) = init_f1ap2().await?;
    let mut ue = builder.new_f1ap_ue(&du, &qc).await?;

    ue.perform_rrc_setup().await?;
    let _ = ue.receive_nas_authentication_request().await?;
    du.send_ue_context_release_request(ue.du_ue_context())
        .await?;
    du.handle_ue_context_release(ue.du_ue_context()).await?;
    Ok(())
}
