use qcore_tests::{MockUe, framework::*};

#[async_std::test]
async fn context_release_request() -> anyhow::Result<()> {
    let (mut du, qc, _dn, sims, logger) = init().await?;

    // Given an established UE context at the DU
    du.perform_f1_setup(qc.ip_addr()).await?;
    let mut ue = MockUe::new(nth_imsi(0, sims), 1, &du, qc.ip_addr(), &logger).await?;
    ue.perform_rrc_setup().await?;
    ue.handle_nas_authentication().await?;
    ue.handle_nas_security_mode().await?;
    ue.handle_rrc_security_mode().await?;
    ue.handle_nas_registration_accept().await?;
    ue.send_nas_pdu_session_establishment_request().await?;
    du.handle_f1_ue_context_setup(&mut ue.du_ue_context).await?;
    ue.handle_rrc_reconfiguration_with_session_accept().await?;

    // When a DU sends a context release request
    du.send_ue_context_release_request(&ue.du_ue_context)
        .await?;

    // Then QCore should release the context.
    du.handle_ue_context_release(&ue.du_ue_context).await?;
    Ok(())
}
