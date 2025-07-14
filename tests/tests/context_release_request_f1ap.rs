use qcore_tests::{MockUeF1ap, framework::*};

#[async_std::test]
async fn context_release_request_f1ap() -> anyhow::Result<()> {
    let (mut du, qc, _dn, sims, logger) = init().await?;

    // Given an established UE context at the DU
    du.perform_f1_setup(qc.ip_addr()).await?;
    let mut ue =
        MockUeF1ap::new_with_session(nth_imsi(0, &sims), 1, &du, qc.ip_addr(), &logger).await?;

    // When a DU sends a context release request
    du.send_ue_context_release_request(ue.du_ue_context())
        .await?;

    // Then QCore should release the context.
    du.handle_ue_context_release(ue.du_ue_context()).await?;
    Ok(())
}
