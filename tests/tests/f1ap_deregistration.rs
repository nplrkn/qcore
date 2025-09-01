use qcore_tests::{MockUeF1ap, framework::*};

#[async_std::test]
async fn f1ap_deregistration() -> anyhow::Result<()> {
    let (mut du, qc, _dn, sims, logger) = init_f1ap().await?;

    // Given an established UE context at the DU
    du.perform_f1_setup(qc.ip_addr()).await?;
    let mut ue =
        MockUeF1ap::new_with_session(nth_imsi(0, &sims), 1, &du, qc.ip_addr(), &logger).await?;

    // When a UE deregisters
    ue.send_nas_deregistration_request().await?;
    ue.receive_nas_deregistration_accept().await?;

    // Then QCore should release the context and accept the deregistration.
    du.handle_ue_context_release(ue.du_ue_context()).await?;

    Ok(())
}
