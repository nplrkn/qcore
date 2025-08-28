use qcore_tests::{MockUeF1ap, framework::*};

#[async_std::test]
async fn session_release() -> anyhow::Result<()> {
    let (mut du, qc, _dn, sims, logger) = init_f1ap().await?;

    du.perform_f1_setup(qc.ip_addr()).await?;
    let mut ue =
        MockUeF1ap::new_with_session(nth_imsi(0, &sims), 1, &du, qc.ip_addr(), &logger).await?;
    ue.send_nas_pdu_session_release_request().await?;
    du.handle_ue_context_modification(ue.du_ue_context())
        .await?;
    ue.handle_rrc_reconfiguration_with_released_session()
        .await?;
    ue.handle_nas_session_release().await?;

    wait_until_idle(&qc).await
}
