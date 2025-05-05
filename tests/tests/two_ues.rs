use qcore_tests::{MockUe, framework::*};

#[async_std::test]
async fn two_ues() -> anyhow::Result<()> {
    let (mut du, qc, _dn, sims, logger) = init().await?;

    // DU connects to CU
    du.perform_f1_setup(qc.ip_addr()).await?;

    // UE 1 registers
    let mut ue_1 = MockUe::new(nth_imsi(0, sims), 1, &du, qc.ip_addr(), &logger).await?;
    ue_1.perform_rrc_setup().await?;
    ue_1.handle_nas_authentication().await?;
    ue_1.handle_nas_security_mode().await?;
    ue_1.handle_rrc_security_mode().await?;
    ue_1.handle_nas_registration_accept().await?;

    // UE 1 PDU session
    ue_1.send_nas_pdu_session_establishment_request().await?;
    du.handle_f1_ue_context_setup(&mut ue_1.du_ue_context)
        .await?;
    ue_1.handle_rrc_reconfiguration_with_session_accept()
        .await?;

    // UE 2 registers
    let mut ue_2 = MockUe::new(nth_imsi(1, sims), 2, &du, qc.ip_addr(), &logger).await?;
    ue_2.perform_rrc_setup().await?;
    ue_2.handle_nas_authentication().await?;
    ue_2.handle_nas_security_mode().await?;
    ue_2.handle_rrc_security_mode().await?;
    ue_2.handle_nas_registration_accept().await?;

    // UE 2 PDU session
    ue_2.send_nas_pdu_session_establishment_request().await?;
    du.handle_f1_ue_context_setup(&mut ue_2.du_ue_context)
        .await?;
    ue_2.handle_rrc_reconfiguration_with_session_accept()
        .await?;

    // UE-to-UE routing
    pass_through_ue_to_ue_ipv4(&ue_1, &ue_2).await?;
    pass_through_ue_to_ue_ipv4(&ue_2, &ue_1).await
}
