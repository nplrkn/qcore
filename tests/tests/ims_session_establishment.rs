use qcore_tests::{MockUeF1ap, framework::*};

#[async_std::test]
async fn ims_session_establishment() -> anyhow::Result<()> {
    let (mut du, qc, _dn, sims, logger) = init_f1ap().await?;

    // DU connects to CU
    du.perform_f1_setup(qc.ip_addr()).await?;

    // UE registers
    let mut ue = MockUeF1ap::new(nth_imsi(0, &sims), 1, &du, qc.ip_addr(), &logger).await?;
    ue.perform_rrc_setup().await?;
    ue.handle_nas_authentication().await?;
    ue.handle_nas_security_mode().await?;
    ue.handle_rrc_security_mode().await?;
    ue.handle_capability_enquiry().await?;
    ue.handle_nas_registration_accept().await?;
    ue.handle_nas_configuration_update().await?;

    // UE establishes PDU session with DNN = 'ims' and gets 5GMM status.
    ue.use_dnn(b"ims");
    ue.send_nas_pdu_session_establishment_request().await?;

    ue.receive_nas_5gmm_status().await
}
