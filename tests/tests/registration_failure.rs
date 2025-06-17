use qcore_tests::{MockUeF1ap, framework::*};

#[async_std::test]
async fn registration_unknown_guti() -> anyhow::Result<()> {
    let (mut du, qc, _dn, sims, logger) = init().await?;
    du.perform_f1_setup(qc.ip_addr()).await?;
    let mut ue = MockUeF1ap::new(nth_imsi(0, &sims), 1, &du, qc.ip_addr(), &logger).await?;

    // Send in an integrity protected GUTI registration on an RRC Setup Complete with a matching PLMN but
    // unknown GUTI.  (In this case, bad AMF ID 5,5,5.)
    ue.use_guti([2, 248, 57, 5, 5, 5, 0, 0, 0, 0]);
    ue.perform_rrc_setup().await?;

    // QCore retrieves the IMSI, challenges the UE, and the registration completes successfully.
    ue.handle_identity_procedure().await?;
    ue.handle_nas_authentication().await?;
    ue.handle_nas_security_mode().await?;
    ue.handle_rrc_security_mode().await?;
    ue.handle_capability_enquiry().await?;
    ue.handle_nas_registration_accept().await?;

    // This time, the identity request returns an unknown IMSI and the registration gets rejected.
    // In this case, the unknown GUTI has the correct AMF IDs but a bad TMSI.
    ue.use_guti([2, 248, 57, 1, 1, 0, 0, 0, 0, 0]);
    ue.perform_rrc_setup().await?;
    ue.use_wrong_imsi();
    ue.handle_identity_procedure().await?;
    ue.receive_nas_registration_reject().await?;

    Ok(())
}
