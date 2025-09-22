use qcore_tests::framework::*;

#[async_std::test]
async fn registration_unknown_guti() -> anyhow::Result<()> {
    let (du, _qc, _dn, builder, _logger) = init_f1ap().await?;
    let mut ue = builder.f1ap_ue(&du).build().await?;

    // Send in an integrity protected GUTI registration on an RRC Setup Complete with a matching PLMN but
    // unknown GUTI.  (In this case, bad AMF ID 5,5,5.)
    ue.use_guti([0, 241, 16, 5, 5, 5, 0, 0, 0, 0]);
    ue.perform_rrc_setup().await?;
    ue.data.guti = None;

    // QCore retrieves the IMSI, challenges the UE, and the registration completes successfully.
    ue.handle_identity_procedure().await?;
    ue.handle_nas_authentication().await?;
    ue.handle_nas_security_mode().await?;
    ue.handle_rrc_security_mode().await?;
    ue.handle_capability_enquiry().await?;
    ue.handle_nas_registration_accept().await?;
    ue.handle_nas_configuration_update().await?;

    // This time, the identity request returns an unknown IMSI and the registration gets rejected.
    // In this case, the unknown GUTI has the correct AMF IDs but a bad TMSI.
    ue.use_guti([0, 241, 16, 1, 1, 0, 0, 0, 0, 0]);
    ue.perform_rrc_setup().await?;
    ue.use_wrong_imsi();
    ue.handle_identity_procedure().await?;
    ue.receive_nas_registration_reject().await
}
