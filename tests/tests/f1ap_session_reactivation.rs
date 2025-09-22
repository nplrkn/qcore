use qcore_tests::{MockUeF1ap, framework::*};

#[async_std::test]
async fn f1ap_session_reactivation() -> anyhow::Result<()> {
    let (mut du, qc, dn, builder, logger) = init_f1ap().await?;
    let ue = builder.f1ap_ue(&du).with_session().await?;

    let ue_data = ue.into();

    // Re-establish the F1 interface.
    du.perform_f1_removal().await?;
    du.perform_f1_setup_with_existing_tnla().await?;

    // UE sends a registration request with GUTI and reactivates its previous session.
    let mut ue = MockUeF1ap::new_from_base(ue_data, 1, &du, qc.ip_addr(), &logger).await?;
    ue.perform_rrc_setup().await?;
    ue.handle_rrc_security_mode().await?;
    ue.handle_capability_enquiry().await?;
    du.handle_f1_ue_context_setup(ue.du_ue_context()).await?;
    ue.handle_rrc_reconfiguration_with_added_session().await?;
    ue.handle_nas_registration_accept().await?;
    ue.handle_nas_configuration_update().await?;

    pass_through_uplink_ipv4(&ue, &dn).await?;
    pass_through_downlink_ipv4(&dn, &ue).await
}
