use qcore_tests::framework::*;
use slog::info;

#[async_std::test]
async fn deregistration_during_nas_request() -> anyhow::Result<()> {
    // This test is inspired by a PacketRusher flow, in which PacketRusher ignores a
    // NAS session release command, and sends a deregistration request.  There are a few
    // ways for QCore to handle this, but the 'Open5GS-like' model is for QCore to
    // immediately action the deregistration request.

    let (gnb, qc, _dn, builder, logger) = init_ngap().await?;
    let mut ue = builder.ngap_ue(&gnb).build().await?;

    for variant in 0..1 {
        info!(logger, "Test variant {}", variant);

        // Get to the point of receiving the NAS session release command.
        ue.send_nas_register_request().await?;
        ue.handle_nas_authentication().await?;
        ue.handle_nas_security_mode().await?;
        gnb.handle_initial_context_setup(&mut ue).await?;
        gnb.send_ue_radio_capability_info(&mut ue).await?;
        ue.handle_nas_registration_accept().await?;
        ue.handle_nas_configuration_update().await?;
        ue.send_nas_pdu_session_establishment_request().await?;
        gnb.handle_pdu_session_resource_setup(&mut ue).await?;
        ue.receive_nas_session_accept().await?;

        ue.send_nas_pdu_session_release_request().await?;

        gnb.handle_pdu_session_resource_release(&mut ue).await?;

        // Instead of replying, send a deregistration request.
        ue.send_nas_deregistration_request().await?;

        // In the first variant, the UE just ignores the session release command (like PacketRusher does).
        // In the second variant, it responds to it, but only after sending its deregistration request.
        if variant == 0 {
            ue.receive_nas_session_release_command().await?;
        } else {
            ue.handle_nas_session_release().await?;
        }

        // Either way, QCore immediately accepts the deregistration and terminates the UE context.
        ue.receive_nas_deregistration_accept().await?;
        gnb.handle_ue_context_release(&ue).await?;
        wait_until_idle(&qc).await?;

        // Reuse the same UE for the next iteration.
        gnb.reset_ue_context(&mut ue, qc.ip_addr()).await?;
    }

    Ok(())
}
