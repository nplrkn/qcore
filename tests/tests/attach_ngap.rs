use qcore_tests::{MockUe, framework::*};

#[async_std::test]
async fn attach_ngap() -> anyhow::Result<()> {
    let (mut gnb, qc, dn, sims, logger) = init_ngap().await?;

    // This test carries out the attach flow - see docs/attach.md.

    // DU connects to CU
    gnb.perform_ng_setup(qc.ip_addr()).await

    // UE registers
    // let mut ue = MockUeNgap::new(nth_imsi(0, &sims), 1, &gnb, qc.ip_addr(), &logger).await?;
    // ue.send_nas_register_request().await?;
    // gnb.handle_initial_context_setup(&mut ue.gnb_ue_context)
    //     .await?;
    // ue.handle_nas_authentication().await?;
    // ue.handle_nas_security_mode().await
}
