use qcore_tests::{MockUeNgap, framework::*};

#[async_std::test]
async fn ngap_deregistration() -> anyhow::Result<()> {
    let (mut gnb, qc, _dn, sims, logger) = init_ngap().await?;
    gnb.perform_ng_setup(qc.ip_addr()).await?;
    let mut ue =
        MockUeNgap::new_registered(nth_imsi(0, &sims), 1, &gnb, qc.ip_addr(), &logger).await?;
    wait_until_idle(&qc).await?;
    ue.perform_nas_deregistration().await?;
    gnb.handle_ue_context_release(ue.gnb_ue_context()).await
}
