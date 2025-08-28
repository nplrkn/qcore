use qcore_tests::{MockUeNgap, framework::*};

#[async_std::test]
async fn disconnect_during_nas_request() -> anyhow::Result<()> {
    // Receive a NAS request from QCore - in this case an authentication request
    let (mut gnb, qc, _dn, sims, logger) = init_ngap().await?;
    gnb.perform_ng_setup(qc.ip_addr()).await?;
    let mut ue = MockUeNgap::new(nth_imsi(0, &sims), 1, &gnb, qc.ip_addr(), &logger).await?;
    ue.send_nas_register_request().await?;

    ue.receive_nas_authentication_request().await?;

    // Drop the SCTP connection of the gNodeB.
    gnb.disconnect().await;

    // Confirm QCore is not still hanging on the pending request.
    wait_until_idle(&qc).await
}
