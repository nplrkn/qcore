use qcore_tests::framework::*;

#[async_std::test]
async fn disconnect_during_nas_request() -> anyhow::Result<()> {
    // Receive a NAS request from QCore - in this case an authentication request
    let (mut gnb, qc, _dn, builder, _logger) = init_ngap().await?;
    let mut ue = builder.ngap_ue(&gnb).build().await?;

    ue.send_nas_register_request().await?;
    ue.receive_nas_authentication_request().await?;

    // Drop the SCTP connection of the gNodeB.
    gnb.disconnect().await;

    // Confirm QCore is not still hanging on the pending request.
    wait_until_idle(&qc).await
}
