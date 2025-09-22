use qcore_tests::framework::*;

#[async_std::test]
async fn ngap_ethernet_session_not_enough_devices() -> anyhow::Result<()> {
    let (gnb, qc, _dn, mut builder, _logger) = init_ngap().await?;

    builder.with_ethernet_session();
    let _ue1 = builder.new_ngap_ue(&gnb, &qc).await?;
    let _ue2 = builder.new_ngap_ue(&gnb, &qc).await?;

    builder.reset().registered().use_ethernet();
    // The third one won't work and we will get a session establishment reject.
    let mut ue3 = builder.new_ngap_ue(&gnb, &qc).await?;

    ue3.send_nas_pdu_session_establishment_request().await?;
    ue3.receive_nas_session_reject().await?;
    wait_until_idle(&qc).await
}
