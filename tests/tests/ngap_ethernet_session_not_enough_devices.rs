use qcore_tests::framework::*;

#[async_std::test]
async fn ngap_ethernet_session_not_enough_devices() -> anyhow::Result<()> {
    let (gnb, qc, _dn, mut builder, _logger) = init_ngap().await?;

    builder.use_ethernet();
    let _ue1 = builder.ngap_ue(&gnb).with_session().await?;
    let _ue2 = builder.ngap_ue(&gnb).with_session().await?;

    // The third one won't work and we will get a session establishment reject.
    let mut ue3 = builder.ngap_ue(&gnb).registered().await?;

    ue3.send_nas_pdu_session_establishment_request().await?;
    ue3.receive_nas_session_reject().await?;
    wait_until_idle(&qc).await
}
