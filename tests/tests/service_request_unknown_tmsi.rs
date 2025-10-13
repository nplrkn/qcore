use qcore_tests::framework::*;

#[async_std::test]
async fn service_request_unknown_tmsi() -> anyhow::Result<()> {
    let (gnb, _qc, _dn, builder, _logger) = init_ngap().await?;
    let mut ue = builder.ngap_ue(&gnb).build().await?;

    ue.data.guti = Some([1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
    ue.send_nas_service_request().await?;
    ue.receive_nas_service_reject().await
}
