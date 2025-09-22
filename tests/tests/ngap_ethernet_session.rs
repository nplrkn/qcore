use qcore_tests::framework::*;

#[async_std::test]
async fn ngap_ethernet_session() -> anyhow::Result<()> {
    let (gnb, qc, dn, mut builder, _logger) = init_ngap().await?;

    builder.with_ethernet_session();
    let ue1 = builder.new_ngap_ue(&gnb, &qc).await?;
    let ue2 = builder.new_ngap_ue(&gnb, &qc).await?;

    // UE 1 sends a broadcast from 2:2:2:2:2:2 causing the bridge to learn this MAC.
    pass_through_uplink_ethernet_broadcast(&ue1, &dn).await?;

    // UE 2 sends a unicast frame to 2:2:2:2:2:2 causing the bridge to forward it to UE 1.
    pass_through_ue_to_ue_ethernet_unicast(&ue2, &ue1).await
}
