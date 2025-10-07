use qcore_tests::{MockGnb, framework::*};

#[async_std::test]
async fn two_qcores() -> anyhow::Result<()> {
    // Create two QCores living on the same LAN.
    //
    // gnb1: 127.0.0.2 <--> 127.0.0.1 qc1 10.255.0.200 <-\
    //                                                    |-> 10.255.0.1 DHCP server
    // gnb2: 127.0.1.2 <--> 127.0.1.1 qc2 10.255.0.201 <-/

    // These will be 10.255.0.200 and 10.255.0.201 (see setup-routing).
    let (gnb1, qc1, dn, builder, logger) = TestFrameworkBuilder::<MockGnb>::new()
        .use_dhcp("veth2")
        .build()
        .await?;

    let (gnb2, qc2) =
        TestFrameworkBuilder::<MockGnb>::add_second_instance(&builder, &dn, &logger).await?;

    // UE registers and creates a session via GNB 1 / QCore 1.
    let mut ue1 = builder.ngap_ue(&gnb1).with_session().await?;

    // UE goes idle.
    gnb1.send_ue_context_release_request(&ue1).await?;
    gnb1.handle_ue_context_release(&ue1).await?;

    let data = ue1.base.disconnect();

    Ok(())
}
