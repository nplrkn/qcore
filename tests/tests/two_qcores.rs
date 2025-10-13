// use qcore_tests::{MockGnb, MockUeNgap, framework::*};

// #[async_std::test]
// async fn two_qcores() -> anyhow::Result<()> {
//     // Create two QCores living on the same LAN.
//     //
//     // gnb1: 127.0.0.2 <--> 127.0.0.1 qc1 10.255.0.200 <-\
//     //                                                    |-> 10.255.0.1 DHCP server
//     // gnb2: 127.0.1.2 <--> 127.0.1.1 qc2 10.255.0.201 <-/

//     // These will be 10.255.0.200 and 10.255.0.201 (see setup-routing).
//     let (gnb1, qc1, dn, builder, logger) = TestFrameworkBuilder::<MockGnb>::new()
//         .use_dhcp()
//         .build()
//         .await?;

//     let (gnb2, qc2) =
//         TestFrameworkBuilder::<MockGnb>::add_second_instance(&builder, &dn, &logger).await?;

//     // UE registers and creates a session via GNB 1 / QCore 1.
//     let ue = builder.ngap_ue(&gnb1).with_session().await?;

//     wait_until_idle(&qc1).await?;
//     pass_through_uplink_ipv4(&ue, &dn).await?;
//     pass_through_downlink_ipv4(&dn, &ue).await?;

//     // UE goes idle.
//     gnb1.send_ue_context_release_request(&ue).await?;
//     gnb1.handle_ue_context_release(&ue).await?;
//     let data = ue.base.disconnect();

//     // UE reconnects via GNB2.
//     let mut ue = MockUeNgap::new_from_base(data, 1, &gnb2, qc2.ip_addr(), &logger).await?;
//     ue.send_nas_service_request().await?;
//     gnb2.handle_initial_context_setup_with_session(&mut ue)
//         .await?;
//     ue.receive_nas_service_accept().await?;
//     wait_until_idle(&qc2).await?;

//     pass_through_uplink_ipv4(&ue, &dn).await?;
//     pass_through_downlink_ipv4(&dn, &ue).await
// }
