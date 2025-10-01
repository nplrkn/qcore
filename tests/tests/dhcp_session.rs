use std::{net::Ipv4Addr, time::Duration};

use qcore_tests::{MockGnb, framework::*};

#[async_std::test]
async fn dhcp_session() -> anyhow::Result<()> {
    // This test makes use of 'veth2' set up by setup-routing script.
    // The script sets two addresses
    //  - 10.255.0.1 for the mock DHCP server
    //  - 10.255.0.200 for the QCore DHCP relay.
    //
    // The 10.255.0.1 address is currently hardcoded in the test framework but could easily be made configurable.
    // The address 10.255.0.200 will be found programmatically by QCore when it queries netlink for the IP address of veth2.
    let (gnb, qc, dn, builder, _logger) = TestFrameworkBuilder::<MockGnb>::new()
        .use_dhcp("veth2")
        .build()
        .await?;
    let dhcp_server = dn.dhcp_server();
    let mut ue = builder.ngap_ue(&gnb).registered().await?;

    let dhcp_lease_time_secs = 1;
    let ue_addr = Ipv4Addr::new(10, 255, 0, 5);

    ue.send_nas_pdu_session_establishment_request().await?;
    dhcp_server
        .hand_out_address(ue_addr, dhcp_lease_time_secs)
        .await?;
    gnb.handle_pdu_session_resource_setup(ue.gnb_ue_context())
        .await?;
    ue.receive_nas_session_accept().await?;
    wait_until_idle(&qc).await?;

    pass_through_uplink_ipv4(&ue, &dn).await?;
    pass_through_downlink_ipv4(&dn, &ue).await?;

    // Wait long enough for the DHCP lease reneval time to come up.
    async_std::task::sleep(Duration::from_millis(1000)).await;
    dhcp_server.handle_renewal(ue_addr).await
}
