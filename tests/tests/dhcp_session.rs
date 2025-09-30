use std::net::Ipv4Addr;

use qcore_tests::{MockGnb, framework::*};

#[async_std::test]
async fn dhcp_session() -> anyhow::Result<()> {
    let (gnb, qc, dn, builder, _logger) = TestFrameworkBuilder::<MockGnb>::new()
        .use_dhcp()
        .build()
        .await?;
    let dhcp_server = dn.dhcp_server();
    let mut ue = builder.ngap_ue(&gnb).registered().await?;

    ue.send_nas_pdu_session_establishment_request().await?;
    dhcp_server
        .hand_out_address(Ipv4Addr::new(10, 255, 0, 5))
        .await?;
    gnb.handle_pdu_session_resource_setup(ue.gnb_ue_context())
        .await?;
    ue.receive_nas_session_accept().await?;
    wait_until_idle(&qc).await?;

    pass_through_uplink_ipv4(&ue, &dn).await?;
    pass_through_downlink_ipv4(&dn, &ue).await
}
