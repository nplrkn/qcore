use qcore_tests::MockDu;
use qcore_tests::framework::*;
use std::net::Ipv4Addr;

const PCSCF: Ipv4Addr = Ipv4Addr::new(10, 255, 1, 1);

// Without a P-CSCF configured there is nothing to offer an IMS UE, so the 'ims' DNN is
// refused with a 5GMM Status and the UE falls back to 'internet'.
#[async_std::test]
async fn ims_session_refused_when_no_pcscf() -> anyhow::Result<()> {
    let (du, _qc, _dn, builder, _logger) = init_f1ap().await?;
    let mut ue = builder.f1ap_ue(&du).build().await?;

    ue.perform_rrc_setup().await?;
    ue.handle_nas_authentication().await?;
    ue.handle_nas_security_mode().await?;
    ue.handle_rrc_security_mode().await?;
    ue.handle_capability_enquiry().await?;
    ue.handle_nas_registration_accept().await?;
    ue.handle_nas_configuration_update().await?;

    ue.use_dnn(b"ims");
    ue.send_nas_pdu_session_establishment_request().await?;

    ue.receive_nas_5gmm_status().await
}

// With --pcscf-ip set, the 'ims' DNN is accepted like any other and the PCO carries the
// P-CSCF address (24.008 container 000C) and the IM CN subsystem signalling flag (0002).
#[async_std::test]
async fn ims_session_establishment() -> anyhow::Result<()> {
    let (du, _qc, _dn, builder, _logger) = TestFrameworkBuilder::<MockDu>::new()
        .pcscf_ipv4(PCSCF)
        .build()
        .await?;
    let mut ue = builder.f1ap_ue(&du).build().await?;

    ue.perform_rrc_setup().await?;
    ue.handle_nas_authentication().await?;
    ue.handle_nas_security_mode().await?;
    ue.handle_rrc_security_mode().await?;
    ue.handle_capability_enquiry().await?;
    ue.handle_nas_registration_accept().await?;
    ue.handle_nas_configuration_update().await?;

    ue.use_dnn(b"ims");
    ue.establish_session(&du).await?;

    let pco = ue
        .last_accept_pco
        .as_ref()
        .expect("IMS accept must carry a PCO");

    let mut want = vec![0x00, 0x0c, 0x04];
    want.extend_from_slice(&PCSCF.octets());
    assert!(
        pco.windows(want.len()).any(|w| w == want),
        "P-CSCF container 000C missing from PCO {pco:02x?}"
    );
    assert!(
        pco.windows(3).any(|w| w == [0x00, 0x02, 0x00]),
        "IM CN subsystem signalling flag missing from PCO {pco:02x?}"
    );

    Ok(())
}

// The P-CSCF belongs to the IMS session only: an 'internet' session on the same core must
// not carry it, or the UE binds its IMS stack to the wrong bearer.
#[async_std::test]
async fn internet_session_carries_no_pcscf() -> anyhow::Result<()> {
    let (du, _qc, _dn, builder, _logger) = TestFrameworkBuilder::<MockDu>::new()
        .pcscf_ipv4(PCSCF)
        .build()
        .await?;
    let mut ue = builder.f1ap_ue(&du).build().await?;

    ue.perform_rrc_setup().await?;
    ue.handle_nas_authentication().await?;
    ue.handle_nas_security_mode().await?;
    ue.handle_rrc_security_mode().await?;
    ue.handle_capability_enquiry().await?;
    ue.handle_nas_registration_accept().await?;
    ue.handle_nas_configuration_update().await?;

    ue.establish_session(&du).await?;

    let pco = ue
        .last_accept_pco
        .as_ref()
        .expect("accept must carry a PCO");
    assert!(
        !pco.windows(2).any(|w| w == [0x00, 0x0c]),
        "internet session must not carry a P-CSCF, got PCO {pco:02x?}"
    );

    Ok(())
}
