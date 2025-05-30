#![allow(clippy::unusual_byte_groupings)]
use crate::PduSession;
use anyhow::{Result, bail};
use f1ap::PlmnIdentity;
use oxirush_nas::{
    Nas5gmmMessage, Nas5gmmMessageType, Nas5gsMessage, Nas5gsmMessage, Nas5gsmMessageType, NasAbba,
    NasAdditionalFGSecurityInformation, NasAuthenticationParameterAutn,
    NasAuthenticationParameterRand, NasDnn, NasFGmmCause, NasFGsMobileIdentity,
    NasFGsNetworkFeatureSupport, NasFGsRegistrationResult, NasKeySetIdentifier, NasNssai,
    NasPayloadContainer, NasPayloadContainerType, NasPduAddress, NasPduSessionType,
    NasQosFlowDescriptions, NasQosRules, NasSNssai, NasSecurityAlgorithms, NasSessionAmbr,
    NasUeSecurityCapability, encode_nas_5gs_message,
    messages::{
        NasAuthenticationRequest, NasDlNasTransport, NasFGmmStatus,
        NasPduSessionEstablishmentAccept, NasRegistrationAccept, NasRegistrationReject,
        NasSecurityModeCommand,
    },
};
use security::NAS_ABBA;
use std::net::IpAddr;

use super::AmfIds;

pub fn authentication_request(rand: &[u8; 16], autn: &[u8; 16]) -> Nas5gsMessage {
    // "The SEAF shall set the ABBA parameter as defined in Annex A.7.1."
    Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::AuthenticationRequest,
        Nas5gmmMessage::AuthenticationRequest(NasAuthenticationRequest {
            ngksi: NasKeySetIdentifier::new(0),
            abba: NasAbba::new(NAS_ABBA.to_vec()),
            authentication_parameter_rand: Some(NasAuthenticationParameterRand::new(rand.to_vec())),
            authentication_parameter_autn: Some(NasAuthenticationParameterAutn::new(autn.to_vec())),
            eap_message: None,
        }),
    )
}

pub fn security_mode_command(
    replayed_ue_security_capabilities: NasUeSecurityCapability,
) -> Nas5gsMessage {
    // Request retransmission of initial NAS message.
    let additional_fg_security_information =
        Some(NasAdditionalFGSecurityInformation::new(vec![0b00000010]));
    Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::SecurityModeCommand,
        Nas5gmmMessage::SecurityModeCommand(NasSecurityModeCommand {
            selected_nas_security_algorithms: NasSecurityAlgorithms::new(2), // AES integrity and NULL encryption,
            ngksi: NasKeySetIdentifier { value: 0 },
            replayed_ue_security_capabilities,
            imeisv_request: None,
            selected_eps_nas_security_algorithms: None,
            additional_fg_security_information,
            eap_message: None,
            abba: None,
            replayed_s1_ue_security_capabilities: None,
        }),
    )
}

fn nas_mobile_identity_guti(
    plmn: &PlmnIdentity,
    amf_ids: &AmfIds,
    tmsi: &[u8; 4],
) -> NasFGsMobileIdentity {
    // See TS24.501, Figure 9.11.3.4.1
    let mut guti = vec![0b11110_010]; // octet 4 , type of identity = 010 = GUTI
    guti.extend_from_slice(&plmn.0);
    guti.extend_from_slice(&amf_ids.0);
    guti.extend_from_slice(tmsi);
    NasFGsMobileIdentity::new(guti)
}

pub fn snssai(sst: u8) -> NasSNssai {
    // TS24.501, 9.11.2.8.
    NasSNssai::new(vec![
        sst, 0x00, // 24 bit SD value
        0x00, 0x00,
    ])
}

pub fn nssai(sst: u8) -> NasNssai {
    // TS24.501, 9.11.3.37 defines as a list of NSSAI length and value from TS24.501, 9.11.2.8.
    NasNssai::new(vec![
        0b00000100, // SST and SD
        sst, 0x00, // 24 bit SD value
        0x00, 0x00,
    ])
}

pub fn registration_accept(
    allowed_sst: u8,
    plmn: &PlmnIdentity,
    amf_ids: &AmfIds,
    tmsi: &[u8; 4],
) -> Nas5gsMessage {
    let fg_guti = Some(nas_mobile_identity_guti(plmn, amf_ids, tmsi));

    // Fake up IMS support - necessary to keep certain UEs registered.
    let fgs_network_feature_support = Some(NasFGsNetworkFeatureSupport::new(vec![0b00000001]));

    Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::RegistrationAccept,
        Nas5gmmMessage::RegistrationAccept(NasRegistrationAccept {
            fg_guti,
            allowed_nssai: Some(nssai(allowed_sst)),
            fgs_network_feature_support,
            ..NasRegistrationAccept::new(NasFGsRegistrationResult::new(
                vec![0b00_0_0_0_001], // no emergency, no slice-specific auth, no SMS, 3GPP access
            ))
        }),
    )
}

pub fn registration_reject(cause: u8) -> Nas5gsMessage {
    Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::RegistrationReject,
        Nas5gmmMessage::RegistrationReject(NasRegistrationReject::new(NasFGmmCause::new(cause))),
    )
}

pub fn fgmm_status(cause: u8) -> Nas5gsMessage {
    Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::FGmmStatus,
        Nas5gmmMessage::FGmmStatus(NasFGmmStatus::new(NasFGmmCause::new(cause))),
    )
}

pub fn pdu_session_establishment_accept(
    pdu_session: &PduSession,
    pti: u8,
    sst: u8,
) -> Result<Nas5gsMessage> {
    let ue_ip_addr = pdu_session.userplane_info.ue_ip_addr;
    let IpAddr::V4(ue_ipv4) = ue_ip_addr else {
        bail!("IPv6 not implemented")
    };

    // TODO - make configurable
    let session_ambr = NasSessionAmbr::new(vec![
        // TS24.501, 9.11.4.14
        0b00000110, // Unit for downlink = Mbps
        0x00, 0x01,       // Downlink session AMBR = 1 Mbps
        0b00000110, // Unit for uplink = Mbps
        0x00, 0x01, // Uplink session AMBR = 1 Mbps
    ]);

    let qfi_1 = 0b00_000001;
    let authorized_qos_rules = NasQosRules::new(vec![
        // TS24.501, 9.11.4.13
        0x01, // Qos Rule Identifier = 1
        0x00,
        0x06,         // Length of QoS rule
        0b001_1_0001, // Rule operation code 001 (create new); default Qos Rule 1; number of packet filters = 1,
        // Packet filter 1
        0b00_11_1111, // Packet filter direction = 11 (bidirectional); packet filter identifier = 1111
        0x01,         // Length of packet filter contents
        // Packet filter 1 contents
        0b00000001, // Packet filter type = match all
        0xff,       // QoS rule precedence,
        qfi_1,      // spare; QFI 1
    ]);

    let five_qi = pdu_session.userplane_info.five_qi;
    let authorized_qos_flow_descriptions = Some(NasQosFlowDescriptions::new(vec![
        // TS24.501, 9.11.4.12
        qfi_1, // QFI 1
        0x20,  // Create new
        0x41,  // 1 parameter supplied
        0x01,  // Param type = 5QI
        0x01,  // Length 1
        five_qi,
    ]));

    let pdu_address = Some(NasPduAddress::new(vec![
        // TS24.501, 9.11.4.10
        0b0000_0_001, // spare; no SMF IPv6 link local address; PDU session type = 001 (IPv4)
        ue_ipv4.octets()[0],
        ue_ipv4.octets()[1],
        ue_ipv4.octets()[2],
        ue_ipv4.octets()[3],
    ]));

    let dnn = Some(NasDnn::new(pdu_session.dnn.clone()));

    let inner_message = Nas5gsMessage::new_5gsm(
        Nas5gsmMessageType::PduSessionEstablishmentAccept,
        Nas5gsmMessage::PduSessionEstablishmentAccept(NasPduSessionEstablishmentAccept {
            selected_pdu_session_type: NasPduSessionType::new(0b001), // IPv4
            authorized_qos_rules,
            session_ambr,
            fgsm_cause: None,
            pdu_address,
            rq_timer_value: None,
            s_nssai: Some(snssai(sst)),
            always_on_pdu_session_indication: None,
            mapped_eps_bearer_contexts: None,
            eap_message: None,
            authorized_qos_flow_descriptions,
            extended_protocol_configuration_options: None,
            dnn,
            fgsm_network_feature_support: None,
            serving_plmn_rate_control: None,
            atsss_container: None,
            control_plane_only_indication: None,
            ip_header_compression_configuration: None,
            ethernet_header_compression_configuration: None,
            service_level_aa_container: None,
            received_mbs_container: None,
        }),
        pdu_session.id,
        pti,
    );
    let inner_message = encode_nas_5gs_message(&inner_message)?;
    let outer_message = Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::DlNasTransport,
        Nas5gmmMessage::DlNasTransport(NasDlNasTransport {
            payload_container_type: NasPayloadContainerType::new(0b0001), // 5GSM
            payload_container: NasPayloadContainer::new(inner_message),
            pdu_session_id: None,
            additional_information: None,
            fgmm_cause: None,
            back_off_timer_value: None,
            lower_bound_timer_value: None,
        }),
    );
    Ok(outer_message)
}
