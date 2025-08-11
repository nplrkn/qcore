#![allow(clippy::unusual_byte_groupings)]
use crate::PduSession;
use anyhow::{Result, bail};
use oxirush_nas::{
    Nas5gmmMessage, Nas5gmmMessageType, Nas5gsMessage, Nas5gsmMessage, Nas5gsmMessageType, NasAbba,
    NasAdditionalFGSecurityInformation, NasAuthenticationParameterAutn,
    NasAuthenticationParameterRand, NasConfigurationUpdateIndication, NasDnn,
    NasExtendedProtocolConfigurationOptions, NasFGmmCause, NasFGsIdentityType,
    NasFGsMobileIdentity, NasFGsNetworkFeatureSupport, NasFGsRegistrationResult,
    NasFGsTrackingAreaIdentityList, NasFGsmCause, NasKeySetIdentifier, NasNetworkName, NasNssai,
    NasPayloadContainer, NasPayloadContainerType, NasPduAddress, NasPduSessionIdentity2,
    NasPduSessionReactivationResult, NasPduSessionStatus, NasPduSessionType,
    NasQosFlowDescriptions, NasQosRules, NasSNssai, NasSecurityAlgorithms, NasSessionAmbr,
    NasUeSecurityCapability, encode_nas_5gs_message,
    messages::{
        NasAuthenticationRequest, NasConfigurationUpdateCommand, NasDlNasTransport, NasFGmmStatus,
        NasIdentityRequest, NasPduSessionEstablishmentAccept, NasPduSessionReleaseCommand,
        NasRegistrationAccept, NasRegistrationReject, NasSecurityModeCommand, NasServiceAccept,
        NasServiceReject,
    },
};
use security::NAS_ABBA;
use std::net::IpAddr;
use xxap::PlmnIdentity;

use super::AmfIds;

pub fn authentication_request(rand: &[u8; 16], autn: &[u8; 16], ksi: u8) -> Box<Nas5gsMessage> {
    // "The SEAF shall set the ABBA parameter as defined in Annex A.7.1."
    Box::new(Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::AuthenticationRequest,
        Nas5gmmMessage::AuthenticationRequest(NasAuthenticationRequest {
            ngksi: NasKeySetIdentifier::new(ksi),
            abba: NasAbba::new(NAS_ABBA.to_vec()),
            authentication_parameter_rand: Some(NasAuthenticationParameterRand::new(rand.to_vec())),
            authentication_parameter_autn: Some(NasAuthenticationParameterAutn::new(autn.to_vec())),
            eap_message: None,
        }),
    ))
}

pub fn identity_request() -> Box<Nas5gsMessage> {
    Box::new(Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::IdentityRequest,
        Nas5gmmMessage::IdentityRequest(NasIdentityRequest::new(NasFGsIdentityType::new(1))),
    ))
}

pub fn security_mode_command(
    replayed_ue_security_capabilities: NasUeSecurityCapability,
    ksi: u8,
) -> Box<Nas5gsMessage> {
    // Request retransmission of initial NAS message.
    let additional_fg_security_information =
        Some(NasAdditionalFGSecurityInformation::new(vec![0b00000010]));
    Box::new(Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::SecurityModeCommand,
        Nas5gmmMessage::SecurityModeCommand(NasSecurityModeCommand {
            selected_nas_security_algorithms: NasSecurityAlgorithms::new(2), // AES integrity and NULL encryption,
            ngksi: NasKeySetIdentifier::new(ksi),
            replayed_ue_security_capabilities,
            imeisv_request: None,
            selected_eps_nas_security_algorithms: None,
            additional_fg_security_information,
            eap_message: None,
            abba: None,
            replayed_s1_ue_security_capabilities: None,
        }),
    ))
}

pub fn nas_mobile_identity_guti(
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
        sst,        // SST
        0x00, 0x00, 0x00, // 24 bit SD value
        // Also offer the same SST but without SD specified
        // This is needed for OAI interop using the default config.
        0b00000001, // SST only
        sst,
    ])
}

pub fn registration_accept(
    allowed_sst: u8,
    fg_guti: NasFGsMobileIdentity,
    plmn: &PlmnIdentity,
    tac: &[u8; 3],
    reactivation_result: Option<u16>,
    current_sessions: u16,
) -> Box<Nas5gsMessage> {
    // Fake up IMS support - necessary to keep certain UEs registered.
    let fgs_network_feature_support = Some(NasFGsNetworkFeatureSupport::new(vec![0b00000001]));

    let mut tai_ie_value = vec![
        0b0_00_00000, // type of list 00, number of elements - 1 = 0 (...so 1 element)
    ];
    tai_ie_value.extend_from_slice(&plmn.0);
    tai_ie_value.extend_from_slice(tac);

    let tai_list = Some(NasFGsTrackingAreaIdentityList::new(tai_ie_value));

    let pdu_session_reactivation_result = reactivation_result
        .map(|rr| NasPduSessionReactivationResult::new(vec![(rr & 0xff) as u8, (rr >> 8) as u8]));

    // We always supply PDU session status for simplicity (even in the case where the UE knows there are no sessions).
    let pdu_session_status = Some(NasPduSessionStatus::new(vec![
        (current_sessions & 0xff) as u8,
        (current_sessions >> 8) as u8,
    ]));

    Box::new(Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::RegistrationAccept,
        Nas5gmmMessage::RegistrationAccept(NasRegistrationAccept {
            fg_guti: Some(fg_guti),
            allowed_nssai: Some(nssai(allowed_sst)),
            tai_list,
            fgs_network_feature_support,
            pdu_session_reactivation_result,
            pdu_session_status,
            ..NasRegistrationAccept::new(NasFGsRegistrationResult::new(
                vec![0b00_0_0_0_001], // no emergency, no slice-specific auth, no SMS, 3GPP access
            ))
        }),
    ))
}

pub fn registration_reject(cause: u8) -> Box<Nas5gsMessage> {
    Box::new(Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::RegistrationReject,
        Nas5gmmMessage::RegistrationReject(NasRegistrationReject::new(NasFGmmCause::new(cause))),
    ))
}

pub fn service_accept(session_status: u16, reactivation_result: Option<u16>) -> Box<Nas5gsMessage> {
    let pdu_session_status = Some(NasPduSessionStatus::new(vec![
        (session_status & 0xff) as u8,
        (session_status >> 8) as u8,
    ]));
    let pdu_session_reactivation_result = reactivation_result
        .map(|x| NasPduSessionReactivationResult::new(vec![(x & 0xff) as u8, (x >> 8) as u8]));
    Box::new(Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::ServiceAccept,
        Nas5gmmMessage::ServiceAccept(NasServiceAccept {
            pdu_session_status,
            pdu_session_reactivation_result,
            ..NasServiceAccept::new()
        }),
    ))
}

pub fn service_reject(cause: u8) -> Box<Nas5gsMessage> {
    Box::new(Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::ServiceReject,
        Nas5gmmMessage::ServiceReject(NasServiceReject {
            ..NasServiceReject::new(NasFGmmCause::new(cause))
        }),
    ))
}

pub fn fgmm_status(cause: u8) -> Box<Nas5gsMessage> {
    Box::new(Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::FGmmStatus,
        Nas5gmmMessage::FGmmStatus(NasFGmmStatus::new(NasFGmmCause::new(cause))),
    ))
}

fn session_ambr() -> NasSessionAmbr {
    // TODO - make configurable
    NasSessionAmbr::new(vec![
        // TS24.501, 9.11.4.14
        0x0a, // Unit for downlink = 256Mbps
        0x00, 0x03, // Downlink session AMBR = 768Mbps
        0x0a, // Unit for uplink = 256Mbps
        0x00, 0x03, // Uplink session AMBR = 768Mbps
    ])
}

fn authorized_qos_rules(qfi: u8) -> NasQosRules {
    let packet_filter_identifier = 0b0001;
    NasQosRules::new(vec![
        // TS24.501, 9.11.4.13
        0x01, // Qos Rule Identifier = 1
        0x00,
        0x06,         // Length of QoS rule
        0b001_1_0001, // Rule operation code 001 (create new); default Qos Rule 1; number of packet filters = 1,
        // Packet filter 1
        0b00_11_0000 | packet_filter_identifier, // Packet filter direction = 11 (bidirectional); packet filter identifier = 0001
        0x01,                                    // Length of packet filter contents
        // Packet filter 1 contents
        0b00000001, // Packet filter type = match all
        0xff,       // QoS rule precedence,
        qfi,        // spare; QFI 1
    ])
}

fn authorized_qos_flow_descriptions(qfi: u8, five_qi: u8) -> NasQosFlowDescriptions {
    NasQosFlowDescriptions::new(vec![
        // TS24.501, 9.11.4.12
        qfi,  // QFI 1
        0x20, // Create new
        0x41, // 1 parameter supplied
        0x01, // Param type = 5QI
        0x01, // Length 1
        five_qi,
    ])
}

fn nas_pdu_address(ue_ipv4: &[u8; 4]) -> NasPduAddress {
    NasPduAddress::new(vec![
        // TS24.501, 9.11.4.10
        0b0000_0_001, // spare; no SMF IPv6 link local address; PDU session type = 001 (IPv4)
        ue_ipv4[0],
        ue_ipv4[1],
        ue_ipv4[2],
        ue_ipv4[3],
    ])
}

fn nas_dnn(dnn: &[u8]) -> NasDnn {
    let mut dnn_contents = vec![dnn.len() as u8];
    dnn_contents.extend_from_slice(dnn);
    NasDnn::new(dnn_contents)
}

pub fn pdu_session_establishment_accept(
    pdu_session: &PduSession,
    pti: u8,
    sst: u8,
) -> Result<Box<Nas5gsMessage>> {
    let ue_ip_addr = pdu_session.userplane_info.ue_ip_addr;
    let IpAddr::V4(ue_ipv4) = ue_ip_addr else {
        bail!("IPv6 not implemented")
    };

    let five_qi = pdu_session.userplane_info.five_qi;
    let qfi = pdu_session.userplane_info.qfi;
    let dns_primary = &[0x08, 0x08, 0x08, 0x08];
    let dns_secondary = &[0x08, 0x08, 0x04, 0x04];

    // Work around limitation in NAS library.  SSC Mode and Selected Session Type are
    // half byte V fields (24.501, table 8.3.2.1.1).  NasPduSessionType wrongly includes
    // a type field.  However, since NasPduSessionType::encode() ORs the type field with
    // the value field we can get the right behaviour by putting the SSC mode in the type field.
    let ssc_mode_and_selected_session_type = NasPduSessionType {
        type_field: 0b0001_0000, // SSC mode 1
        value: 0b0000_0001,      // session type IPv4
    };

    let inner_message = Nas5gsMessage::new_5gsm(
        Nas5gsmMessageType::PduSessionEstablishmentAccept,
        Nas5gsmMessage::PduSessionEstablishmentAccept(NasPduSessionEstablishmentAccept {
            selected_pdu_session_type: ssc_mode_and_selected_session_type,
            authorized_qos_rules: authorized_qos_rules(qfi),
            session_ambr: session_ambr(),
            fgsm_cause: None,
            pdu_address: Some(nas_pdu_address(&ue_ipv4.octets())),
            rq_timer_value: None,
            s_nssai: Some(snssai(sst)),
            always_on_pdu_session_indication: None,
            mapped_eps_bearer_contexts: None,
            eap_message: None,
            authorized_qos_flow_descriptions: Some(authorized_qos_flow_descriptions(qfi, five_qi)),
            extended_protocol_configuration_options: Some(extended_protocol_configuration_options(
                dns_primary,
                dns_secondary,
                true,
            )),
            dnn: Some(nas_dnn(&pdu_session.dnn)),
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
    wrap_in_dl_nas_transport(pdu_session.id, &inner_message)
}

pub fn pdu_session_release_command(
    pdu_session: &PduSession,
    cause: u8,
) -> Result<Box<Nas5gsMessage>> {
    let inner_message = Nas5gsMessage::new_5gsm(
        Nas5gsmMessageType::PduSessionReleaseCommand,
        Nas5gsmMessage::PduSessionReleaseCommand(NasPduSessionReleaseCommand {
            fgsm_cause: NasFGsmCause::new(cause),
            back_off_timer_value: None,
            eap_message: None,
            fgsm_congestion_re_attempt_indicator: None,
            extended_protocol_configuration_options: None,
            access_type: None,
            service_level_aa_container: None,
        }),
        pdu_session.id,
        0,
    );
    wrap_in_dl_nas_transport(pdu_session.id, &inner_message)
}

fn wrap_in_dl_nas_transport(
    session_id: u8,
    inner_message: &Nas5gsMessage,
) -> Result<Box<Nas5gsMessage>> {
    let inner_message = encode_nas_5gs_message(inner_message)?;
    Ok(Box::new(Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::DlNasTransport,
        Nas5gmmMessage::DlNasTransport(NasDlNasTransport {
            payload_container_type: NasPayloadContainerType::new(0b0001), // 5GSM
            payload_container: NasPayloadContainer::new(inner_message),
            pdu_session_id: Some(NasPduSessionIdentity2::new(session_id)),
            additional_information: None,
            fgmm_cause: None,
            back_off_timer_value: None,
            lower_bound_timer_value: None,
        }),
    )))
}

fn extended_protocol_configuration_options(
    dns_primary: &[u8; 4],
    dns_secondary: &[u8; 4],
    include_ppp_ip_configuration_ack: bool,
) -> NasExtendedProtocolConfigurationOptions {
    let mut epco = vec![];
    if include_ppp_ip_configuration_ack {
        epco.extend_from_slice(&[
            0x80, // PPP for use with IP PDP type or IP PDN type
            0x80, 0x21, // Internet Protocol Control Protocol
            0x10, // Length = 16
            0x02, // Type = Configuration Ack
            0x00, // Identifier
            0x00, 0x10, // Length = 16
            0x81, // Primary DNS address
            0x06, // Length = 6
        ]);
        epco.extend_from_slice(dns_primary);
        epco.extend_from_slice(&[
            0x83, // Secondary DNS address
            0x06, // Length = 6
        ]);
        epco.extend_from_slice(dns_secondary);
    }

    epco.extend_from_slice(&[
        0x00, 0x0d, // DNS server address
        0x04, // Length
    ]);
    epco.extend_from_slice(dns_primary);

    epco.extend_from_slice(&[
        0x00, 0x0d, // DNS server address
        0x04, // Length
    ]);
    epco.extend_from_slice(dns_secondary);

    epco.extend_from_slice(&[
        0x00, 0x10, // Link MTU
        0x02, // Length
        0x05, 0x78, // 1400
    ]);
    NasExtendedProtocolConfigurationOptions::new(epco)
}

fn network_name(ucs2_network_name: &[u8]) -> NasNetworkName {
    let mut network_name_ie_value = vec![
        0b1_001_0_000, // coding scheme = 001: UCS2 (16 bit); add country initials = 0; number of spare bits in last octet = 000
    ];
    network_name_ie_value.extend_from_slice(ucs2_network_name);
    NasNetworkName::new(network_name_ie_value)
}

pub fn configuration_update_command(
    ucs2_network_name: Option<&[u8]>,
    fg_guti: Option<NasFGsMobileIdentity>,
) -> Box<Nas5gsMessage> {
    Box::new(Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::ConfigurationUpdateCommand,
        Nas5gmmMessage::ConfigurationUpdateCommand(NasConfigurationUpdateCommand {
            configuration_update_indication: Some(NasConfigurationUpdateIndication::new(0b00_0_1)), // spare; RED; ACK
            full_name_for_network: ucs2_network_name.map(network_name),
            fg_guti,
            ..NasConfigurationUpdateCommand::new()
        }),
    ))
}
