use anyhow::Result;
use oxirush_nas::{
    Nas5gmmMessage, Nas5gmmMessageType, Nas5gsMessage, Nas5gsmMessage, Nas5gsmMessageType,
    NasAuthenticationResponseParameter, NasDeRegistrationType, NasFGsMobileIdentity,
    NasFGsRegistrationType, NasFGsmCapability, NasIntegrityProtectionMaximumDataRate,
    NasPayloadContainer, NasPayloadContainerType, NasPduSessionType, NasSscMode,
    NasUeSecurityCapability, encode_nas_5gs_message,
    messages::{
        Nas5gmmHeader, Nas5gsmHeader, NasAuthenticationResponse, NasDeregistrationRequestFromUe,
        NasPduSessionEstablishmentRequest, NasRegistrationComplete, NasRegistrationRequest,
        NasSecurityModeComplete, NasUlNasTransport,
    },
};

// 5GS registration type value (octet 1, bits 1 to 3) (9.11.3.7.1)
pub struct FivegsRegistrationType;
#[allow(dead_code)]
impl FivegsRegistrationType {
    pub const INITIAL_REGISTRATION: u8 = 0b001;
    pub const MOBILITY_REGISTRATION_UPDATING: u8 = 0b010;
    pub const PERIODIC_REGISTRATION_UPDATING: u8 = 0b011;
    pub const EMERGENCY_REGISTRATION: u8 = 0b100;
}

// Follow-on request bit (FOR) (octet 1, bit 4) (9.11.3.7.1)
pub struct FollowOnRequest;
#[allow(dead_code)]
impl FollowOnRequest {
    pub const NOT_PENDING: u8 = 0b0;
    pub const PENDING: u8 = 0b1;
}

// 24.007, table 11.2.3.1A.1
pub struct ExtendedProtocolDiscriminator;
impl ExtendedProtocolDiscriminator {
    pub const FIVEGSM: u8 = 0b00101110;
    pub const FIVEGMM: u8 = 0b01111110;
}

// 24.501 table 9.3.1
pub struct SecurityHeaderType;
#[allow(dead_code)]
impl SecurityHeaderType {
    pub const PLAIN_5GS_NAS_MESSAGE_NOT_SECURITY_PROTECTED: u8 = 0b0000;
    pub const INTEGRITY_PROTECTED: u8 = 0b0001;
    pub const INTEGRITY_PROTECTED_AND_CIPHERED: u8 = 0b0010;
    pub const INTEGRITY_PROTECTED_WITH_NEW_5G_NAS_SECURITY_CONTEXT: u8 = 0b0011;
    pub const INTEGRITY_PROTECTED_AND_CIPHERED_WITH_NEW_5G_NAS_SECURITY_CONTEXT: u8 = 0b0100;
}

pub fn registration_request(imsi: &String) -> Result<Vec<u8>> {
    // Get the MSIN out of the IMSI.
    let msin: Vec<u8> = imsi[5..imsi.len()]
        .chars()
        .map(|c| c.to_digit(10).unwrap() as u8)
        .collect();
    assert!(msin.len() == 10);

    let message = Nas5gmmMessage::RegistrationRequest(NasRegistrationRequest {
        fgs_registration_type: NasFGsRegistrationType::new(
            (FollowOnRequest::PENDING << 3) | FivegsRegistrationType::INITIAL_REGISTRATION,
        ),
        fgs_mobile_identity: NasFGsMobileIdentity::new(vec![
            // Figure 9.11.3.4.3 and 9.11.3.4.3a of TS 24.501.
            0x01, // SUPI
            0x02,
            0xf8,
            0x39, // MCC and MNC = 208, 93
            0xf0,
            0xff, // Routing indicator digits = 0
            0x00, // Protection scheme: 0000 null scheme
            0x00, // Home network public key identifier
            msin[0] | msin[1] << 4,
            msin[2] | msin[3] << 4,
            msin[4] | msin[5] << 4,
            msin[6] | msin[7] << 4,
            msin[8] | msin[9] << 4,
        ]),
        non_current_native_nas_key_set_identifier: None,
        fgmm_capability: None,
        ue_security_capability: Some(NasUeSecurityCapability::new(vec![
            0b10000000, // 5G EA0 only
            0b00100000, // 5G IA2 only
        ])),
        requested_nssai: None,
        last_visited_registered_tai: None,
        s1_ue_network_capability: None,
        uplink_data_status: None,
        pdu_session_status: None,
        mico_indication: None,
        ue_status: None,
        additional_guti: None,
        allowed_pdu_session_status: None,
        ue_usage_setting: None,
        requested_drx_parameters: None,
        eps_nas_message_container: None,
        ladn_indication: None,
        payload_container_type: None,
        payload_container: None,
        network_slicing_indication: None,
        fgs_update_type: None,
        mobile_station_classmark_2: None,
        supported_codecs: None,
        nas_message_container: None,
        eps_bearer_context_status: None,
        requested_extended_drx_parameters: None,
        t3324_value: None,
        ue_radio_capability_id: None,
        requested_mapped_nssai: None,
        additional_information_requested: None,
        requested_wus_assistance_information: None,
        nfgc_indication: None,
        requested_nb_n1_mode_drx_parameters: None,
        ue_request_type: None,
        paging_restriction: None,
        service_level_aa_container: None,
        nid: None,
        ms_determined_plmn_with_disaster_condition: None,
        requested_peips_assistance_information: None,
        requested_t3512_value: None,
    });

    let message = Nas5gsMessage::Gmm(
        Nas5gmmHeader {
            extended_protocol_discriminator: ExtendedProtocolDiscriminator::FIVEGMM,
            security_header_type: SecurityHeaderType::PLAIN_5GS_NAS_MESSAGE_NOT_SECURITY_PROTECTED,
            message_type: Nas5gmmMessageType::RegistrationRequest,
        },
        message,
    );
    Ok(encode_nas_5gs_message(&message)?)
}

pub fn authentication_response() -> Result<Vec<u8>> {
    let message = Nas5gmmMessage::AuthenticationResponse(NasAuthenticationResponse {
        authentication_response_parameter: Some(NasAuthenticationResponseParameter::new(vec![])),
        eap_message: None,
    });

    let message = Nas5gsMessage::Gmm(
        Nas5gmmHeader {
            extended_protocol_discriminator: ExtendedProtocolDiscriminator::FIVEGMM,
            security_header_type: SecurityHeaderType::PLAIN_5GS_NAS_MESSAGE_NOT_SECURITY_PROTECTED,
            message_type: Nas5gmmMessageType::AuthenticationResponse {},
        },
        message,
    );
    Ok(encode_nas_5gs_message(&message)?)
}

pub fn security_mode_complete() -> Result<Vec<u8>> {
    let message = Nas5gsMessage::Gmm(
        Nas5gmmHeader {
            extended_protocol_discriminator: ExtendedProtocolDiscriminator::FIVEGMM,
            security_header_type: SecurityHeaderType::PLAIN_5GS_NAS_MESSAGE_NOT_SECURITY_PROTECTED,
            message_type: Nas5gmmMessageType::SecurityModeComplete {},
        },
        Nas5gmmMessage::SecurityModeComplete(NasSecurityModeComplete::new()),
    );
    Ok(encode_nas_5gs_message(&message)?)
}

pub fn registration_complete() -> Result<Vec<u8>> {
    let message = Nas5gsMessage::Gmm(
        Nas5gmmHeader {
            extended_protocol_discriminator: ExtendedProtocolDiscriminator::FIVEGMM,
            security_header_type: SecurityHeaderType::PLAIN_5GS_NAS_MESSAGE_NOT_SECURITY_PROTECTED,
            message_type: Nas5gmmMessageType::RegistrationComplete {},
        },
        Nas5gmmMessage::RegistrationComplete(NasRegistrationComplete::new()),
    );
    Ok(encode_nas_5gs_message(&message)?)
}

pub fn pdu_session_establishment_request() -> Result<Vec<u8>> {
    // See https://www.sharetechnote.com/html/5G/5G_PDUSessionEstablishment.html for an example.
    let inner_message = Nas5gsMessage::Gsm(
        Nas5gsmHeader {
            extended_protocol_discriminator: ExtendedProtocolDiscriminator::FIVEGSM,
            message_type: Nas5gsmMessageType::PduSessionEstablishmentRequest,
            pdu_session_identity: 1,
            procedure_transaction_identity: 23,
        },
        Nas5gsmMessage::PduSessionEstablishmentRequest(NasPduSessionEstablishmentRequest {
            integrity_protection_maximum_data_rate: NasIntegrityProtectionMaximumDataRate::new(
                0xffff,
            ),
            pdu_session_type: Some(NasPduSessionType::new(0b001)), // IPv4 - 9.11.4.11
            ssc_mode: Some(NasSscMode::new(0b001)),                // SSC Mode 1 - 9.11.4.16.1
            fgsm_capability: Some(NasFGsmCapability::new(
                vec![0x00], // No reflective QoS, multi-homed IPv6, Ethernet S1, TPMIC
            )),
            maximum_number_of_supported_packet_filters: None,
            always_on_pdu_session_requested: None,
            sm_pdu_dn_request_container: None,
            extended_protocol_configuration_options: None,
            ip_header_compression_configuration: None,
            ds_tt_ethernet_port_mac_address: None,
            ue_ds_tt_residence_time: None,
            port_management_information_container: None,
            ethernet_header_compression_configuration: None,
            suggested_interface_identifier: None,
            service_level_aa_container: None,
            requested_mbs_container: None,
            pdu_session_pair_id: None,
            rsn: None,
        }),
    );
    let inner_message = encode_nas_5gs_message(&inner_message)?;

    let outer_message = Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::UlNasTransport,
        Nas5gmmMessage::UlNasTransport(NasUlNasTransport {
            payload_container_type: NasPayloadContainerType::new(0b0001), // 5GSM
            payload_container: NasPayloadContainer::new(inner_message),
            pdu_session_id: None,
            old_pdu_session_id: None,
            request_type: None,
            s_nssai: None,
            dnn: None,
            additional_information: None,
            ma_pdu_session_information: None,
            release_assistance_indication: None,
        }),
    );
    Ok(encode_nas_5gs_message(&outer_message)?)
}

pub fn deregistration_request() -> Result<Vec<u8>> {
    let dereg_type = 0b0001; // 3GPP normal dereg - TS24.501, table 9.11.3.20.1
    let guti_mobile_identity = vec![
        0b11110_010, // octet 4 , type of identity = 010 = GUTI
        0x00,        // TODO - populate this properly with the UE's GUTI
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ];

    let message = Nas5gsMessage::Gmm(
        Nas5gmmHeader {
            extended_protocol_discriminator: ExtendedProtocolDiscriminator::FIVEGMM,
            security_header_type: SecurityHeaderType::PLAIN_5GS_NAS_MESSAGE_NOT_SECURITY_PROTECTED,
            message_type: Nas5gmmMessageType::DeregistrationRequestFromUe {},
        },
        Nas5gmmMessage::DeregistrationRequestFromUe(NasDeregistrationRequestFromUe::new(
            NasDeRegistrationType::new(dereg_type),
            NasFGsMobileIdentity::new(guti_mobile_identity),
        )),
    );
    Ok(encode_nas_5gs_message(&message)?)
}
