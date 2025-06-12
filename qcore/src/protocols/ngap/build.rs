//! build_f1ap - construction of F1AP messages
use anyhow::Result;
use asn1_per::*;
use ngap::*;
use xxap::{GtpTunnel, PduSessionId, PlmnIdentity, Snssai, TransportLayerAddress};
use crate::data::PduSession;

pub fn ng_setup_response(
    guami: &Guami,
    plmn_identity: &PlmnIdentity,
    sst: u8,
) -> Result<NgSetupResponse> {
    let slice_support_list = SliceSupportList(nonempty![
        SliceSupportItem {
            snssai: Snssai(sst, None).into()
        },
        SliceSupportItem {
            snssai: Snssai(sst, Some([0, 0, 0])).into()
        }
    ]);
    Ok(NgSetupResponse {
        amf_name: AmfName("QCore".to_string()),
        served_guami_list: ServedGuamiList(nonempty![ServedGuamiItem {
            guami: guami.clone(),
            backup_amf_name: None,
            guami_type: None
        }]),
        relative_amf_capacity: RelativeAmfCapacity(100),
        plmn_support_list: PlmnSupportList(nonempty![PlmnSupportItem {
            plmn_identity: plmn_identity.clone(),
            slice_support_list,
            npn_support: None,
            extended_slice_support_list: None,
        }]),
        criticality_diagnostics: None,
        ue_retention_information: None,
        iab_supported: None,
        extended_amf_name: None,
    })
}

pub fn initial_context_setup_request(
    amf_ue_ngap_id: AmfUeNgapId,
    ran_ue_ngap_id: RanUeNgapId,
    guami: Guami,
    kgnb: &[u8; 32],
    sst: u8,
    ue_security_capabilities: &crate::UeSecurityCapabilities,
) -> Box<InitialContextSetupRequest> {
    let allowed_nssai = AllowedNssai(nonempty![
        AllowedNssaiItem {
            snssai: Snssai(sst, None).into()
        },
        AllowedNssaiItem {
            snssai: Snssai(sst, Some([0, 0, 0])).into()
        }
    ]);

    // These are 16 bit bitstrings.  Our UeSecurityCapabilities type follows the NAS format from 24.501, Figure 9.11.3.54.1.
    // This needs to be converted into the format from 38.413, 9.3.1.86.
    // We blank the EUTRA fields, since we do not support 4G.
    let nr_encryption_algorithms =
        NrEncryptionAlgorithms(BitVec::from_slice(&[ue_security_capabilities[0] << 1, 0]));
    let nr_integrity_protection_algorithms =
        NrIntegrityProtectionAlgorithms(BitVec::from_slice(&[ue_security_capabilities[1] << 1, 0]));
    let eutr_aencryption_algorithms = EutrAencryptionAlgorithms(BitVec::from_slice(&[0u8; 2]));
    let eutr_aintegrity_protection_algorithms =
        EutrAintegrityProtectionAlgorithms(BitVec::from_slice(&[0u8; 2]));

    Box::new(InitialContextSetupRequest {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        old_amf: None,
        ue_aggregate_maximum_bit_rate: None,
        core_network_assistance_information_for_inactive: None,
        guami,
        pdu_session_resource_setup_list_cxt_req: None,
        allowed_nssai,
        ue_security_capabilities: UeSecurityCapabilities {
            nr_encryption_algorithms,
            nr_integrity_protection_algorithms,
            eutr_aencryption_algorithms,
            eutr_aintegrity_protection_algorithms,
        },
        security_key: SecurityKey(BitVec::from_slice(kgnb)),
        trace_activation: None,
        mobility_restriction_list: None,
        ue_radio_capability: None,
        index_to_rfsp: None,
        masked_imeisv: None,
        nas_pdu: None,
        emergency_fallback_indicator: None,
        rrc_inactive_transition_report_request: None,
        ue_radio_capability_for_paging: None,
        redirection_voice_fallback: None,
        location_reporting_request_type: None,
        cn_assisted_ran_tuning: None,
        srvcc_operation_possible: None,
        iab_authorized: None,
        enhanced_coverage_restriction: None,
        extended_connected_time: None,
        ue_differentiation_info: None,
        nr_v2x_services_authorized: None,
        ltev2x_services_authorized: None,
        nr_ue_sidelink_aggregate_maximum_bitrate: None,
        lte_ue_sidelink_aggregate_maximum_bitrate: None,
        pc5_qos_parameters: None,
        c_emode_brestricted: None,
        ue_up_c_iot_support: None,
        rg_level_wireline_access_characteristics: None,
        management_based_mdt_plmn_list: None,
        ue_radio_capability_id: None,
    })
}

pub fn downlink_nas_transport(
    amf_ue_ngap_id: AmfUeNgapId,
    ran_ue_ngap_id: RanUeNgapId,
    nas_pdu: Vec<u8>,
) -> Box<DownlinkNasTransport> {
    Box::new(DownlinkNasTransport {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        old_amf: None,
        ran_paging_priority: None,
        nas_pdu: NasPdu(nas_pdu),
        mobility_restriction_list: None,
        index_to_rfsp: None,
        ue_aggregate_maximum_bit_rate: None,
        allowed_nssai: None,
        srvcc_operation_possible: None,
        enhanced_coverage_restriction: None,
        extended_connected_time: None,
        ue_differentiation_info: None,
        c_emode_brestricted: None,
        ue_radio_capability: None,
        ue_capability_info_request: None,
        end_indication: None,
        ue_radio_capability_id: None,
    })
}

pub fn pdu_session_resource_setup_request(
    amf_ue_ngap_id: AmfUeNgapId,
    ran_ue_ngap_id: RanUeNgapId,
    pdu_session: &PduSession,
    transport_layer_address: TransportLayerAddress,
    nas: Vec<u8>,
) -> Result<Box<PduSessionResourceSetupRequest>> {
    let pdu_session_resource_setup_request_transfer = PduSessionResourceSetupRequestTransfer {
        pdu_session_aggregate_maximum_bit_rate: Some(PduSessionAggregateMaximumBitRate {
            pdu_session_aggregate_maximum_bit_rate_dl: BitRate(768_000_000),
            pdu_session_aggregate_maximum_bit_rate_ul: BitRate(768_000_000),
        }),
        ul_ngu_up_tnl_information: UpTransportLayerInformation::GtpTunnel(GtpTunnel {
            transport_layer_address,
            gtp_teid: pdu_session.userplane_info.uplink_gtp_teid,
        }),
        additional_ul_ngu_up_tnl_information: None,
        data_forwarding_not_possible: None,
        pdu_session_type: PduSessionType::Ipv4,
        security_indication: None,
        network_instance: None,
        qos_flow_setup_request_list: QosFlowSetupRequestList(nonempty![QosFlowSetupRequestItem {
            qos_flow_identifier: QosFlowIdentifier(1),
            qos_flow_level_qos_parameters: QosFlowLevelQosParameters {
                qos_characteristics: QosCharacteristics::NonDynamic5qi(NonDynamic5qiDescriptor {
                    five_qi: FiveQi(pdu_session.userplane_info.five_qi),
                    priority_level_qos: None,
                    averaging_window: None,
                    maximum_data_burst_volume: None,
                    cn_packet_delay_budget_dl: None,
                    cn_packet_delay_budget_ul: None
                }),
                allocation_and_retention_priority: AllocationAndRetentionPriority {
                    priority_level_arp: PriorityLevelArp(8),
                    pre_emption_capability: PreEmptionCapability::ShallNotTriggerPreEmption,
                    pre_emption_vulnerability: PreEmptionVulnerability::PreEmptable
                },
                gbr_qos_information: None,
                reflective_qos_attribute: None,
                additional_qos_flow_information: None,
                qos_monitoring_request: None,
                qos_monitoring_reporting_frequency: None
            },
            e_rab_id: None,
            tsc_traffic_characteristics: None,
            redundant_qos_flow_indicator: None
        }]),
        common_network_instance: None,
        direct_forwarding_path_availability: None,
        redundant_ul_ngu_up_tnl_information: None,
        additional_redundant_ul_ngu_up_tnl_information: None,
        redundant_common_network_instance: None,
        redundant_pdu_session_information: None,
    }
    .as_bytes()?;
    Ok(Box::new(PduSessionResourceSetupRequest {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        ran_paging_priority: None,
        nas_pdu: None,
        pdu_session_resource_setup_list_su_req: PduSessionResourceSetupListSuReq(nonempty![
            PduSessionResourceSetupItemSuReq {
                pdu_session_id: PduSessionId(pdu_session.id),
                pdu_session_nas_pdu: Some(NasPdu(nas)),
                snssai: pdu_session.snssai.into(),
                pdu_session_resource_setup_request_transfer
            }
        ]),
        ue_aggregate_maximum_bit_rate: Some(UeAggregateMaximumBitRate {
            ue_aggregate_maximum_bit_rate_dl: BitRate(768_000_000),
            ue_aggregate_maximum_bit_rate_ul: BitRate(768_000_000),
        }),
    }))
}
