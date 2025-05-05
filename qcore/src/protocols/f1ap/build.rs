//! build_f1ap - construction of F1AP messages
use crate::{PduSession, UeContext};
use anyhow::Result;
use asn1_per::*;
use f1ap::*;
use rrc::{
    CellReselectionInfoCommon, CellReselectionPriority, CellReselectionServingFreqInfo,
    IntraFreqCellReselectionInfo, QHyst, QRxLevMin,
};
use xxap::{GtpTunnel, PduSessionId, Snssai, TransportLayerAddress};

pub fn f1_setup_response(
    r: F1SetupRequest,
    gnb_cu_name: Option<String>,
) -> Result<F1SetupResponse> {
    // Ask for all served cells to be activated.
    let sib2 = build_sib2().into_bytes()?;
    let cells_to_be_activated_list = r.gnb_du_served_cells_list.map(|cells| {
        CellsToBeActivatedList(
            cells
                .0
                .map(|ref x| served_cell_to_activated(x, sib2.clone())),
        )
    });
    Ok(F1SetupResponse {
        transaction_id: r.transaction_id,
        gnb_cu_rrc_version: RrcVersion {
            latest_rrc_version: bitvec![u8, Msb0;0, 0, 0],
            latest_rrc_version_enhanced: None,
        },
        gnb_cu_name: gnb_cu_name.map(GnbCuName),
        cells_to_be_activated_list,
        transport_layer_address_info: None,
        ul_bh_non_up_traffic_mapping: None,
        bap_address: None,
        extended_gnb_du_name: None,
    })
}

pub fn gnb_du_configuration_update_acknowledge(
    transaction_id: TransactionId,
) -> GnbDuConfigurationUpdateAcknowledge {
    GnbDuConfigurationUpdateAcknowledge {
        transaction_id,
        cells_to_be_activated_list: None,
        criticality_diagnostics: None,
        cells_to_be_deactivated_list: None,
        transport_layer_address_info: None,
        ul_bh_non_up_traffic_mapping: None,
        bap_address: None,
    }
}

pub fn dl_rrc_message_transfer(
    ue_id: u32,
    gnb_du_ue_f1ap_id: GnbDuUeF1apId,
    rrc_container: RrcContainer,
    srb_id: SrbId,
) -> DlRrcMessageTransfer {
    DlRrcMessageTransfer {
        gnb_cu_ue_f1ap_id: GnbCuUeF1apId(ue_id),
        gnb_du_ue_f1ap_id,
        old_gnb_du_ue_f1ap_id: None,
        srb_id,
        execute_duplication: None,
        rrc_container,
        rat_frequency_priority_information: None,
        rrc_delivery_status_request: None,
        ue_context_not_retrievable: None,
        redirected_rrc_message: None,
        plmn_assistance_info_for_net_shar: None,
        new_gnb_cu_ue_f1ap_id: None,
        additional_rrm_priority_index: None,
    }
}

fn build_sib2() -> rrc::Sib2 {
    rrc::Sib2 {
        cell_reselection_info_common: CellReselectionInfoCommon {
            nrof_ss_blocks_to_average: None,
            abs_thresh_ss_blocks_consolidation: None,
            range_to_best_cell: None,
            q_hyst: QHyst::Db1,
            speed_state_reselection_pars: None,
        },
        cell_reselection_serving_freq_info: CellReselectionServingFreqInfo {
            s_non_intra_search_p: None,
            s_non_intra_search_q: None,
            thresh_serving_low_p: rrc::ReselectionThreshold(2),
            thresh_serving_low_q: None,
            cell_reselection_priority: CellReselectionPriority(2),
            cell_reselection_sub_priority: None,
        },
        intra_freq_cell_reselection_info: IntraFreqCellReselectionInfo {
            q_rx_lev_min: QRxLevMin(-50),
            q_rx_lev_min_sul: None,
            q_qual_min: None,
            s_intra_search_p: rrc::ReselectionThreshold(2),
            s_intra_search_q: None,
            t_reselection_nr: rrc::TReselection(2),
            frequency_band_list: None,
            frequency_band_list_sul: None,
            p_max: None,
            smtc: None,
            ss_rssi_measurement: None,
            ssb_to_measure: None,
            derive_ssb_index_from_cell: true,
        },
    }
}

fn served_cell_to_activated(
    served_cell: &GnbDuServedCellsItem,
    sib_2: Vec<u8>,
) -> CellsToBeActivatedListItem {
    let served_cell_information = &served_cell.served_cell_information;
    let nr_pci = Some(served_cell_information.nr_pci);

    CellsToBeActivatedListItem {
        nr_cgi: served_cell_information.nr_cgi.clone(),
        nr_pci,
        gnb_cu_system_information: Some(GnbCuSystemInformation {
            sib_type_to_be_updated_list: nonempty![SibTypeToBeUpdatedListItem {
                sib_type: 2,
                sib_message: sib_2,
                value_tag: 0,
                area_scope: None
            }],
            system_information_area_id: None,
        }),
        available_plmn_list: None,
        extended_available_plmn_list: None,
        iab_info_iab_donor_cu: None,
        available_snpn_id_list: None,
    }
}

pub fn drb_to_be_setup_item(
    snssai: Snssai,
    gtp_tunnel: GtpTunnel,
    pdu_session_id: u8,
    qfi: u8,
) -> DrbsToBeSetupItem {
    DrbsToBeSetupItem {
        drb_id: DrbId(1),
        qos_information: QosInformation::DrbInformation(DrbInformation {
            drb_qos: QosFlowLevelQosParameters {
                qos_characteristics: QosCharacteristics::NonDynamic5qi(NonDynamic5qiDescriptor {
                    five_qi: 9,
                    qos_priority_level: None,
                    averaging_window: None,
                    max_data_burst_volume: None,
                    cn_packet_delay_budget_downlink: None,
                    cn_packet_delay_budget_uplink: None,
                }),
                ngran_allocation_retention_priority: NgranAllocationAndRetentionPriority {
                    priority_level: PriorityLevel(14),
                    pre_emption_capability: PreEmptionCapability::MayTriggerPreEmption,
                    pre_emption_vulnerability: PreEmptionVulnerability::NotPreEmptable,
                },
                gbr_qos_flow_information: None,
                reflective_qos_attribute: None,
                pdu_session_id: Some(PduSessionId(pdu_session_id)),
                ulpdu_session_aggregate_maximum_bit_rate: None,
                qos_monitoring_request: None,
            },
            snssai: snssai.into(),
            notification_control: None,
            flows_mapped_to_drb_list: FlowsMappedToDrbList(nonempty![FlowsMappedToDrbItem {
                qos_flow_identifier: QosFlowIdentifier(qfi),
                qos_flow_level_qos_parameters: QosFlowLevelQosParameters {
                    qos_characteristics: QosCharacteristics::NonDynamic5qi(
                        NonDynamic5qiDescriptor {
                            five_qi: 9,
                            qos_priority_level: None,
                            averaging_window: None,
                            max_data_burst_volume: None,
                            cn_packet_delay_budget_downlink: None,
                            cn_packet_delay_budget_uplink: None,
                        },
                    ),
                    ngran_allocation_retention_priority: NgranAllocationAndRetentionPriority {
                        priority_level: PriorityLevel(14),
                        pre_emption_capability: PreEmptionCapability::MayTriggerPreEmption,
                        pre_emption_vulnerability: PreEmptionVulnerability::NotPreEmptable,
                    },
                    gbr_qos_flow_information: None,
                    reflective_qos_attribute: None,
                    pdu_session_id: None,
                    ulpdu_session_aggregate_maximum_bit_rate: None,
                    qos_monitoring_request: None,
                },
                qos_flow_mapping_indication: None,
                tsc_traffic_characteristics: None,
            }]),
        }),
        ul_up_tnl_information_to_be_setup_list: UlUpTnlInformationToBeSetupList(nonempty![
            UlUpTnlInformationToBeSetupItem {
                ul_up_tnl_information: UpTransportLayerInformation::GtpTunnel(gtp_tunnel),
                bh_info: None,
            },
        ]),
        rlc_mode: RlcMode::RlcUmBidirectional,
        ul_configuration: None,
        duplication_activation: None,
        dc_based_duplication_configured: None,
        dc_based_duplication_activation: None,
        dlpdcpsn_length: None,
        ulpdcpsn_length: None,
        additional_pdcp_duplication_tnl_list: None,
        rlc_duplication_information: None,
    }
}

fn scell_to_be_setup_item(nr_cgi: NrCgi) -> SCellToBeSetupItem {
    SCellToBeSetupItem {
        s_cell_id: nr_cgi,
        s_cell_index: SCellIndex(1), // TODO
        s_cell_ul_configured: None,
        serving_cell_mo: None,
    }
}

pub fn ue_context_setup_request(
    ue: &UeContext,
    transport_layer_address: TransportLayerAddress,
    session: &PduSession,
) -> Result<UeContextSetupRequest> {
    // TODO: avoid hardcoding
    let gnb_du_ue_ambr_ul = Some(BitRate(1_000_000));

    let drbs_to_be_setup_list = Some(DrbsToBeSetupList(nonempty![drb_to_be_setup_item(
        session.snssai,
        GtpTunnel {
            transport_layer_address,
            gtp_teid: session.userplane_info.uplink_gtp_teid.clone()
        },
        session.id,
        session.userplane_info.qfi
    )]));

    Ok(UeContextSetupRequest {
        gnb_cu_ue_f1ap_id: GnbCuUeF1apId(ue.key),
        gnb_du_ue_f1ap_id: Some(ue.gnb_du_ue_f1ap_id),
        sp_cell_id: ue.nr_cgi.clone(),
        serv_cell_index: f1ap::ServCellIndex(0), // TODO
        sp_cell_ul_configured: Some(CellUlConfigured::None),
        cu_to_du_rrc_information: CuToDuRrcInformation {
            cg_config_info: None,
            ue_capability_rat_container_list: None,
            meas_config: None,
            handover_preparation_information: None,
            cell_group_config: None,
            measurement_timing_configuration: None,
            ue_assistance_information: None,
            cg_config: None,
            ue_assistance_information_eutra: None,
        },
        candidate_sp_cell_list: None,
        drx_cycle: None,
        resource_coordination_transfer_container: None,
        s_cell_to_be_setup_list: Some(SCellToBeSetupList(nonempty![scell_to_be_setup_item(
            ue.nr_cgi.clone(),
        )])),
        srbs_to_be_setup_list: Some(SrbsToBeSetupList(nonempty![SrbsToBeSetupItem {
            srb_id: SrbId(2),
            duplication_indication: None,
            additional_duplication_indication: None,
        }])),
        drbs_to_be_setup_list,
        inactivity_monitoring_request: None,
        rat_frequency_priority_information: None,
        rrc_container: None,
        masked_imeisv: None,
        serving_plmn: None,
        gnb_du_ue_ambr_ul,
        rrc_delivery_status_request: Some(RrcDeliveryStatusRequest::True),
        resource_coordination_transfer_information: None,
        serving_cell_mo: None,
        new_gnb_cu_ue_f1ap_id: None,
        ran_ue_id: None,
        trace_activation: None,
        additional_rrm_priority_index: None,
        bh_channels_to_be_setup_list: None,
        configured_bap_address: None,
        nr_v2x_services_authorized: None,
        ltev2x_services_authorized: None,
        nr_ue_sidelink_aggregate_maximum_bitrate: None,
        lte_ue_sidelink_aggregate_maximum_bitrate: None,
        pc5_link_ambr: None,
        sl_drbs_to_be_setup_list: None,
        conditional_inter_du_mobility_information: None,
        management_based_mdt_plmn_list: None,
        serving_nid: None,
        f1c_transfer_path: None,
    })
}

pub fn ue_context_release_command(ue: &UeContext, cause: Cause) -> UeContextReleaseCommand {
    UeContextReleaseCommand {
        gnb_cu_ue_f1ap_id: GnbCuUeF1apId(ue.key),
        gnb_du_ue_f1ap_id: ue.gnb_du_ue_f1ap_id,
        cause,
        rrc_container: None,
        srb_id: Some(SrbId(1)),
        old_gnb_du_ue_f1ap_id: None,
        execute_duplication: None,
        rrc_delivery_status_request: None,
        target_cells_to_cancel: None,
    }
}
