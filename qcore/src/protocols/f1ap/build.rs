//! build_f1ap - construction of F1AP messages
use crate::{PdcpSequenceNumberLength, PduSession, data::UeContextRan};
use anyhow::{Result, anyhow};
use asn1_per::*;
use f1ap::*;
use rrc::{
    CellReselectionInfoCommon, CellReselectionPriority, CellReselectionServingFreqInfo,
    IntraFreqCellReselectionInfo, QHyst, QRxLevMin,
};
use xxap::{GtpTunnel, NrCgi, PduSessionId, TransportLayerAddress};

pub fn f1_setup_response(
    transaction_id: TransactionId,
    gnb_cu_name: Option<String>,
    served_cells: &[GnbDuServedCellsItem],
) -> Result<F1SetupResponse> {
    // Ask for all served cells to be activated.
    let sib2 = build_sib2().as_bytes()?;
    let cells_to_be_activated_list = NonEmpty::collect(
        served_cells
            .iter()
            .map(|item| served_cell_to_activated(item, sib2.clone())),
    )
    .map(CellsToBeActivatedList);

    Ok(F1SetupResponse {
        transaction_id,
        gnb_cu_rrc_version: RrcVersion {
            latest_rrc_version: bitvec![u8, Msb0;0, 0, 0],
            latest_rrc_version_enhanced: None,
        },
        gnb_cu_name: gnb_cu_name.map(GnbCuName),
        cells_to_be_activated_list,
        transport_layer_address_info: None,
        ul_bh_non_up_traffic_mapping: None,
        bap_address: None,
        extended_gnb_cu_name: None,
        ncgi_to_be_updated_list: None,
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
        cells_for_son_list: None,
    }
}

pub fn dl_rrc_message_transfer(
    ue_id: u32,
    gnb_du_ue_f1ap_id: GnbDuUeF1apId,
    rrc_container: RrcContainer,
    srb_id: SrbId,
) -> Box<DlRrcMessageTransfer> {
    Box::new(DlRrcMessageTransfer {
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
        srb_mapping_info: None,
    })
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
        mbs_broadcast_neighbour_cell_list: None,
        ss_bs_within_the_cell_tobe_activated_list: None,
    }
}

pub fn drb_to_be_setup_item(
    transport_layer_address: TransportLayerAddress,
    session: &PduSession,
) -> DrbsToBeSetupItem {
    let gtp_tunnel = GtpTunnel {
        transport_layer_address,
        gtp_teid: session.userplane_info.uplink_gtp_teid,
    };

    let five_qi = session.userplane_info.five_qi;
    let qfi = session.userplane_info.qfi;
    let (dlpdcpsn_length, ulpdcpsn_length) = match session.userplane_info.pdcp_sn_length {
        PdcpSequenceNumberLength::TwelveBits => (
            Some(PdcpsnLength::TwelveBits),
            Some(PdcpsnLength::TwelveBits),
        ),
        PdcpSequenceNumberLength::EighteenBits => (
            Some(PdcpsnLength::EighteenBits),
            Some(PdcpsnLength::EighteenBits),
        ),
    };

    // Temp code
    let rlc_mode = if five_qi == 9 {
        RlcMode::RlcAm
    } else {
        RlcMode::RlcUmBidirectional
    };

    DrbsToBeSetupItem {
        drb_id: DrbId(1),
        qos_information: QosInformation::DrbInformation(DrbInformation {
            drb_qos: QosFlowLevelQosParameters {
                qos_characteristics: QosCharacteristics::NonDynamic5qi(NonDynamic5qiDescriptor {
                    five_qi,
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
                pdu_session_id: Some(PduSessionId(session.id)),
                ulpdu_session_aggregate_maximum_bit_rate: None,
                qos_monitoring_request: None,
                pdcp_terminating_node_dl_tnl_addr_info: None,
                pdu_set_qos_parameters: None,
            },
            snssai: session.snssai.into(),
            notification_control: None,
            flows_mapped_to_drb_list: FlowsMappedToDrbList(nonempty![FlowsMappedToDrbItem {
                qos_flow_identifier: QosFlowIdentifier(qfi),
                qos_flow_level_qos_parameters: QosFlowLevelQosParameters {
                    qos_characteristics: QosCharacteristics::NonDynamic5qi(
                        NonDynamic5qiDescriptor {
                            five_qi,
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
                    pdcp_terminating_node_dl_tnl_addr_info: None,
                    pdu_set_qos_parameters: None
                },
                qos_flow_mapping_indication: None,
                tsc_traffic_characteristics: None,
            }]),
            ecn_markingor_congestion_information_reporting_request: None,
            p_sib_ased_s_du_discard_ul: None,
        }),
        ul_up_tnl_information_to_be_setup_list: UlUpTnlInformationToBeSetupList(nonempty![
            UlUpTnlInformationToBeSetupItem {
                ul_up_tnl_information: UpTransportLayerInformation::GtpTunnel(gtp_tunnel),
                bh_info: None,
                drb_mapping_info: None
            },
        ]),
        rlc_mode,
        ul_configuration: None,
        duplication_activation: None,
        dc_based_duplication_configured: None,
        dc_based_duplication_activation: None,
        dlpdcpsn_length,
        ulpdcpsn_length,
        additional_pdcp_duplication_tnl_list: None,
        rlc_duplication_information: None,
        sdtrlc_bearer_configuration: None,
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
    ue: &UeContextRan,
    transport_layer_address: TransportLayerAddress,
    session: &PduSession,
) -> Result<Box<UeContextSetupRequest>> {
    // TODO: avoid hardcoding
    let gnb_du_ue_ambr_ul = Some(BitRate(768_000_000));

    let drbs_to_be_setup_list = Some(DrbsToBeSetupList(nonempty![drb_to_be_setup_item(
        transport_layer_address,
        session,
    )]));

    Ok(Box::new(UeContextSetupRequest {
        gnb_cu_ue_f1ap_id: GnbCuUeF1apId(ue.local_ran_ue_id),
        gnb_du_ue_f1ap_id: Some(ue.gnb_du_ue_f1ap_id()),
        sp_cell_id: ue
            .nr_cgi
            .as_ref()
            .ok_or_else(|| anyhow!("NR CGI must be present"))?
            .clone(),
        serv_cell_index: f1ap::ServCellIndex(0), // TODO
        sp_cell_ul_configured: Some(CellUlConfigured::None),
        cu_to_du_rrc_information: CuToDuRrcInformation {
            cg_config_info: None,
            ue_capability_rat_container_list: ue
                .rat_capabilities
                .as_ref()
                .map(|x| UeCapabilityRatContainerList(x.clone())),
            meas_config: None,
            handover_preparation_information: None,
            cell_group_config: None,
            measurement_timing_configuration: None,
            ue_assistance_information: None,
            cg_config: None,
            ue_assistance_information_eutra: None,
            location_measurement_information: None,
            musim_gap_config: None,
            sdt_mac_phy_cg_config: None,
            mbs_interest_indication: None,
            need_for_gaps_info_nr: None,
            need_for_gap_ncsg_info_nr: None,
            need_for_gap_ncsg_info_eutra: None,
            config_restrict_info_daps: None,
            preconfigured_measurement_gap_request: None,
            need_for_interruption_info_nr: None,
            musim_capability_restriction_indication: None,
            musim_candidate_band_list: None,
        },
        candidate_sp_cell_list: None,
        drx_cycle: None,
        resource_coordination_transfer_container: None,
        s_cell_to_be_setup_list: Some(SCellToBeSetupList(nonempty![scell_to_be_setup_item(
            ue.nr_cgi
                .as_ref()
                .ok_or_else(|| anyhow!("NR CGI must be present"))?
                .clone(),
        )])),
        srbs_to_be_setup_list: Some(SrbsToBeSetupList(nonempty![SrbsToBeSetupItem {
            srb_id: SrbId(2),
            duplication_indication: None,
            additional_duplication_indication: None,
            sdtrlc_bearer_configuration: None,
            srb_mapping_info: None
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
        f1c_transfer_path_nr_dc: None,
        mdt_polluted_measurement_indicator: None,
        scg_activation_request: None,
        cg_sdt_session_info_old: None,
        five_g_pro_se_authorized: None,
        five_g_pro_se_ue_pc5_aggregate_maximum_bitrate: None,
        five_g_pro_se_pc5_link_ambr: None,
        uu_rlc_channel_to_be_setup_list: None,
        pc5rlc_channel_to_be_setup_list: None,
        path_switch_configuration: None,
        gnb_du_ue_slice_maximum_bit_rate_list: None,
        multicast_mbs_session_setup_list: None,
        ue_multicast_mr_bs_to_be_setup_list: None,
        serving_cell_mo_list: None,
        network_controlled_repeater_authorized: None,
        sdt_volume_threshold: None,
        ltm_information_setup: None,
        ltm_configuration_id_mapping_list: None,
        early_sync_information_request: None,
        path_addition_information: None,
        nr_a2x_services_authorized: None,
        ltea2x_services_authorized: None,
        nr_ue_sidelink_aggregate_maximum_bitrate_for_a2x: None,
        lte_ue_sidelink_aggregate_maximum_bitrate_for_a2x: None,
        dllbt_failure_information_request: None,
        sl_positioning_ranging_service_info: None,
        non_integer_drx_cycle: None,
    }))
}

pub fn ue_context_modification_request(
    ue: &UeContextRan,
    _released_session: &PduSession,
) -> Box<UeContextModificationRequest> {
    let drbs_to_be_released_list = Some(DrbsToBeReleasedList(nonempty![DrbsToBeReleasedItem {
        drb_id: DrbId(1)
    }]));
    Box::new(UeContextModificationRequest {
        gnb_cu_ue_f1ap_id: GnbCuUeF1apId(ue.local_ran_ue_id),
        gnb_du_ue_f1ap_id: ue.gnb_du_ue_f1ap_id(),
        sp_cell_id: None,
        serv_cell_index: None,
        sp_cell_ul_configured: None,
        drx_cycle: None,
        cu_to_du_rrc_information: None,
        transmission_action_indicator: None,
        resource_coordination_transfer_container: None,
        rrc_reconfiguration_complete_indicator: None,
        rrc_container: None,
        s_cell_to_be_setup_mod_list: None,
        s_cell_to_be_removed_list: None,
        srbs_to_be_setup_mod_list: None,
        drbs_to_be_setup_mod_list: None,
        drbs_to_be_modified_list: None,
        srbs_to_be_released_list: None,
        drbs_to_be_released_list,
        inactivity_monitoring_request: None,
        rat_frequency_priority_information: None,
        drx_configuration_indicator: None,
        rlc_failure_indication: None,
        uplink_tx_direct_current_list_information: None,
        gnb_du_configuration_query: None,
        gnb_du_ue_ambr_ul: None,
        execute_duplication: None,
        rrc_delivery_status_request: None,
        resource_coordination_transfer_information: None,
        serving_cell_mo: None,
        needfor_gap: None,
        full_configuration: None,
        additional_rrm_priority_index: None,
        lower_layer_presence_status_change: None,
        bh_channels_to_be_setup_mod_list: None,
        bh_channels_to_be_modified_list: None,
        bh_channels_to_be_released_list: None,
        nr_v2x_services_authorized: None,
        ltev2x_services_authorized: None,
        nr_ue_sidelink_aggregate_maximum_bitrate: None,
        lte_ue_sidelink_aggregate_maximum_bitrate: None,
        pc5_link_ambr: None,
        sl_drbs_to_be_setup_mod_list: None,
        sl_drbs_to_be_modified_list: None,
        sl_drbs_to_be_released_list: None,
        conditional_intra_du_mobility_information: None,
        f1c_transfer_path: None,
        scg_indicator: None,
        uplink_tx_direct_current_two_carrier_list_info: None,
        iab_conditional_rrc_message_delivery_indication: None,
        f1c_transfer_path_nr_dc: None,
        mdt_polluted_measurement_indicator: None,
        scg_activation_request: None,
        cg_sdt_query_indication: None,
        five_g_pro_se_authorized: None,
        five_g_pro_se_ue_pc5_aggregate_maximum_bitrate: None,
        five_g_pro_se_pc5_link_ambr: None,
        updated_remote_ue_local_id: None,
        uu_rlc_channel_to_be_setup_list: None,
        uu_rlc_channel_to_be_modified_list: None,
        uu_rlc_channel_to_be_released_list: None,
        pc5rlc_channel_to_be_setup_list: None,
        pc5rlc_channel_to_be_modified_list: None,
        pc5rlc_channel_to_be_released_list: None,
        path_switch_configuration: None,
        gnb_du_ue_slice_maximum_bit_rate_list: None,
        multicast_mbs_session_setup_list: None,
        multicast_mbs_session_remove_list: None,
        ue_multicast_mr_bs_to_be_setup_at_modify_list: None,
        ue_multicast_mr_bs_to_be_released_list: None,
        sldrx_cycle_list: None,
        management_based_mdt_plmn_modification_list: None,
        sdt_bearer_configuration_query_indication: None,
        daps_ho_status: None,
        serving_cell_mo_list: None,
        ul_tx_direct_current_more_carrier_information: None,
        cpacmcg_information: None,
        network_controlled_repeater_authorized: None,
        sdt_volume_threshold: None,
        ltm_information_modify: None,
        ltmcfra_resource_config_list: None,
        ltm_configuration_id_mapping_list: None,
        early_sync_information_request: None,
        early_sync_candidate_cell_information_list: None,
        early_sync_serving_cell_information: None,
        ltm_cells_to_be_released_list: None,
        path_addition_information: None,
        nr_a2x_services_authorized: None,
        ltea2x_services_authorized: None,
        nr_ue_sidelink_aggregate_maximum_bitrate_for_a2x: None,
        lte_ue_sidelink_aggregate_maximum_bitrate_for_a2x: None,
        dllbt_failure_information_request: None,
        sl_positioning_ranging_service_info: None,
        non_integer_drx_cycle: None,
        ltm_reset_information: None,
    })
}

pub fn ue_context_release_command(ue: &UeContextRan, cause: Cause) -> Box<UeContextReleaseCommand> {
    Box::new(UeContextReleaseCommand {
        gnb_cu_ue_f1ap_id: GnbCuUeF1apId(ue.local_ran_ue_id),
        gnb_du_ue_f1ap_id: ue.gnb_du_ue_f1ap_id(),
        cause,
        rrc_container: None,
        srb_id: None, // This is supplied if there is an Rrc Container to send (TS38.473, 8.3.3.2)
        old_gnb_du_ue_f1ap_id: None,
        execute_duplication: None,
        rrc_delivery_status_request: None,
        target_cells_to_cancel: None,
        pos_context_rev_indication: None,
        cg_sdt_kept_indicator: None,
        ltm_cells_to_be_released_list: None,
        dllbt_failure_information_request: None,
    })
}
