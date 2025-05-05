use anyhow::{Result, bail};
use asn1_per::{Msb0, SerDes, bitvec, nonempty};
use f1ap::*;
use rrc::CellGroupId;
use xxap::{GtpTunnel, TransportLayerAddress};

use super::UeContext;

pub fn f1_setup_request() -> F1apPdu {
    F1apPdu::InitiatingMessage(InitiatingMessage::F1SetupRequest(F1SetupRequest {
        transaction_id: TransactionId(0),
        gnb_du_id: GnbDuId(123),
        gnb_du_rrc_version: RrcVersion {
            latest_rrc_version: bitvec![u8, Msb0;0, 0, 0],
            latest_rrc_version_enhanced: None,
        },
        gnb_du_name: None,
        gnb_du_served_cells_list: None,
        transport_layer_address_info: None,
        bap_address: None,
        extended_gnb_cu_name: None,
    }))
}

pub fn initial_ul_rrc_message_transfer(gnb_du_ue_f1ap_id: u32, rrc_bytes: Vec<u8>) -> F1apPdu {
    F1apPdu::InitiatingMessage(InitiatingMessage::InitialUlRrcMessageTransfer(
        InitialUlRrcMessageTransfer {
            gnb_du_ue_f1ap_id: GnbDuUeF1apId(gnb_du_ue_f1ap_id),
            nr_cgi: NrCgi {
                plmn_identity: PlmnIdentity([0, 1, 2]),
                nr_cell_identity: NrCellIdentity(bitvec![u8,Msb0;0;36]),
            },
            c_rnti: CRnti(14),
            rrc_container: RrcContainer(rrc_bytes),
            du_to_cu_rrc_container: Some(make_du_to_cu_rrc_container()),
            sul_access_indication: None,
            transaction_id: Some(TransactionId(1)), // Should be mandatory - ODU ORAN interop hack
            ran_ue_id: None,
            rrc_container_rrc_setup_complete: None,
        },
    ))
}

pub fn ul_rrc_message_transfer(
    gnb_cu_ue_f1ap_id: GnbCuUeF1apId,
    gnb_du_ue_f1ap_id: u32,
    pdcp_pdu_bytes: Vec<u8>,
) -> F1apPdu {
    F1apPdu::InitiatingMessage(InitiatingMessage::UlRrcMessageTransfer(
        UlRrcMessageTransfer {
            gnb_cu_ue_f1ap_id,
            gnb_du_ue_f1ap_id: GnbDuUeF1apId(gnb_du_ue_f1ap_id),
            srb_id: SrbId(1),
            rrc_container: RrcContainer(pdcp_pdu_bytes),
            selected_plmn_id: None,
            new_gnb_du_ue_f1ap_id: None,
        },
    ))
}

pub fn ue_context_setup_response(ue: &UeContext, local_ip: &String) -> Result<F1apPdu> {
    let Some(gnb_cu_ue_f1ap_id) = ue.gnb_cu_ue_f1ap_id else {
        bail!("CU F1AP ID should be set on UE");
    };
    let Some(drb) = &ue.drb else {
        bail!("Drb should be set on UE");
    };
    let cell_group_config = f1ap::CellGroupConfig(make_rrc_cell_group_config().into_bytes()?);
    let transport_layer_address = TransportLayerAddress::try_from(local_ip)?;

    // TODO: confirm setup of SRB2

    Ok(F1apPdu::SuccessfulOutcome(
        SuccessfulOutcome::UeContextSetupResponse(UeContextSetupResponse {
            gnb_cu_ue_f1ap_id,
            gnb_du_ue_f1ap_id: GnbDuUeF1apId(ue.ue_id),
            du_to_cu_rrc_information: DuToCuRrcInformation {
                cell_group_config,
                meas_gap_config: None,
                requested_p_max_fr1: None,
                drx_long_cycle_start_offset: None,
                selected_band_combination_index: None,
                selected_feature_set_entry_index: None,
                ph_info_scg: None,
                requested_band_combination_index: None,
                requested_feature_set_entry_index: None,
                drx_config: None,
                pdcch_blind_detection_scg: None,
                requested_pdcch_blind_detection_scg: None,
                ph_info_mcg: None,
                meas_gap_sharing_config: None,
                sl_phy_mac_rlc_config: None,
                sl_config_dedicated_eutra_info: None,
                requested_p_max_fr2: None,
            },
            c_rnti: None,
            resource_coordination_transfer_container: None,
            full_configuration: None,
            drbs_setup_list: Some(DrbsSetupList(nonempty![DrbsSetupItem {
                drb_id: drb.drb_id,
                lcid: None,
                dl_up_tnl_information_to_be_setup_list: DlUpTnlInformationToBeSetupList(nonempty![
                    DlUpTnlInformationToBeSetupItem {
                        dl_up_tnl_information: UpTransportLayerInformation::GtpTunnel(GtpTunnel {
                            transport_layer_address,
                            gtp_teid: drb.local_teid.clone(),
                        },),
                    },
                ]),
                additional_pdcp_duplication_tnl_list: None,
                current_qos_para_set_index: None,
            }])),
            srbs_failed_to_be_setup_list: None,
            drbs_failed_to_be_setup_list: None,
            s_cell_failedto_setup_list: None,
            inactivity_monitoring_response: None,
            criticality_diagnostics: None,
            srbs_setup_list: None,
            bh_channels_setup_list: None,
            bh_channels_failed_to_be_setup_list: None,
            sl_drbs_setup_list: None,
            sl_drbs_failed_to_be_setup_list: None,
            requested_target_cell_global_id: None,
        }),
    ))
}

pub fn build_gnb_cu_configuration_update_acknowledge(
    transaction_id: TransactionId,
    transport_layer_address: TransportLayerAddress,
) -> F1apPdu {
    F1apPdu::SuccessfulOutcome(SuccessfulOutcome::GnbCuConfigurationUpdateAcknowledge(
        GnbCuConfigurationUpdateAcknowledge {
            transaction_id,
            cells_failed_to_be_activated_list: None,
            criticality_diagnostics: None,
            gnb_cu_tnl_association_setup_list: Some(GnbCuTnlAssociationSetupList(nonempty![
                GnbCuTnlAssociationSetupItem {
                    tnl_association_transport_layer_address:
                        CpTransportLayerAddress::EndpointIpAddress(transport_layer_address),
                },
            ])),
            gnb_cu_tnl_association_failed_to_setup_list: None,
            dedicated_si_delivery_needed_ue_list: None,
            transport_layer_address_info: None,
        },
    ))
}

pub fn gnb_du_configuration_update() -> F1apPdu {
    F1apPdu::InitiatingMessage(InitiatingMessage::GnbDuConfigurationUpdate(
        GnbDuConfigurationUpdate {
            transaction_id: TransactionId(1),
            served_cells_to_add_list: None,
            served_cells_to_modify_list: None,
            served_cells_to_delete_list: None,
            cells_status_list: None,
            dedicated_si_delivery_needed_ue_list: None,
            gnb_du_id: None,
            gnb_du_tnl_association_to_remove_list: None,
            transport_layer_address_info: None,
        },
    ))
}

pub fn ue_context_release_request(ue: &UeContext) -> F1apPdu {
    let Some(gnb_cu_ue_f1ap_id) = ue.gnb_cu_ue_f1ap_id else {
        panic!("CU F1AP ID should be set on UE");
    };
    F1apPdu::InitiatingMessage(InitiatingMessage::UeContextReleaseRequest(
        UeContextReleaseRequest {
            gnb_cu_ue_f1ap_id,
            gnb_du_ue_f1ap_id: GnbDuUeF1apId(ue.ue_id),
            cause: Cause::RadioNetwork(CauseRadioNetwork::RlFailureRlc),
            target_cells_to_cancel: None,
        },
    ))
}

fn make_rrc_cell_group_config() -> rrc::CellGroupConfig {
    rrc::CellGroupConfig {
        cell_group_id: CellGroupId(1),
        rlc_bearer_to_add_mod_list: None,
        rlc_bearer_to_release_list: None,
        mac_cell_group_config: None,
        physical_cell_group_config: None,
        sp_cell_config: None,
        s_cell_to_add_mod_list: None,
        s_cell_to_release_list: None,
    }
}

fn make_du_to_cu_rrc_container() -> DuToCuRrcContainer {
    // We also need a CellGroupConfig to give to the CU.
    let cell_group_config_ie = make_rrc_cell_group_config().into_bytes().unwrap();
    DuToCuRrcContainer(cell_group_config_ie)
}
