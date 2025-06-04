use asn1_per::{Msb0, bitvec, nonempty};
use ngap::*;
use xxap::*;

//use super::UeContext;

pub fn ng_setup_request() -> Box<NgapPdu> {
    Box::new(NgapPdu::InitiatingMessage(
        InitiatingMessage::NgSetupRequest(NgSetupRequest {
            global_ran_node_id: GlobalRanNodeId::GlobalGnbId(GlobalGnbId {
                plmn_identity: PlmnIdentity([0, 0, 1]),
                gnb_id: GnbId::GnbId(bitvec![u8,Msb0; 1; 22]),
            }),
            ran_node_name: None,
            supported_ta_list: SupportedTaList(nonempty![SupportedTaItem {
                tac: Tac([0, 0, 1]),
                broadcast_plmn_list: BroadcastPlmnList(nonempty![BroadcastPlmnItem {
                    plmn_identity: PlmnIdentity([0, 0, 1]),
                    tai_slice_support_list: SliceSupportList(nonempty![
                        SliceSupportItem {
                            snssai: Snssai(1, None).into(),
                        },
                        SliceSupportItem {
                            snssai: Snssai(1, Some([0, 0, 0])).into(),
                        },
                        SliceSupportItem {
                            snssai: Snssai(1, Some([0, 0, 1])).into(),
                        }
                    ]),
                    npn_support: None,
                    extended_tai_slice_support_list: None,
                }]),
                configured_tac_indication: None,
                rat_information: None,
            }]),
            default_paging_drx: PagingDrx::V128,
            ue_retention_information: None,
            nb_iot_default_paging_drx: None,
            extended_ran_node_name: None,
        }),
    ))
}

pub fn uplink_nas_transport(
    amf_ue_ngap_id: AmfUeNgapId,
    ran_ue_ngap_id: RanUeNgapId,
    nas_pdu: NasPdu,
    user_location_information: UserLocationInformation,
) -> Box<NgapPdu> {
    Box::new(NgapPdu::InitiatingMessage(
        InitiatingMessage::UplinkNasTransport(UplinkNasTransport {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            nas_pdu,
            user_location_information,
            w_agf_identity_information: None,
            tngf_identity_information: None,
            twif_identity_information: None,
        }),
    ))
}

pub fn initial_ue_message(
    ran_ue_ngap_id: RanUeNgapId,
    nas_pdu: NasPdu,
    user_location_information: UserLocationInformation,
) -> Box<NgapPdu> {
    Box::new(NgapPdu::InitiatingMessage(
        InitiatingMessage::InitialUeMessage(InitialUeMessage {
            ran_ue_ngap_id,
            nas_pdu,
            user_location_information,
            rrc_establishment_cause: RrcEstablishmentCause::MtAccess,
            five_g_s_tmsi: None,
            amf_set_id: None,
            ue_context_request: None,
            allowed_nssai: None,
            source_to_target_amf_information_reroute: None,
            selected_plmn_identity: None,
            iab_node_indication: None,
            c_emode_b_support_indicator: None,
            ltem_indication: None,
            edt_session: None,
            authenticated_indication: None,
            npn_access_information: None,
        }),
    ))
}

pub fn initial_context_setup_response(
    amf_ue_ngap_id: AmfUeNgapId,
    ran_ue_ngap_id: RanUeNgapId,
) -> Box<NgapPdu> {
    Box::new(NgapPdu::SuccessfulOutcome(
        SuccessfulOutcome::InitialContextSetupResponse(InitialContextSetupResponse {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            pdu_session_resource_setup_list_cxt_res: None,
            pdu_session_resource_failed_to_setup_list_cxt_res: None,
            criticality_diagnostics: None,
        }),
    ))
}
