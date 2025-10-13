use anyhow::Result;
use asn1_per::*;
use ngap::*;
use xxap::*;

pub fn ng_setup_request() -> Box<NgapPdu> {
    Box::new(NgapPdu::InitiatingMessage(
        InitiatingMessage::NgSetupRequest(NgSetupRequest {
            global_ran_node_id: GlobalRanNodeId::GlobalGnbId(GlobalGnbId {
                plmn_identity: PlmnIdentity([0x00, 0xf1, 0x10]),
                gnb_id: GnbId::GnbId(bitvec![u8,Msb0; 1; 22]),
            }),
            ran_node_name: None,
            supported_ta_list: SupportedTaList(nonempty![SupportedTaItem {
                tac: Tac([0, 0, 1]),
                broadcast_plmn_list: BroadcastPlmnList(nonempty![BroadcastPlmnItem {
                    plmn_identity: PlmnIdentity([0x00, 0xf1, 0x10]),
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

pub fn ng_reset() -> Box<NgapPdu> {
    Box::new(NgapPdu::InitiatingMessage(InitiatingMessage::NgReset(
        NgReset {
            cause: Cause::RadioNetwork(CauseRadioNetwork::UserInactivity),
            reset_type: ResetType::NgInterface(ResetAll::ResetAll),
        },
    )))
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
    guti: &Option<[u8; 10]>,
    user_location_information: UserLocationInformation,
) -> Box<NgapPdu> {
    let five_g_s_tmsi = guti.map(|guti| FiveGSTmsi {
        amf_set_id: AmfSetId(guti[4..6].view_bits::<Msb0>()[0..10].to_bitvec()),
        amf_pointer: AmfPointer(guti[5].view_bits::<Msb0>()[2..8].to_bitvec()),
        five_g_tmsi: FiveGTmsi(guti[6..10].try_into().unwrap()),
    });

    Box::new(NgapPdu::InitiatingMessage(
        InitiatingMessage::InitialUeMessage(InitialUeMessage {
            ran_ue_ngap_id,
            nas_pdu,
            user_location_information,
            rrc_establishment_cause: RrcEstablishmentCause::MtAccess,
            five_g_s_tmsi,
            amf_set_id: None,
            ue_context_request: Some(UeContextRequest::Requested),
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
    local_ip: &String,
    local_teid: Option<&[u8; 4]>,
) -> Box<NgapPdu> {
    let pdu_session_resource_setup_list_cxt_res = local_teid.map(|teid| {
        PduSessionResourceSetupListCxtRes(nonempty![PduSessionResourceSetupItemCxtRes {
            pdu_session_id: PduSessionId(1), // TODO - avoid hardcoding
            pdu_session_resource_setup_response_transfer:
                pdu_session_resource_setup_response_transfer(local_ip, teid).unwrap()
        }])
    });
    Box::new(NgapPdu::SuccessfulOutcome(
        SuccessfulOutcome::InitialContextSetupResponse(InitialContextSetupResponse {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            pdu_session_resource_setup_list_cxt_res,
            pdu_session_resource_failed_to_setup_list_cxt_res: None,
            criticality_diagnostics: None,
        }),
    ))
}

fn pdu_session_resource_setup_response_transfer(
    local_ip: &String,
    local_teid: &[u8; 4],
) -> Result<Vec<u8>> {
    let transport_layer_address = TransportLayerAddress::try_from(local_ip)?;

    Ok(PduSessionResourceSetupResponseTransfer {
        dl_qos_flow_per_tnl_information: QosFlowPerTnlInformation {
            up_transport_layer_information: UpTransportLayerInformation::GtpTunnel(GtpTunnel {
                transport_layer_address,
                gtp_teid: GtpTeid(*local_teid),
            }),
            associated_qos_flow_list: AssociatedQosFlowList(nonempty![AssociatedQosFlowItem {
                qos_flow_identifier: ngap::QosFlowIdentifier(1),
                qos_flow_mapping_indication: None,
                current_qos_para_set_index: None,
            }]),
        },
        additional_dl_qos_flow_per_tnl_information: None,
        security_result: None,
        qos_flow_failed_to_setup_list: None,
        redundant_dl_qos_flow_per_tnl_information: None,
        additional_redundant_dl_qos_flow_per_tnl_information: None,
        used_rsn_information: None,
        global_ran_node_id: None,
    }
    .as_bytes()?)
}

pub fn pdu_session_resource_setup_response(
    amf_ue_ngap_id: AmfUeNgapId,
    ran_ue_ngap_id: RanUeNgapId,
    local_ip: &String,
    local_teid: &[u8; 4],
) -> Result<Box<NgapPdu>> {
    let pdu_session_resource_setup_response_transfer =
        pdu_session_resource_setup_response_transfer(local_ip, local_teid)?;

    Ok(Box::new(NgapPdu::SuccessfulOutcome(
        SuccessfulOutcome::PduSessionResourceSetupResponse(PduSessionResourceSetupResponse {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            pdu_session_resource_setup_list_su_res: Some(PduSessionResourceSetupListSuRes(
                nonempty![PduSessionResourceSetupItemSuRes {
                    pdu_session_id: PduSessionId(1),
                    pdu_session_resource_setup_response_transfer
                }],
            )),
            pdu_session_resource_failed_to_setup_list_su_res: None,
            criticality_diagnostics: None,
        }),
    )))
}

pub fn pdu_session_resource_release_response(
    amf_ue_ngap_id: AmfUeNgapId,
    ran_ue_ngap_id: RanUeNgapId,
    pdu_session_id: PduSessionId,
) -> Result<Box<NgapPdu>> {
    let pdu_session_resource_release_response_transfer =
        PduSessionResourceReleaseResponseTransfer {
            secondary_rat_usage_information: None,
        }
        .as_bytes()?;

    Ok(Box::new(NgapPdu::SuccessfulOutcome(
        SuccessfulOutcome::PduSessionResourceReleaseResponse(PduSessionResourceReleaseResponse {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            pdu_session_resource_released_list_rel_res: PduSessionResourceReleasedListRelRes(
                nonempty![PduSessionResourceReleasedItemRelRes {
                    pdu_session_id,
                    pdu_session_resource_release_response_transfer
                }],
            ),
            user_location_information: None,
            criticality_diagnostics: None,
        }),
    )))
}

pub fn ue_radio_capability_info_indication(
    amf_ue_ngap_id: AmfUeNgapId,
    ran_ue_ngap_id: RanUeNgapId,
) -> Box<NgapPdu> {
    let rrc_bytes = hex_literal::hex!(
        "0418b888314e9a05380574f5a0316000302402c1262c003387a0609b20c39f30c7942c0e0980406238\
         18507c1bd608c21a081078804496c982a091c790e7c639f30c7942c0e070f027f4000001fd000000a8\
         3626eb04610d04083a4022cb64c150d0e7c471e819f604f8c73e618f28581c0e1e138002f800e000be\
         0004103650000500000141f04f582308682041e201125b260a82471e439f18e7cc31e50b0381c3c09f\
         c0000007f0000000a0f80fac1184341020f100892d930541238f21cf8c73e618f28581c0e1e04fe000\
         0003f8000000507c06d608c21a081078804496c982a091c790e7c639f30c7942c0e070f027f0000001\
         fc000000283e026b04610d04083c40224b64c15048e3c873e31cf9863ca16070387813f8000000fe00\
         0000141f00b582308682041e201125b260a82471e439f18e7cc31e50b0381c3c09fc0000007f000000\
         0a0f801ac1184341020f100892d930541238f21cf8c73e618f28581c0e1e04fec000003fb000000506\
         c4cd608c21a081074804596c982a1a1cf88e3d033ec09f18e7cc31e50b0381c3c270005b001c0016c0\
         0a83e20eb04610d04083c40224b64c15048e3c873e31cf9863ca16070387813fa000000fe800000040\
         80c1741b0a303582308682041d201165b260a86873e238f40cfb027c639f30c7942c0e070f09c0017c\
         0070005f0002081b280002800000a0d84fac1184341020e9008b2d930543439f11c7a067d813e31cf9\
         863ca1607038784e000be0038002f800506c25d608c21a081074804596c982a1a1cf88e3d033ec09f1\
         8e7cc31e50b0381c3c2700058001c00160000108389a00000000404d0541a01810b639f0c0a0233d03\
         801f08060180c0150180018090010180f8140080000000400000802000008010000060080000400400\
         0028020000180100000e00800008004000048020000280a60a5e54d6065606d654d652564cd60cd650\
         d60ad650501c1000009652404000065949010000296524040000e59490100004965240400016594901\
         0000696524040001e5949007d2a8aa0b1540e2a95455298aa4d1541a2a944503074029804060300804\
         02030080c0200000010040040b0280"
    );

    Box::new(NgapPdu::InitiatingMessage(
        InitiatingMessage::UeRadioCapabilityInfoIndication(UeRadioCapabilityInfoIndication {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            ue_radio_capability: UeRadioCapability(rrc_bytes.to_vec()),
            ue_radio_capability_for_paging: None,
            ue_radio_capability_eutra_format: None,
        }),
    ))
}

pub fn ue_context_release_request(
    amf_ue_ngap_id: AmfUeNgapId,
    ran_ue_ngap_id: RanUeNgapId,
) -> Box<NgapPdu> {
    Box::new(NgapPdu::InitiatingMessage(
        InitiatingMessage::UeContextReleaseRequest(UeContextReleaseRequest {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            pdu_session_resource_list_cxt_rel_req: None,
            cause: Cause::RadioNetwork(CauseRadioNetwork::RadioConnectionWithUeLost),
        }),
    ))
}

pub fn ue_context_release_complete(
    amf_ue_ngap_id: AmfUeNgapId,
    ran_ue_ngap_id: RanUeNgapId,
) -> Box<NgapPdu> {
    Box::new(NgapPdu::SuccessfulOutcome(
        SuccessfulOutcome::UeContextReleaseComplete(UeContextReleaseComplete {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            user_location_information: None,
            info_on_recommended_cells_and_ran_nodes_for_paging: None,
            pdu_session_resource_list_cxt_rel_cpl: None,
            criticality_diagnostics: None,
            paging_assis_datafor_c_ecapab_ue: None,
        }),
    ))
}
