//! build_f1ap - construction of F1AP messages
use anyhow::Result;
use asn1_per::*;
use ngap::*;
use xxap::{PlmnIdentity, Snssai};

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
