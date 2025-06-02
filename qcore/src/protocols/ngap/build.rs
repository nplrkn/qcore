//! build_f1ap - construction of F1AP messages
use anyhow::Result;
use asn1_per::*;
use ngap::*;
use xxap::{Snssai, PlmnIdentity};

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
