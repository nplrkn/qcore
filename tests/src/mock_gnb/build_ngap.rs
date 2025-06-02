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
