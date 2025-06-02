use super::ies::*;
use super::pdu::*;
use super::top_pdu::*;
use asn1_per::*;
use xxap::{PlmnIdentity, Snssai};

fn make_ng_setup() -> NgSetupRequest {
    let plmn_identity = PlmnIdentity([0x02, 0xf8, 0x39]);
    NgSetupRequest {
        global_ran_node_id: GlobalRanNodeId::GlobalGnbId(GlobalGnbId {
            plmn_identity: plmn_identity.clone(),
            gnb_id: GnbId::GnbId(vec![0x00, 0x01, 0x02].view_bits::<Msb0>().into()),
        }),
        ran_node_name: Some(RanNodeName("free5gc".to_string())),
        supported_ta_list: SupportedTaList(nonempty![SupportedTaItem {
            tac: Tac([0, 0, 1]),
            broadcast_plmn_list: BroadcastPlmnList(nonempty![BroadcastPlmnItem {
                plmn_identity: plmn_identity,
                tai_slice_support_list: SliceSupportList(nonempty![SliceSupportItem {
                    snssai: Snssai(1, Some([1, 2, 3])).into(),
                }]),
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
    }
}

#[test]
fn test_ngap_pdu_coding() -> Result<(), PerCodecError> {
    let ng_setup = make_ng_setup();
    let ngap_pdu = NgapPdu::InitiatingMessage(InitiatingMessage::NgSetupRequest(ng_setup));
    let bytes = ngap_pdu.as_bytes()?;
    let output_hex = hex::encode(bytes);
    let reference = "00150035000004001b00080002f83910000102005240090300667265653567630066001000000000010002f839000010080102030015400140";
    assert_eq!(reference, output_hex);
    let bytes = hex::decode(reference).unwrap();
    let bytes = NgapPdu::from_bytes(&bytes)?.as_bytes()?;
    let output_hex = hex::encode(bytes);
    assert_eq!(reference, output_hex);

    Ok(())
}

#[test]
fn test_ng_setup() -> Result<(), PerCodecError> {
    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage::NgSetupRequest(NgSetupRequest {
        global_ran_node_id: GlobalRanNodeId::GlobalGnbId(GlobalGnbId {
            plmn_identity: PlmnIdentity([2, 3, 2]),
            gnb_id: GnbId::GnbId(bitvec![u8,Msb0; 1; 22]),
        }),
        ran_node_name: None,
        supported_ta_list: SupportedTaList(nonempty![SupportedTaItem {
            tac: Tac([0, 1, 2]),
            broadcast_plmn_list: BroadcastPlmnList(nonempty![BroadcastPlmnItem {
                plmn_identity: PlmnIdentity([2, 3, 2]),
                tai_slice_support_list: SliceSupportList(nonempty![SliceSupportItem {
                    snssai: Snssai(1, None).into(),
                }]),
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
    }));
    let bytes = pdu.as_bytes()?;
    //let output_hex = hex::encode(bytes.clone());
    //println!("Output of encode is {}", output_hex);

    let _pdu = NgapPdu::from_bytes(&bytes)?;
    Ok(())
}

#[test]
fn test_ran_ue_ngap_id() -> Result<(), PerCodecError> {
    let ran_ue_ngap_id = RanUeNgapId(0x10203040);
    let bytes = ran_ue_ngap_id.as_bytes()?;
    let output_hex = hex::encode(bytes.clone());
    //println!("Output of RAN UE NGAP ID encode is {}", output_hex);
    assert_eq!(output_hex, "c010203040");
    let ran_ue_ngap_id_2 = RanUeNgapId::from_bytes(&bytes)?;
    assert_eq!(0x10203040, ran_ue_ngap_id_2.0);

    Ok(())
}
