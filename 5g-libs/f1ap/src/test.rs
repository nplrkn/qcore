use crate::{
    BapAddress, F1SetupResponse, F1apPdu, NrModeInfo, RrcVersion, ServedCellInformation,
    ServedPlmnsList,
};
use asn1_per::*;

#[test]
fn test_oran_du_f1_setup() -> Result<(), PerCodecError> {
    let reference = "00010080bf000004004e00020001002a00020001002c00809d0000002b008096480013f184000000001000010000010813f18400000083400c0001402002030440a0060708010005f37000000000400687e0000000004708e00100000300000c55700030988d200040000040000000069000010140908000180000013670cb15d801b82010007888401041a3010a0a1371105820000013d5ce1962d4100a49014cf98f3f0004e3110a2a1184a8101d8082c07c010bc000ab000a80000000c700030f0500";
    let bytes = hex::decode(reference).unwrap();
    let _item = F1apPdu::from_bytes(&bytes)?;
    Ok(())
}

#[test]
fn test_nr_mode_info() -> Result<(), PerCodecError> {
    let reference = "410009c40800004d002700";
    let bytes = hex::decode(reference).unwrap();
    let _item = NrModeInfo::from_bytes(&bytes)?;
    Ok(())
}

#[test]
fn test_served_cell_information() -> Result<(), PerCodecError> {
    let reference =
        "480002f899000bc614e000000000010802f89900000083400400000020410009c40800004d0027000130";
    let bytes = hex::decode(reference).unwrap();
    let mut data = PerCodecData::from_slice_aper(&bytes);
    data.advance_maybe_err(3, false)?;
    let _item = ServedCellInformation::decode(&mut data)?;
    Ok(())
}

#[test]
fn test_served_plmns_list() -> Result<(), PerCodecError> {
    let reference = "0802f89900000083400400000020";
    let bytes = hex::decode(reference).unwrap();
    let _item = ServedPlmnsList::from_bytes(&bytes)?;
    Ok(())
}

#[test]
fn test_f1_response_encode_decode() -> Result<(), PerCodecError> {
    let f1_setup_reponse = F1SetupResponse {
        transaction_id: crate::TransactionId(0),
        gnb_cu_name: None,
        cells_to_be_activated_list: None,
        gnb_cu_rrc_version: RrcVersion {
            latest_rrc_version: bitvec![u8, Msb0;0, 0, 0],
            latest_rrc_version_enhanced: None,
        },
        transport_layer_address_info: None,
        ul_bh_non_up_traffic_mapping: None,
        bap_address: Some(BapAddress(bitvec![u8, Msb0;0, 0,0,0,0,0,0,0,0,0])),
        extended_gnb_du_name: None,
    };

    let bytes = f1_setup_reponse.into_bytes()?;
    let _f1_setup_response = F1SetupResponse::from_bytes(&bytes)?;
    Ok(())
}
