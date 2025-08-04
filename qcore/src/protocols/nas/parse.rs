use anyhow::{Result, bail, ensure};
use oxirush_nas::{
    NasDnn, NasFGsMobileIdentity, NasPduSessionStatus, NasUeSecurityCapability,
    NasUplinkDataStatus, messages::NasIdentityResponse,
};
use std::fmt::Write;
use xxap::PlmnIdentity;

use crate::{
    data::UeSecurityCapabilities,
    protocols::nas::{AmfSetAndPointer, Guti, STmsi},
};

use super::{AmfIds, Imsi, MobileIdentity, Tmsi}; // Import the Write trait for String

pub fn fgs_mobile_identity(fgs_mobile_identity: &NasFGsMobileIdentity) -> Result<MobileIdentity> {
    // Get the SUPI.  TODO: SUCI support.
    let NasFGsMobileIdentity {
        value: mobile_identity_ie,
        ..
    } = fgs_mobile_identity;

    match mobile_identity_ie[0] & 0b111 {
        // SUPI
        0b001 => {
            if mobile_identity_ie.len() < 12 {
                bail!("Mobile identity IE is too short: {:?}", mobile_identity_ie)
            }
            let plmn: [u8; 3] = mobile_identity_ie[1..4].try_into().unwrap();
            let msin = &mobile_identity_ie[8..];

            // Build a 16-byte IMSI as needed by the authentication algorithm.
            let mut imsi = vec![];
            imsi.push(plmn[0] & 0xf);
            imsi.push(plmn[0] >> 4);
            imsi.push(plmn[1] & 0xf);
            if (plmn[1] >> 4) != 0xf {
                imsi.push(plmn[1] >> 4);
            }
            imsi.push(plmn[2] & 0xf);
            imsi.push(plmn[2] >> 4);
            msin.iter().for_each(|byte| {
                imsi.push(byte & 0xf);
                imsi.push(byte >> 4);
            });
            // Convert to string

            let imsi = imsi.iter().fold(String::new(), |mut s, b| {
                let _ = write!(s, "{b}");
                s
            });
            Ok(MobileIdentity::Supi(PlmnIdentity(plmn), Imsi(imsi)))
        }
        // GUTI
        0b010 => {
            if mobile_identity_ie.len() != 11 {
                bail!(
                    "GUTI Mobile identity IE contents should be 11 bytes: {:?}",
                    mobile_identity_ie
                )
            }
            Ok(MobileIdentity::Guti(Guti(
                PlmnIdentity(mobile_identity_ie[1..4].try_into().unwrap()),
                AmfIds(mobile_identity_ie[4..7].try_into().unwrap()),
                Tmsi(mobile_identity_ie[7..11].try_into().unwrap()),
            )))
        }
        // S-TMSI
        0b100 => {
            if mobile_identity_ie.len() != 7 {
                bail!(
                    "S-TMSI Mobile identity IE contents should be 7 bytes: {:?}",
                    mobile_identity_ie
                )
            }
            Ok(MobileIdentity::STmsi(STmsi(
                AmfSetAndPointer(mobile_identity_ie[1..3].try_into().unwrap()),
                Tmsi(mobile_identity_ie[3..7].try_into().unwrap()),
            )))
        }

        x => bail!("Mobile identity type {x} not supported - just SUPI, GUTI, S-TMSI"),
    }
}

pub fn pdu_session_status(pdu_session_status: &Option<NasPduSessionStatus>) -> u16 {
    pdu_session_status
        .as_ref()
        .map(|x| x.value[0] as u16 | ((x.value[1] as u16) << 8))
        .unwrap_or_default()
}

pub fn uplink_data_status(uplink_data_status: &Option<NasUplinkDataStatus>) -> u16 {
    uplink_data_status
        .as_ref()
        .map(|x| x.value[0] as u16 | ((x.value[1] as u16) << 8))
        .unwrap_or_default()
}

pub fn nas_ue_security_capability(
    ue_security_capabilities: &NasUeSecurityCapability,
) -> UeSecurityCapabilities {
    ue_security_capabilities.value[0..2].try_into().unwrap()
}

pub fn identity_response(identity_response: &NasIdentityResponse) -> Result<Imsi> {
    match fgs_mobile_identity(&identity_response.mobile_identity)? {
        MobileIdentity::Supi(_plmn, imsi) => Ok(imsi),
        x => bail!("Asked for SUPI identity, got {:?}", x),
    }
}

pub fn dnn(dnn: NasDnn) -> Result<Vec<u8>> {
    let dnn = dnn.value;

    // The first byte is a length field.
    ensure!(dnn.len() >= 2, "DNN too short");
    ensure!(
        dnn[0] as usize == dnn.len() - 1,
        "DNN length does not match IE length"
    );
    Ok(dnn[1..].into())
}
