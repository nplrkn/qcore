use anyhow::{Result, bail};
use f1ap::PlmnIdentity;
use oxirush_nas::NasFGsMobileIdentity;
use std::fmt::Write;

use super::{AmfIds, Imsi, MobileIdentity, Tmsi}; // Import the Write trait for String

pub fn fgs_mobile_identity(fgs_mobile_identity: &NasFGsMobileIdentity) -> Result<MobileIdentity> {
    // Get the SUPI.  TODO: SUCI + GUTI support.
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
            Ok(MobileIdentity::Guti(
                PlmnIdentity(mobile_identity_ie[1..4].try_into().unwrap()),
                AmfIds(mobile_identity_ie[4..7].try_into().unwrap()),
                Tmsi(mobile_identity_ie[7..11].try_into().unwrap()),
            ))
        }

        x => bail!("Mobile identity type {x} not supported - just SUPI and GUTI"),
    }
}
