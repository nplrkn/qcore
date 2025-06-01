use anyhow::Result;
use oxirush_nas::{
    Nas5gsMessage, Nas5gsSecurityHeaderType, encode_nas_5gs_message, messages::Nas5gsSecurityHeader,
};
use security::nia2::calculate_nia2_mac;

// TODO - should this really be cloneable
#[derive(Clone, Debug)]
pub struct SecurityContext {
    ik: [u8; 16],
    dl_count: u32,
    pub ul_count: u32,
}

impl SecurityContext {
    pub fn new(ik: [u8; 16]) -> Self {
        SecurityContext {
            ik,
            dl_count: 0,
            ul_count: 0,
        }
    }

    pub fn admit_message(
        &mut self,
        security_header: Option<&Nas5gsSecurityHeader>,
        _bytes: &[u8], // for integrity check in future
    ) -> Result<()> {
        if let Some(security_header) = security_header {
            let last_rcvd_seq_num = (self.ul_count & 0xff) as u8;

            if last_rcvd_seq_num > 0xf0 && security_header.sequence_number < 0x10 {
                // u8 overflow of sequence number past of NAS COUNT - see TS33.501, 6.4.3.1.
                self.ul_count += 0x00000100;
            } else if security_header.sequence_number <= last_rcvd_seq_num {
                // TS33.501, 6.4.3.2: "Replay protection shall ensure that the receiver only accepts each incoming NAS COUNT
                // value once using the same NAS security context."

                // TODO: this kicked in on the NAS security mode complete with a real phone.
                // Clearly the security mode complete should be sequence number 0.
                // bail!(
                //     "NAS sequence number {} did not advance from last {} - dropped for replay protection",
                //     security_header.sequence_number,
                //     last_rcvd_seq_num
                // );
            }

            self.ul_count = (self.ul_count & 0x00ffff00) | security_header.sequence_number as u32;
        }

        // TODO: Check the security header type
        // For example,
        // -  Most messages should be Integrity Protected + Ciphered
        // -  GUTI registration should be Integrity Protected

        // TODO: Do not allow plain messages (without security header) except for specific cases

        Ok(())
    }

    pub fn encode_with_integrity(&mut self, nas: Box<Nas5gsMessage>) -> Result<Vec<u8>> {
        let security_header_type = if self.dl_count == 0 {
            Nas5gsSecurityHeaderType::IntegrityProtectedWithNewContext
        } else {
            Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered
        };

        let nas =
            Nas5gsMessage::protect(*nas, security_header_type, 0, (self.dl_count & 0xff) as u8);
        let mut nas_bytes = encode_nas_5gs_message(&nas)?;

        // Run the MAC calculation over the inner message, which starts at byte 6.

        // TS33.501, 6.4.3.1
        // The BEARER input shall be equal to the NAS connection identifier.
        let bearer = 1;

        // The DIRECTION bit shall be set to 0 for uplink and 1 for downlink.
        let direction = 0b1;

        let mac = calculate_nia2_mac(
            &self.ik,
            self.dl_count.to_be_bytes(),
            bearer,
            direction,
            &nas_bytes[6..],
        );

        nas_bytes[2] = mac[0];
        nas_bytes[3] = mac[1];
        nas_bytes[4] = mac[2];
        nas_bytes[5] = mac[3];

        self.dl_count = (self.dl_count + 1) & 0xffffff;
        Ok(nas_bytes)
    }
}
