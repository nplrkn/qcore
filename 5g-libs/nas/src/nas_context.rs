use anyhow::{Result, anyhow, bail, ensure};
use oxirush_nas::{
    Nas5gsMessage, Nas5gsSecurityHeaderType, decode_nas_5gs_message, encode_nas_5gs_message,
    messages::Nas5gsSecurityHeader,
};
use security::nia2::calculate_nia2_mac;

#[derive(Debug, Default)]
pub struct NasContext {
    security_activated: bool,
    ik: [u8; 16],
    tx_count: u32,
    pub rx_count: u32,
}

pub type DecodedNas = (Box<Nas5gsMessage>, Option<Nas5gsSecurityHeader>);

impl NasContext {
    pub fn security_activated(&self) -> bool {
        self.security_activated
    }

    pub fn rx_nas_count(&self) -> u32 {
        self.rx_count
    }

    pub fn admit_message(
        &mut self,
        security_header: Option<&Nas5gsSecurityHeader>,
        _bytes: &[u8], // for integrity check in future
    ) -> Result<()> {
        ensure!(
            self.security_activated,
            "Cannot admit message without a security context"
        );

        if let Some(security_header) = security_header {
            // TODO: Check the security header type
            // For example,
            // -  Most messages should be Integrity Protected + Ciphered
            // -  GUTI registration should be Integrity Protected

            // Replay protection and UL NAS COUNT calculation.
            let last_rcvd_seq_num = (self.rx_count & 0xff) as u8;
            if last_rcvd_seq_num > 0xf0 && security_header.sequence_number < 0x10 {
                // u8 overflow of sequence number past of NAS COUNT - see TS33.501, 6.4.3.1.
                self.rx_count += 0x00000100;
            } else if security_header.sequence_number <= last_rcvd_seq_num && self.rx_count != 0 {
                // TS33.501, 6.4.3.2: "Replay protection shall ensure that the receiver only accepts each incoming NAS COUNT
                // value once using the same NAS security context."

                // TODO: police sequence number.  This is just a warning until the test framework is ready and we have
                // confirmed that the logic is correct with real phone interop testing.

                // We also need to be careful about reordering - can this occur?  If so, the sequence number will go backwards but
                // should not be dropped.
                // bail!(
                //     "NAS sequence number {} did not advance from last {} - dropped for replay protection",
                //     security_header.sequence_number,
                //     last_rcvd_seq_num
                // );
            }

            self.rx_count = (self.rx_count & 0x00ffff00) | security_header.sequence_number as u32;
        } else {
            // TODO: Do not allow plain messages (without security header) except for specific cases
            //bail!("Non security protected NAS message");
        }

        Ok(())
    }

    // TS33.501, 6.4.3.1
    // -  The DIRECTION bit shall be set to 0 for uplink and 1 for downlink.
    pub fn encode_dl_with_integrity(&mut self, nas: Box<Nas5gsMessage>) -> Result<Vec<u8>> {
        self.encode_with_integrity(nas, 1)
    }
    pub fn encode_ul_with_integrity(&mut self, nas: Box<Nas5gsMessage>) -> Result<Vec<u8>> {
        self.encode_with_integrity(nas, 0)
    }

    fn encode_with_integrity(&mut self, nas: Box<Nas5gsMessage>, direction: u8) -> Result<Vec<u8>> {
        let security_header_type = if self.tx_count == 0 {
            Nas5gsSecurityHeaderType::IntegrityProtectedWithNewContext
        } else {
            Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered
        };

        let nas =
            Nas5gsMessage::protect(*nas, security_header_type, 0, (self.tx_count & 0xff) as u8);
        let mut nas_bytes = encode_nas_5gs_message(&nas)?;

        // Run the MAC calculation over the inner message, which starts at byte 6.

        // TS33.501, 6.4.3.1
        // -  The BEARER input shall be equal to the NAS connection identifier.
        const BEARER: u8 = 1;

        let mac = calculate_nia2_mac(
            &self.ik,
            self.tx_count.to_be_bytes(),
            BEARER,
            direction,
            &nas_bytes[6..],
        );

        nas_bytes[2..6].copy_from_slice(&mac);

        self.tx_count = (self.tx_count + 1) & 0xffffff;
        Ok(nas_bytes)
    }

    pub fn decode(&mut self, data: &[u8]) -> Result<DecodedNas> {
        let nas_message = Box::new(
            decode_nas_5gs_message(data)
                .map_err(|e| anyhow!("NAS decode error - {e} - message bytes: {:?}", data))?,
        );
        let (nas, security_header) = match *nas_message {
            Nas5gsMessage::Gmm(_, _) => (nas_message, None),
            Nas5gsMessage::SecurityProtected(hdr, bx) => (bx, Some(hdr)),
            Nas5gsMessage::Gsm(_, _) => bail!("Unexpected Nas SM message {:?} ", nas_message),
        };

        if self.security_activated {
            self.admit_message(security_header.as_ref(), data)?;
        }

        Ok((nas, security_header))
    }

    pub fn enable_security(&mut self, knasint: [u8; 16]) {
        self.security_activated = true;
        self.ik = knasint;
        self.rx_count = 0;
        self.tx_count = 0;
    }

    pub fn encode_dl(&mut self, nas: Box<Nas5gsMessage>) -> Result<Vec<u8>> {
        let nas = if self.security_activated {
            self.encode_dl_with_integrity(nas)?
        } else {
            encode_nas_5gs_message(&nas)?
        };
        Ok(nas)
    }
}
