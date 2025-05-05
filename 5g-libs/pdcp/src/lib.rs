//! lib - wrap and unwrap PDCP packets

use anyhow::{Result, ensure};
use security::nia2;

const PDCP_SN_DL_MASK: u16 = 0x0fff; // 12 bits, as per TS38.323, 6.3.2
const DIRECTION_DL: u8 = 1; // TS33.401, B.2.1

#[derive(Debug, Default)]

pub struct PdcpTx {
    pub tx_next: u32,
    pub pdcp_integrity_key: Option<[u8; 16]>,
}
pub struct PdcpPdu(pub Vec<u8>);
impl PdcpPdu {
    /// View the inner packet in a PDCP packet.
    pub fn view_inner(&self) -> Result<&[u8]> {
        ensure!(self.0.len() >= 6, "Too short for PDCP PDU");
        Ok(&self.0[2..self.0.len() - 4])
    }
}

impl PdcpTx {
    pub fn enable_security(&mut self, ik: [u8; 16]) {
        self.pdcp_integrity_key = Some(ik);
    }

    /// Encapsulate an inner packet in an outer PDCP packet.
    pub fn encode(&mut self, srb_id: u8, inner: Vec<u8>) -> PdcpPdu {
        let pdcp_seq_num = if srb_id == 0 {
            0
        } else {
            self.tx_next as u16 & PDCP_SN_DL_MASK
        };
        let mut pdcp_pdu = pdcp_seq_num.to_be_bytes().to_vec(); // 4 bits reserved, 12 bits of sequence numbers
        pdcp_pdu.extend(inner);

        let mut mac = [0u8; 4];
        if srb_id > 0 {
            assert!(srb_id == 1); // TODO temporary limitation that we only support SRB1

            // TS38.323, 5.2.1: associate the COUNT value corresponding to TX_NEXT to this PDCP SDU
            let count = self.tx_next;

            // TS 38.323, 5.8.  The required inputs to the integrity protection function include the COUNT value,
            // and DIRECTION (direction of the transmission: set as specified in TS 33.501 [6]) or TS 33.401 [17].
            // The parameters required by PDCP which are provided by upper layers TS 38.331 [3] are listed below:
            // - BEARER (defined as the radio bearer identifier in TS 33.501 [6] or TS 33.401 [17]. It will use the value
            //   RB identity –1 as in TS 38.331 [3]);
            // - KEY (the integrity protection keys for the control plane and for the user plane are KRRCint and
            //   KUPint, respectively).
            let bearer = srb_id - 1;

            if let Some(ik) = self.pdcp_integrity_key {
                mac = nia2::calculate_nia2_mac(
                    &ik,
                    count.to_be_bytes(),
                    bearer,
                    DIRECTION_DL,
                    &pdcp_pdu,
                )
            }
            self.tx_next += 1;
        }
        pdcp_pdu.extend(mac);

        PdcpPdu(pdcp_pdu)
    }
}

impl From<PdcpPdu> for Vec<u8> {
    fn from(p: PdcpPdu) -> Self {
        p.0
    }
}
