use crate::{
    protocols::nas::{FGSM_CAUSE_INSUFFICIENT_RESOURCES, FGSM_CAUSE_UNKNOWN_PDU_SESSION_TYPE},
    ue_dhcp_identifier,
};

use super::prelude::*;
use oxirush_nas::{
    NasPduSessionType,
    messages::{Nas5gsmHeader, NasPduSessionEstablishmentRequest},
};
use xxap::Snssai;

impl<'a, B: NasBase> NasProcedure<'a, B> {
    pub async fn session_establishment(
        &mut self,
        hdr: Nas5gsmHeader,
        r: &NasPduSessionEstablishmentRequest,
        dnn: Option<Vec<u8>>,
    ) -> Result<()> {
        self.log_message(">> Nas PduSessionEstablishmentRequest");

        let session_id = hdr.pdu_session_identity;
        let pti = hdr.procedure_transaction_identity;

        let ipv4 = if let Some(NasPduSessionType { value, .. }) = r.pdu_session_type {
            match value {
                0b001 => true,  // IPv4
                0b101 => false, // Ethernet
                0b111 => {
                    debug!(self.logger, "UE requested IPv4v6 - accept IPv4 only");
                    true
                }
                _ => {
                    warn!(self.logger, "Unsupported PduSessionType {value:03b}");
                    self.session_reject(session_id, pti, FGSM_CAUSE_UNKNOWN_PDU_SESSION_TYPE)
                        .await?;
                    return Ok(());
                }
            }
        } else {
            true
        };

        let userplane = match self
            .api
            .allocate_userplane_session(ipv4, ue_dhcp_identifier(&self.ue.imsi)?)
            .await
        {
            Ok(userplane) => userplane,
            Err(e) => {
                warn!(self.logger, "{e}");
                self.session_reject(session_id, pti, FGSM_CAUSE_INSUFFICIENT_RESOURCES)
                    .await?;
                return Ok(());
            }
        };

        let mut session = PduSession {
            id: hdr.pdu_session_identity,
            snssai: Snssai(self.api.config().sst, Some([0, 0, 0])),
            userplane,
            dnn: dnn.unwrap_or(b"internet".to_vec()),
        };

        let accept = crate::nas::build::pdu_session_establishment_accept(
            &session,
            hdr.procedure_transaction_identity,
            self.api.config().sst,
        )?;

        self.log_message("<< Nas PduSessionEstablishmentAccept");
        let accept = self.ue.nas.encode_dl(accept)?;
        self.api.ran_session_setup(&mut session, accept).await?;
        self.ue.pdu_sessions.push(session);

        Ok(())
    }

    async fn session_reject(&mut self, session_id: u8, pti: u8, cause: u8) -> Result<()> {
        let reject = crate::nas::build::pdu_session_establishment_reject(session_id, pti, cause)?;
        self.log_message("<< Nas PduSessionEstablishmentReject");
        self.send_nas(reject).await
    }
}
