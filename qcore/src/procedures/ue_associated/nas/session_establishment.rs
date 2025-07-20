use super::prelude::*;
use crate::PduSession;
use oxirush_nas::messages::{Nas5gsmHeader, NasPduSessionEstablishmentRequest};
use xxap::Snssai;

define_ue_procedure!(SessionEstablishmentProcedure);

impl<'a, A: HandlerApi> SessionEstablishmentProcedure<'a, A> {
    pub async fn run(
        mut self,
        hdr: Nas5gsmHeader,
        _r: &NasPduSessionEstablishmentRequest,
        dnn: Option<Vec<u8>>,
    ) -> Result<()> {
        self.log_message(">> Nas PduSessionEstablishmentRequest");
        // TODO: check request
        let session_id = hdr.pdu_session_identity;
        let session = PduSession {
            id: session_id,
            snssai: Snssai(self.config().sst, Some([0, 0, 0])),
            userplane_info: self.api.reserve_userplane_session(self.logger).await?,
            dnn: dnn.unwrap_or(b"internet".to_vec()),
        };

        let accept = crate::nas::build::pdu_session_establishment_accept(
            &session,
            hdr.procedure_transaction_identity,
            self.config().sst,
        )?;
        self.ue.core.pdu_sessions.push(session);
        self.log_message("<< Nas PduSessionEstablishmentAccept");
        let _ = self.0.ran_session_setup(accept).await?;
        Ok(())
    }
}
