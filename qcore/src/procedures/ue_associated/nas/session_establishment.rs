use super::prelude::*;
use crate::PduSession;
use oxirush_nas::messages::{Nas5gsmHeader, NasPduSessionEstablishmentRequest};
use xxap::Snssai;

impl<'a, B: NasBase> NasProcedure<'a, B> {
    pub async fn session_establishment(
        &mut self,
        hdr: Nas5gsmHeader,
        _r: &NasPduSessionEstablishmentRequest,
        dnn: Option<Vec<u8>>,
    ) -> Result<()> {
        self.log_message(">> Nas PduSessionEstablishmentRequest");
        // TODO: check request
        let session_id = hdr.pdu_session_identity;
        let session = PduSession {
            id: session_id,
            snssai: Snssai(self.api.config().sst, Some([0, 0, 0])),
            userplane_info: self.api.reserve_userplane_session(self.logger).await?,
            dnn: dnn.unwrap_or(b"internet".to_vec()),
        };

        let accept = crate::nas::build::pdu_session_establishment_accept(
            &session,
            hdr.procedure_transaction_identity,
            self.api.config().sst,
        )?;

        // TODO: once all tests are working, try moving this after the .ran_session_setup
        // so as to get rid of the last_mut().unwrap().
        self.ue.pdu_sessions.push(session);
        self.log_message("<< Nas PduSessionEstablishmentAccept");
        let accept = self.ue.nas.encode(accept)?;
        self.api
            .ran_session_setup(self.ue.pdu_sessions.last_mut().unwrap(), accept)
            .await
    }
}
