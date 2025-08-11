use super::prelude::*;
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

        let mut session = PduSession {
            id: hdr.pdu_session_identity,
            snssai: Snssai(self.api.config().sst, Some([0, 0, 0])),
            userplane_info: self.api.allocate_userplane_session().await?,
            dnn: dnn.unwrap_or(b"internet".to_vec()),
        };

        let accept = crate::nas::build::pdu_session_establishment_accept(
            &session,
            hdr.procedure_transaction_identity,
            self.api.config().sst,
        )?;

        self.log_message("<< Nas PduSessionEstablishmentAccept");
        let accept = self.ue.nas.encode(accept)?;
        self.api.ran_session_setup(&mut session, accept).await?;
        self.ue.pdu_sessions.push(session);

        Ok(())
    }
}
