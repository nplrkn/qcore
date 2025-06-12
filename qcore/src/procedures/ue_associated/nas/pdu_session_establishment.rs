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
        let mut session = PduSession {
            id: session_id,
            snssai: Snssai(self.config().sst, Some([0, 0, 0])),
            userplane_info: self.api.reserve_userplane_session(self.logger).await?,
            dnn: dnn.unwrap_or(b"internet".to_vec()),
            cell_group_config: None,
        };

        self.0 = self.0.ran_session_setup_phase1(&mut session).await?;

        let accept = crate::nas::build::pdu_session_establishment_accept(
            &session,
            hdr.procedure_transaction_identity,
            self.config().sst,
        )?;
        let accept = self.ue.nas.encode(accept)?;

        self.commit_userplane_session(&session.userplane_info, self.logger)
            .await?;
        self.ue.pdu_sessions.push(session);
        let session_index = self.ue.pdu_sessions.len() - 1;

        self.log_message("<< NasPduSessionEstablishmentAccept");
        self.0.ran_session_setup_phase2(accept, session_index).await
    }
}
