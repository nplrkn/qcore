use super::prelude::*;
use crate::data::PduSession;
use ngap::{Cause, CauseMisc};

define_ue_procedure!(RanSessionReleaseProcedure);
impl<'a, A: HandlerApi> RanSessionReleaseProcedure<'a, A> {
    pub async fn run(
        self,
        released_session: &PduSession,
        nas: Vec<u8>,
    ) -> Result<UeProcedure<'a, A>> {
        let req = crate::ngap::build::pdu_session_resource_release_command(
            self.ue.amf_ue_ngap_id(),
            self.ue.ran_ue_ngap_id(),
            released_session,
            nas,
            Cause::Misc(CauseMisc::Unspecified), // TODO: provide a meaningful cause
        )?;
        self.log_message("<< Ngap PduSessionResourceReleaseCommand");
        let _rsp = self
            .xxap_request::<ngap::PduSessionResourceReleaseProcedure>(req, self.logger)
            .await?;
        self.log_message(">> Ngap PduSessionResourceReleaseResponse");
        Ok(self.0)
    }
}
