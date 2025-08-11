use super::prelude::*;
use ngap::{Cause, CauseMisc};

impl<'a, B: RanUeBase> NgapUeProcedure<'a, B> {
    pub async fn pdu_session_resource_release(
        &mut self,
        released_session: &PduSession,
        nas: Vec<u8>,
    ) -> Result<()> {
        let req = crate::ngap::build::pdu_session_resource_release_command(
            self.ue.amf_ue_ngap_id(),
            self.ue.ran_ue_ngap_id(),
            released_session,
            nas,
            Cause::Misc(CauseMisc::Unspecified), // TODO: provide a meaningful cause
        )?;
        self.log_message("<< Ngap PduSessionResourceReleaseCommand");
        let _rsp = self
            .api
            .xxap_request::<ngap::PduSessionResourceReleaseProcedure>(req, &self.logger)
            .await?;
        self.log_message(">> Ngap PduSessionResourceReleaseResponse");
        Ok(())
    }
}
