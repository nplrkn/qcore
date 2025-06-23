use super::prelude::*;
use crate::{data::PduSession, procedures::ue_associated::RrcReconfigurationProcedure};

define_ue_procedure!(RanSessionReleaseProcedure);
impl<'a, A: HandlerApi> RanSessionReleaseProcedure<'a, A> {
    pub async fn run(
        self,
        released_session: &PduSession,
        nas: Vec<u8>,
    ) -> Result<UeProcedure<'a, A>> {
        // Send a UE context modification to delete the DRB.
        todo!()
    }
}
