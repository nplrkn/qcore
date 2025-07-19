use super::prelude::*;
use crate::procedures::ue_associated::UplinkNasProcedure;
use ngap::{InitialUeMessage, UserLocationInformation, UserLocationInformationNr};

define_ue_procedure!(InitialUeMessageProcedure);

impl<'a, A: HandlerApi> InitialUeMessageProcedure<'a, A> {
    pub async fn run(mut self, r: Box<InitialUeMessage>) -> Result<()> {
        self.log_message(">> Ngap InitialUeMessage");

        let UserLocationInformation::UserLocationInformationNr(UserLocationInformationNr {
            nr_cgi,
            tai,
            ..
        }) = r.user_location_information
        else {
            bail!("Expected Nr user location information");
        };
        self.ue.remote_ran_ue_id = r.ran_ue_ngap_id.0;
        self.ue.nr_cgi = Some(nr_cgi);
        self.ue.core.tac = tai.tac.0;

        // If there is a valid S-TMSI, retrieve the UE context now, so the NAS context is in place for the NAS decode.
        if let Some(x) = r.five_g_s_tmsi {
            let mut amf_set_and_pointer = x.amf_set_id.0.clone();
            amf_set_and_pointer.extend_from_bitslice(&x.amf_pointer.0);
            let amf_set_and_pointer = amf_set_and_pointer.as_raw_slice();
            match self
                .retrieve_ue2(None, amf_set_and_pointer, &x.five_g_tmsi.0)
                .await
            {
                Ok(false) => debug!(
                    self.logger,
                    "Successfully retrieved TMSI prior to NAS decode"
                ),
                Ok(true) => debug!(self.logger, "Unknown TMSI in outer NGAP message"),
                Err(e) => warn!(self.logger, "Error retrieving UE {e}"),
            }
        }

        // TODO - protect against retrieval of UE context by a TMSI that does not actually pass its integrity check
        // TODO - cross check inner TMSI against outer TMSI

        let nas = self.nas_decode(&r.nas_pdu.0)?;
        UplinkNasProcedure::new(self.0).run(nas).await
    }
}
