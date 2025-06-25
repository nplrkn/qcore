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
        self.ue.nr_cgi = Some(nr_cgi);
        self.ue.tac = tai.tac.0;

        let nas = self.nas_decode(&r.nas_pdu.0)?;
        UplinkNasProcedure::new(self.0).run(nas).await
    }
}
