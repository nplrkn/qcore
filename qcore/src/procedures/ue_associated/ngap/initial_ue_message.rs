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

        let stmsi: Option<Vec<u8>> = r.five_g_s_tmsi.map(|x| {
            let mut stmsi = x.amf_set_id.0.clone();
            stmsi.extend_from_bitslice(&x.amf_pointer.0);
            let mut stmsi: Vec<u8> = stmsi.into();
            stmsi.extend_from_slice(&x.five_g_tmsi.0);
            stmsi
        });

        UplinkNasProcedure::new(self.0)
            .run_initial(r.nas_pdu.0, stmsi.as_deref())
            .await
    }
}
