use super::prelude::*;
use crate::{data::UeContext5GC, procedures::ue_associated::NasProcedure};
use ngap::{InitialUeMessage, UserLocationInformation, UserLocationInformationNr};

impl<'a, B: RanUeBase> NgapUeProcedure<'a, B> {
    pub async fn initial_ue_message(
        &mut self,
        r: Box<InitialUeMessage>,
        core_context: &mut UeContext5GC,
    ) -> Result<()> {
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
        self.ue.tac = tai.tac.0;

        let stmsi: Option<Vec<u8>> = r.five_g_s_tmsi.map(|x| {
            let mut stmsi = x.amf_set_id.0.clone();
            stmsi.extend_from_bitslice(&x.amf_pointer.0);
            let mut stmsi: Vec<u8> = stmsi.into();
            stmsi.extend_from_slice(&x.five_g_tmsi.0);
            stmsi
        });

        // TODO - pass in the TAC so it can be populated in the core context
        let result = NasProcedure {
            ue: core_context,
            logger: &self.logger.clone(),
            api: self,
        }
        .initial_nas(r.nas_pdu.0, stmsi.as_deref())
        .await;
        result
    }
}
