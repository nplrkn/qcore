use super::prelude::*;
use ngap::{InitialUeMessage, UserLocationInformation, UserLocationInformationNr};

impl<'a, B: RanUeBase> NgapUeProcedure<'a, B> {
    pub async fn initial_ue_message(
        &mut self,
        r: Box<InitialUeMessage>,
        core_context: &'a mut UeContext5GC,
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

        // The UE technically isn't CM-Connected until the N2 context is established
        // (TS23.501, figure 5.3.3.2.4-2), but from an info logging point of view, this is the best place to
        // introduce the new UE ID.
        info!(self.logger, "New UE RAN connection");

        let stmsi: Option<Vec<u8>> = r.five_g_s_tmsi.map(|x| {
            let mut stmsi = x.amf_set_id.0.clone();
            stmsi.extend_from_bitslice(&x.amf_pointer.0);
            let mut stmsi: Vec<u8> = stmsi.into();
            stmsi.extend_from_slice(&x.five_g_tmsi.0);
            stmsi
        });

        self.nas_procedure(core_context)
            .initial_nas(r.nas_pdu.0, stmsi.as_deref())
            .await
    }
}
