use super::prelude::*;
use crate::nas::*;
use oxirush_nas::{
    Nas5gmmMessage, Nas5gsMessage, decode_nas_5gs_message, messages::NasServiceRequest,
};

impl<'a, B: NasBase> NasProcedure<'a, B> {
    pub async fn service(&mut self, r: Box<NasServiceRequest>) -> Result<()> {
        self.log_message(">> Nas ServiceRequest");

        // Ensure that the UE security context has been retrieved based on the TMSI in the outer message.
        if !self.ue.nas.security_activated() {
            warn!(self.logger, "Rejecting Nas Service Request - unknown TMSI");
            self.reject(FGMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED)
                .await?;
            return Ok(());
        }

        // Check that the TMSI in the inner message matches that in UE context (and hence the one in the outer message).
        let mut tmsi_matches = false;
        if let Ok(MobileIdentity::STmsi(x)) = crate::nas::parse::fgs_mobile_identity(&r.fg_s_tmsi) {
            if let Some(tmsi) = &self.ue.tmsi {
                if tmsi.0 == x.1.0 && self.api.config().amf_ids.0[1..3] == x.0.0 {
                    tmsi_matches = true;
                }
            } else {
                debug!(self.logger, "No TMSI on this UE");
            }
        } else {
            debug!(self.logger, "Non S-TMSI identity on Service request");
        }
        if !tmsi_matches {
            warn!(self.logger, "S-TMSI mismatch in Service request");
            self.reject(FGMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED)
                .await?;
        }

        // If there is an inner ServiceRequest message contained, switch to using it from now on.
        let service_request = if let Some(x) = r.nas_message_container {
            let inner_message = Box::new(
                decode_nas_5gs_message(&x.value)
                    .map_err(|e| anyhow!("NAS decode error - {e} - message bytes: {:?}", x))?,
            );
            if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::ServiceRequest(x)) = *inner_message {
                Box::new(x)
            } else {
                bail!(
                    "Service Request outer message non-Service Request inner message {:?}",
                    inner_message
                )
            }
        } else {
            r
        };

        let (active_sessions, reactivation_result) = self
            .reconcile_sessions(
                &service_request.uplink_data_status,
                &service_request.pdu_session_status,
            )
            .await?;

        info!(
            self.logger,
            "UE service request - reactivate existing session(s)"
        );

        let accept = crate::nas::build::service_accept(active_sessions, reactivation_result);
        self.log_message("<< Nas ServiceAccept");
        let ue_was_paged = self.ran_context_create(accept).await?;
        if ue_was_paged {
            // TS 24.501, 5.4.4.1
            // "[Configuration Update] procedure shall be initiated by the network to assign a new 5G-GUTI to the UE
            // after ... a successful service request procedure invoked as a response to a paging request from the network.

            // Regenerate GUTI and send a configuration update to update it.
            // TODO: actually the new GUTI should only be stored after the configuration update
            // has been acknowledged - TS 24.501, 5.4.4.4
            //   If a new 5G-GUTI was included in the CONFIGURATION UPDATE COMMAND message, the AMF shall
            //   consider the new 5G-GUTI as valid and the old 5G-GUTI as invalid.
            let guti = self.allocate_guti().await;
            self.perform_configuration_update(Some(guti)).await
        } else {
            Ok(())
        }
    }

    async fn reject(&mut self, cause: u8) -> Result<()> {
        let reject = crate::nas::build::service_reject(cause);
        self.log_message("<< Nas ServiceReject");
        self.send_nas(reject).await
    }
}
