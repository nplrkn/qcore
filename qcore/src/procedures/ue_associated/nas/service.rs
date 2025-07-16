use super::prelude::*;
use crate::nas::*;
use anyhow::ensure;
use oxirush_nas::{
    Nas5gmmMessage, Nas5gsMessage, NasFGsMobileIdentity, decode_nas_5gs_message,
    messages::{Nas5gsSecurityHeader, NasServiceRequest},
};

define_ue_procedure!(ServiceProcedure);

impl<'a, A: HandlerApi> ServiceProcedure<'a, A> {
    pub async fn run(
        mut self,
        r: Box<NasServiceRequest>,
        security_header: Option<Nas5gsSecurityHeader>,
    ) -> Result<()> {
        self.log_message(">> Nas ServiceRequest");

        // There should be an inner ServiceRequest message contained in this.
        let Some(ref inner_message) = r.nas_message_container else {
            bail!("Service request missing message container")
        };
        let inner_message =
            Box::new(decode_nas_5gs_message(&inner_message.value).map_err(|e| {
                anyhow!(
                    "NAS decode error - {e} - message bytes: {:?}",
                    inner_message
                )
            })?);
        let inner_message =
            if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::ServiceRequest(x)) = *inner_message {
                x
            } else {
                bail!(
                    "Security mode complete contained non-registration nas message {:?}",
                    inner_message
                )
            };

        let sessions_to_reactivate =
            if let Some(uplink_data_status) = inner_message.uplink_data_status {
                uplink_data_status.value[0..2].to_vec()
            } else {
                vec![0u8; 2]
            };

        match self.lookup_ue(&r, security_header).await {
            Ok(()) => {
                // Reactivate sessions
                let mut session_status = [0u8; 2];
                for session in self.ue.pdu_sessions.iter() {
                    let id = session.id;
                    ensure!(id < 16, "Session ID >= 16 not supported");
                    session_status[(id / 8) as usize] |= 1 << id % 8;
                }

                // TODO - commonize
                // Derive Kgnb, and from that kRRCInt.

                /* TS33.501, 6.8.1.1.2.3: "The NAS (uplink and downlink) COUNTs are set to start
                   values, and the start value of the uplink NAS COUNT shall be used as freshness 
                   parameter in the KgNB derivation from the fresh KAMF (after primary authentication) 
                   when UE receives AS SMC the KgNB is derived from the current 5G NAS security context, 
                   i.e., the fresh KAMF is used to derive the KgNB." */

                /* 6.8.1.1.2.2: When the UE receives the AS SMC without having received a NAS Security Mode Command after the Registration Request
                with "PDU session(s) to be re-activated", it shall use the uplink NAS COUNT of the Registration Request message that
                triggered the AS SMC to be sent as freshness parameter in the derivation of the initial KgNB/KeNB.           */
                debug!(self.logger, "UL NAS COUNT {}", self.ue.nas.ul_nas_count());
                let _kgnb = security::derive_kgnb(&self.ue.kamf, self.ue.nas.ul_nas_count());
                //self.0 = self.0.ran_ue_registration(&kgnb).await?;

                // If the UE is asking to reactivate a session that does not exist, set the relevant bit in the result
                let reactivation_result = [
                    sessions_to_reactivate[0] & !session_status[0],
                    sessions_to_reactivate[1] & !session_status[1],
                ];

                let accept = crate::nas::build::service_accept(session_status, reactivation_result);
                self.log_message("<< Nas ServiceAccept");
                self.nas_indication(accept).await?;

                // Regenerate GUTI and send a configuration update to update it.
                let guti = self.allocate_tmsi().await;
                self.send_configuration_update(guti).await?;
            }
            Err(cause) => {
                if cause != ABORT_PROCEDURE {
                    self.reject(cause).await?
                } else {
                    bail!("Abort registration procedure")
                }
            }
        }

        Ok(())
    }

    async fn reject(&mut self, _cause: u8) -> Result<()> {
        //let reject = crate::nas::build::service_reject(cause);
        self.log_message("<< Nas ServiceReject");
        //self.nas_indication(reject).await
        todo!()
    }

    async fn lookup_ue(
        &mut self,
        request: &NasServiceRequest,
        security_header: Option<Nas5gsSecurityHeader>,
    ) -> Result<(), u8> {
        let STmsi(amf_set_and_pointer, tmsi) = self.check_service_request(request)?;
        match self
            .retrieve_ue(None, &amf_set_and_pointer.0, &tmsi, security_header)
            .await
        {
            Ok(true) => Err(FGMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED),
            Ok(false) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn check_service_request(&self, service_request: &NasServiceRequest) -> Result<STmsi, u8> {
        match crate::nas::parse::fgs_mobile_identity(&service_request.fg_s_tmsi) {
            Ok(MobileIdentity::STmsi(x)) => return Ok(x),
            Ok(x) => {
                warn!(
                    self.logger,
                    "Expected STmsi mobile identity on service request, got {x:?}"
                );
            }
            Err(e) => {
                warn!(self.logger, "{e}");
            }
        }
        Err(FGMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED)
    }

    async fn send_configuration_update(&mut self, guti: NasFGsMobileIdentity) -> Result<()> {
        let command = crate::nas::build::configuration_update_command(None, Some(guti));
        self.log_message("<< Nas ConfigurationUpdateCommand");
        self.nas_indication(command).await
    }
}
