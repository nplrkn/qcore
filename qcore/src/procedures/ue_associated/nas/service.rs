use super::prelude::*;
use crate::nas::*;
use oxirush_nas::messages::{Nas5gsSecurityHeader, NasServiceRequest};

define_ue_procedure!(ServiceProcedure);

impl<'a, A: HandlerApi> ServiceProcedure<'a, A> {
    pub async fn run(
        mut self,
        r: Box<NasServiceRequest>,
        security_header: Option<Nas5gsSecurityHeader>,
    ) -> Result<()> {
        self.log_message(">> Nas ServiceRequest");
        match self.handle(r, security_header).await {
            Ok(()) => {
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
                let kgnb = security::derive_kgnb(&self.ue.kamf, self.ue.nas.ul_nas_count());
                self.0 = self.0.ran_ue_registration(&kgnb).await?;
                self.accept().await?;
                //self.send_configuration_update().await?;
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

    async fn accept(&mut self) -> Result<()> {
        //let accept = crate::nas::build::service_accept();
        self.log_message("<< Nas ServiceAccept");
        //self.nas_indication(accept).await
        todo!()
    }

    async fn reject(&mut self, _cause: u8) -> Result<()> {
        //let reject = crate::nas::build::service_reject(cause);
        self.log_message("<< Nas ServiceReject");
        //self.nas_indication(reject).await
        todo!()
    }

    async fn handle(
        &mut self,
        request: Box<NasServiceRequest>,
        security_header: Option<Nas5gsSecurityHeader>,
    ) -> Result<(), u8> {
        let STmsi(amf_set_and_pointer, tmsi) = self.check_service_request(request)?;
        match self
            .retrieve_ue(None, &amf_set_and_pointer.0, &tmsi, security_header)
            .await
        {
            Ok(true) => todo!(),
            Ok(false) => todo!(),
            Err(e) => Err(e),
        }
    }

    fn check_service_request(&self, service_request: Box<NasServiceRequest>) -> Result<STmsi, u8> {
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

    // async fn send_configuration_update(&mut self) -> Result<()> {
    //     let command =
    //         crate::nas::build::configuration_update_command(&self.config().network_display_name);
    //     self.log_message("<< Nas ConfigurationUpdateCommand");
    //     self.nas_indication(command).await
    // }
}
