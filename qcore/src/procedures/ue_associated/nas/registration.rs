use super::prelude::*;
use crate::nas::*;
use oxirush_nas::messages::{Nas5gsSecurityHeader, NasRegistrationRequest};
use oxirush_nas::{
    Nas5gmmMessage, Nas5gsMessage, NasFGsMobileIdentity, NasMessageContainer,
    NasUeSecurityCapability, decode_nas_5gs_message,
};

impl<'a, B: NasBase> NasProcedure<'a, B> {
    pub async fn registration(
        &mut self,
        request: Box<NasRegistrationRequest>,
        _security_header: Option<Nas5gsSecurityHeader>,
    ) -> Result<()> {
        match self.validate_registration(request).await {
            Ok(request) => {
                let (current_sessions, reactivation_result) =
                    self.process_session_reactivation(&request).await?;
                let guti = self.allocate_guti().await;
                let accept =
                    self.build_registration_accept(guti, reactivation_result, current_sessions);
                let _ue_was_paged = self
                    .ran_context_create(accept)
                    .await
                    .context("context creation")?;
                self.receive_registration_complete()
                    .await
                    .context("awaiting registration complete")?;
                self.perform_configuration_update(None)
                    .await
                    .context("configuration update")
            }
            Err(NasProcedureError::Fail(cause, err)) => {
                warn!(self.logger, "Reject registration: {:#}", err);
                self.reject_registration(cause).await
            }
            Err(NasProcedureError::Abort(cause)) => Err(cause),
        }
    }

    async fn reject_registration(&mut self, cause: u8) -> Result<()> {
        let reject = crate::nas::build::registration_reject(cause);
        self.log_message("<< Nas RegistrationReject");
        self.send_nas(reject).await
    }

    async fn process_session_reactivation(
        &mut self,
        registration_request: &NasRegistrationRequest,
    ) -> Result<(u16, Option<u16>)> {
        self.reconcile_sessions(
            &registration_request.uplink_data_status,
            &registration_request.pdu_session_status,
        )
        .await
        .inspect(|(sessions, _)| {
            if *sessions != 0 {
                info!(self.logger, "UE reregistration with existing session(s)")
            }
        })
    }

    fn build_registration_accept(
        &self,
        guti: NasFGsMobileIdentity,
        reactivation_result: Option<u16>,
        current_sessions: u16,
    ) -> Box<Nas5gsMessage> {
        debug!(
            self.logger,
            "Allowed NSSAIs: SST {} with and without SD 0",
            self.api.config().sst
        );

        let accept = crate::nas::build::registration_accept(
            self.api.config().sst,
            guti,
            &self.api.config().plmn,
            self.api.ue_tac(),
            reactivation_result,
            current_sessions,
        );
        self.log_message("<< Nas RegistrationAccept");

        accept
    }

    async fn receive_registration_complete(&mut self) -> Result<()> {
        let _registration_complete = self
            .receive_nas_response(nas_filter!(RegistrationComplete), "Registration Complete")
            .await?;
        Ok(())
    }

    // Takes as input the cleartext only registration request, and returns the full registration request
    async fn validate_registration(
        &mut self,
        request: Box<NasRegistrationRequest>,
    ) -> Result<Box<NasRegistrationRequest>, NasProcedureError> {
        self.log_message(">> Nas RegistrationRequest");

        // If this is a registration update and security is not activated then we failed to retrieve the UE context
        // based on the TMSI in the outer message.  Tell the UE it needs to do an initial registration.
        let is_registration_update = request.fgs_registration_type.value & REGISTRATION_TYPE_MASK
            != REGISTRATION_TYPE_INITIAL;

        if is_registration_update && !self.ue.nas.security_activated() {
            // TS24.501 5.5.1.3.5
            // "The UE shall enter the state 5GMM-DEREGISTERED.NORMAL-SERVICE. The UE shall delete any mapped 5G NAS
            // security context or partial native 5G NAS security context."
            return Err(NasProcedureError::Fail(
                FGMM_CAUSE_IMPLICITLY_DEREGISTERED,
                anyhow!(
                    "Reject security protected registration update with unknown or missing TMSI in outer message"
                ),
            ));
        };

        // The UE is authenticated based on cleartext IEs in the outer message.  Any non-cleartext IEs (such as those
        // governing session reactivation) come in a NAS message container (TS24.501, 4.4.6).
        //   -  On a initial GUTI registration that reusing existing security context, the NAS message container IE is in the Registration Request
        //   -  Otherwise, it comes in the Security Mode Complete.
        let nas_message_container = {
            match self.check_registration_request(&request)? {
                (RegistrationType::Supi(Imsi(imsi)), ue_security_capability) => {
                    self.supi_registration(&imsi, &ue_security_capability)
                        .await?
                }

                (RegistrationType::Guti, ue_security_capability) => {
                    // If we successfully retrieved the UE earlier, we can continue.
                    // Otherwise this was an unknown GUTI, so we need to perform an identity procedure.
                    // We can tell based on whether there is a NAS security context in place.
                    if self.ue.nas.security_activated() {
                        // If there are any non-cleartext IEs to process, there will be an inner registration request
                        // in the NAS message container.  Switch to that, if it is present, otherwise return the original
                        // request.
                        info!(
                            self.logger,
                            "UE GUTI reregistration reusing existing security context"
                        );
                        match request.nas_message_container {
                            None => return Ok(request),
                            Some(x) => x,
                        }
                    } else {
                        self.ue.reset_nas_security();
                        let imsi = self.query_ue_identity().await?;
                        self.supi_registration(&imsi.0, &ue_security_capability)
                            .await?
                    }
                }
            }
        };

        // Decode (but do not admit) the registration request in the NAS message container.
        let value = nas_message_container.value;
        let nas = Box::new(decode_nas_5gs_message(&value).map_err(|e| {
            NasProcedureError::Abort(anyhow!(
                "NAS decode error - {e} - message bytes: {:?}",
                value
            ))
        })?);
        if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(registration_request)) =
            *nas
        {
            Ok(Box::new(registration_request))
        } else {
            Err(NasProcedureError::Abort(anyhow!(
                "Nas message container contained non-registration Nas message {:?}",
                nas
            )))
        }
    }

    async fn query_ue_identity(&mut self) -> Result<Imsi, NasProcedureError> {
        self.identity()
            .await
            .map_err(|e| NasProcedureError::Fail(FGMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED, e))
    }

    async fn supi_registration(
        &mut self,
        imsi: &str,
        ue_security_capability: &NasUeSecurityCapability,
    ) -> Result<NasMessageContainer, NasProcedureError> {
        info!(self.logger, "Registering imsi-{imsi}");
        self.authentication(imsi).await?;
        self.activate_nas_security(ue_security_capability)
            .await
            .map_err(|e| NasProcedureError::Abort(e.context("activating NAS security")))
    }

    async fn activate_nas_security(
        &mut self,
        ue_security_capabilities: &NasUeSecurityCapability,
    ) -> Result<NasMessageContainer> {
        self.ue.security_capabilities =
            crate::nas::parse::nas_ue_security_capability(ue_security_capabilities);

        // TS33.501, 6.7.2: AMF starts integrity protection before transmitting SecurityModeCommand.
        let knasint = security::derive_knasint(&self.ue.kamf);
        self.ue.nas.enable_security(knasint);
        self.security_mode().await
    }

    fn check_registration_request(
        &self,
        registration_request: &NasRegistrationRequest,
    ) -> Result<(RegistrationType, NasUeSecurityCapability), NasProcedureError> {
        let Some(ue_security_capability) = registration_request.ue_security_capability.clone()
        else {
            return Err(NasProcedureError::Fail(
                FGMM_CAUSE_IE_NONEXISTENT_OR_NOT_IMPLEMENTED,
                anyhow!("UE security capability missing from Registration Request"),
            ));
        };

        let (plmn, ret) =
            match crate::nas::parse::fgs_mobile_identity(&registration_request.fgs_mobile_identity)
                .map_err(|e| NasProcedureError::Fail(FGMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED, e))?
            {
                MobileIdentity::Guti(Guti(plmn, _amf_ids, _tmsi)) => {
                    (plmn, (RegistrationType::Guti, ue_security_capability))
                }
                MobileIdentity::Supi(plmn, imsi) => {
                    (plmn, (RegistrationType::Supi(imsi), ue_security_capability))
                }
                x => {
                    return Err(NasProcedureError::Fail(
                        FGMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED,
                        anyhow!(
                            "Expected Guti or Supi identity on a registration request, got {x:?}"
                        ),
                    ));
                }
            };

        if plmn != self.api.config().plmn {
            // This will cause authentication to fail, because the UE will form its
            // serving network name using its MCC/MNC, and we form ours using our MCC/MNC.
            return Err(NasProcedureError::Fail(
                FGMM_CAUSE_PLMN_NOT_ALLOWED,
                anyhow!(
                    "UE PLMN {:?} doesn't match ours {:?}",
                    &plmn,
                    self.api.config().plmn
                ),
            ));
        }

        Ok(ret)
    }
}

enum RegistrationType {
    Supi(Imsi),
    Guti,
}
