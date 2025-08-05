use super::prelude::*;
use crate::nas::*;
use crate::nas_filter;
use crate::nas_request_filter;
use crate::{SimCreds, SubscriberAuthParams};
use oxirush_nas::Nas5gmmMessage;
use oxirush_nas::Nas5gsMessage;
use oxirush_nas::messages::{
    Nas5gsSecurityHeader, NasAuthenticationFailure, NasAuthenticationResponse,
    NasRegistrationRequest, NasSecurityModeComplete,
};
use oxirush_nas::{NasMessageContainer, NasUeSecurityCapability, decode_nas_5gs_message};
use security::{Challenge, resync_sqn};

enum RegistrationType {
    Supi(Imsi),
    Guti,
}

#[derive(Debug)]
enum NasAuthOutcome {
    Kseaf([u8; 32]),
    RetryWithNewKSI,
    ResyncSqn([u8; 6]),
}

// Called before the procedure starts to extract a GUTI mobile identity.
pub fn peek_mobile_identity(r: &Nas5gsMessage) -> Result<MobileIdentity> {
    match r {
        Nas5gsMessage::Gmm(_header, Nas5gmmMessage::RegistrationRequest(registration_request)) => {
            crate::nas::parse::fgs_mobile_identity(&registration_request.fgs_mobile_identity)
        }
        _ => bail!("Not a registration request"),
    }
}

define_ue_procedure!(RegistrationProcedure);

impl<'a, A: HandlerApi> RegistrationProcedure<'a, A> {
    pub async fn run(
        mut self,
        registration_request: Box<NasRegistrationRequest>,
        _security_header: Option<Nas5gsSecurityHeader>,
    ) -> Result<()> {
        self.log_message(">> Nas RegistrationRequest");

        // If this is a registration update and security is not activated then we failed to retrieve the UE context
        // based on the TMSI in the outer message.  Tell the UE it needs to do an initial registration.
        let is_registration_update = registration_request.fgs_registration_type.value
            & REGISTRATION_TYPE_MASK
            != REGISTRATION_TYPE_INITIAL;

        if is_registration_update && !self.ue.core.nas.security_activated() {
            warn!(
                self.logger,
                "Reject security protected registration update with unknown or missing TMSI in outer message"
            );
            // TS24.501 5.5.1.3.5
            // "The UE shall enter the state 5GMM-DEREGISTERED.NORMAL-SERVICE. The UE shall delete any mapped 5G NAS
            // security context or partial native 5G NAS security context."
            self.reject_registration(FGMM_CAUSE_IMPLICITLY_DEREGISTERED)
                .await?;
            return Ok(());
        }

        // The UE is authenticated based on cleartext IEs in the outer message.  Any non-cleartext IEs (such as those
        // governing session reactivation) come in a NAS message container (TS24.501, 4.4.6).
        //   -  On a initial GUTI registration that reusing existing security context, the NAS message container IE is in the Registration Request
        //   -  Otherwise, it comes in the Security Mode Complete.
        //
        let registration_request = match self.handle_registration(registration_request).await {
            Ok(r) => r,
            Err(cause) => {
                if cause != ABORT_PROCEDURE {
                    self.reject_registration(cause).await?;
                    return Ok(());
                } else {
                    bail!("Abort registration procedure")
                }
            }
        };
        // From now on, we are using the full version of the registration request complete with non-cleartext IEs, if available.

        let (current_sessions, reactivation_result) = self
            .reconcile_sessions(
                &registration_request.uplink_data_status,
                &registration_request.pdu_session_status,
            )
            .await?;

        let guti = self.allocate_tmsi().await;
        debug!(
            self.logger,
            "Allowed NSSAIs: SST {} with and without SD 0",
            self.config().sst
        );

        let accept = crate::nas::build::registration_accept(
            self.config().sst,
            guti,
            &self.config().plmn,
            &self.ue.core.tac,
            registration_request
                .uplink_data_status
                .map(|_| reactivation_result),
            current_sessions,
        );
        self.log_message("<< Nas RegistrationAccept");
        self.0 = self.0.ran_context_create(accept).await?;

        let _registration_complete = self
            .receive_nas(nas_filter!(RegistrationComplete), "Registration Complete")
            .await?;

        self.perform_configuration_update().await?;

        Ok(())
    }

    async fn reject_registration(&mut self, cause: u8) -> Result<()> {
        let reject = crate::nas::build::registration_reject(cause);
        self.log_message("<< Nas RegistrationReject");
        self.nas_indication(reject).await
    }

    // Takes as input the cleartext only registration request, and returns the full registration request
    async fn handle_registration(
        &mut self,
        registration_request: Box<NasRegistrationRequest>,
    ) -> Result<Box<NasRegistrationRequest>, u8> {
        let nas_message_container = {
            match self.check_registration_request(&registration_request)? {
                (RegistrationType::Supi(Imsi(imsi)), ue_security_capability) => {
                    self.supi_registration(&imsi, ue_security_capability)
                        .await?
                }

                (RegistrationType::Guti, ue_security_capability) => {
                    // If we successfully retrieved the UE earlier, we can continue.
                    // Otherwise this was an unknown GUTI, so we need to perform an identity procedure.
                    // We can tell based on whether there is a NAS security context in place.
                    if self.ue.core.nas.security_activated() {
                        // If there are any non-cleartext IEs to process, there will be an inner registration request
                        // in the NAS message container.  Switch to that, if it is present, otherwise return the original
                        // request.
                        match registration_request.nas_message_container {
                            None => return Ok(registration_request),
                            Some(x) => x,
                        }
                    } else {
                        self.ue.reset_nas_security();
                        let imsi = self.query_ue_identity().await?;
                        self.supi_registration(&imsi, ue_security_capability)
                            .await?
                    }
                }
            }
        };

        // Decode (but do not admit) the registration request in the NAS message container.
        let value = nas_message_container.value;
        let nas = Box::new(decode_nas_5gs_message(&value).map_err(|e| {
            warn!(
                self.logger,
                "NAS decode error - {e} - message bytes: {:?}", value
            );
            ABORT_PROCEDURE
        })?);
        if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(registration_request)) =
            *nas
        {
            Ok(Box::new(registration_request))
        } else {
            warn!(
                self.logger,
                "Nas message container contained non-registration Nas message {:?}", nas
            );
            Err(ABORT_PROCEDURE)
        }
    }

    async fn query_ue_identity(&mut self) -> Result<Imsi, u8> {
        self.query_ue_identity_inner().await.map_err(|e| {
            warn!(self.logger, "Identity procedure failed - {e}");
            FGMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED
        })
    }

    async fn query_ue_identity_inner(&mut self) -> Result<Imsi> {
        let r = crate::nas::build::identity_request();
        self.log_message("<< Nas IdentityRequest");
        let rsp = self
            .nas_request(r, nas_filter!(IdentityResponse), "Identity response")
            .await?;
        self.log_message(">> Nas IdentityResponse");
        crate::nas::parse::identity_response(&rsp)
    }

    async fn supi_registration(
        &mut self,
        imsi: &str,
        ue_security_capability: NasUeSecurityCapability,
    ) -> Result<NasMessageContainer, u8> {
        info!(self.logger, "SUPI registration for imsi-{imsi}");

        self.authenticate_ue(imsi).await?;

        self.activate_nas_security(ue_security_capability)
            .await
            .map_err(|e| {
                warn!(self.logger, "Failure during NAS security activation - {e}");
                ABORT_PROCEDURE
            })
    }

    async fn authenticate_ue(&mut self, imsi: &str) -> Result<(), u8> {
        let mut ksi_retry_done = false;
        let mut resync_retry_done = false;
        loop {
            match self.perform_nas_authentication(imsi).await? {
                NasAuthOutcome::Kseaf(kseaf) => {
                    self.ue.core.kamf = security::derive_kamf(&kseaf, imsi.as_bytes());
                    return Ok(());
                }
                NasAuthOutcome::RetryWithNewKSI if !ksi_retry_done => {
                    ksi_retry_done = true;
                    continue;
                }
                NasAuthOutcome::ResyncSqn(sqn) if !resync_retry_done => {
                    self.resync_subscriber_sqn(imsi, sqn).await.map_err(|e| {
                        warn!(self.logger, "Resync signature failure - {e}");
                        ABORT_PROCEDURE
                    })?;
                    resync_retry_done = true;
                    debug!(self.logger, "Resynchronized SQN to UE {:02x?}", sqn);
                    continue;
                }
                x => {
                    warn!(self.logger, "Successive auth failures {:?}", x);
                    return Err(ABORT_PROCEDURE);
                }
            }
        }
    }

    async fn activate_nas_security(
        &mut self,
        ue_security_capabilities: NasUeSecurityCapability,
    ) -> Result<NasMessageContainer> {
        self.configure_nas_security(&ue_security_capabilities);
        let r =
            crate::nas::build::security_mode_command(ue_security_capabilities, *self.ue.core.ksi);
        self.log_message("<< NasSecurityModeCommand");
        let Ok(security_mode_complete) = self
            .nas_request(
                r,
                nas_request_filter!(SecurityModeComplete, SecurityModeReject),
                "Security Mode response",
            )
            .await?
        else {
            bail!("Security mode command failed");
        };
        self.log_message(">> Nas SecurityModeComplete");
        self.check_nas_security_mode_complete(Box::new(security_mode_complete))
    }

    async fn perform_nas_authentication(&mut self, imsi: &str) -> Result<NasAuthOutcome, u8> {
        let (challenge, auth_params) = self.generate_challenge(imsi).await.map_err(|e| {
            warn!(self.logger, "While generating challenge - {e}");
            FGMM_CAUSE_ILLEGAL_UE
        })?;
        let req = crate::nas::build::authentication_request(
            &challenge.rand,
            &challenge.autn,
            *self.ue.core.ksi,
        );

        self.log_message("<< NasAuthenticationRequest");
        match self
            .nas_request(
                req,
                nas_request_filter!(AuthenticationResponse, AuthenticationFailure),
                "Authentication result",
            )
            .await
            .map_err(|e| {
                warn!(
                    self.logger,
                    "While waiting for authentication response - {e}"
                );
                ABORT_PROCEDURE
            })? {
            Ok(rsp) => {
                self.log_message(">> Nas AuthenticationResponse");
                self.check_authentication_response(&rsp, &challenge)
                    .map_err(|e| {
                        warn!(self.logger, "Bad authentication respnse - {e}");
                        ABORT_PROCEDURE
                    })?;
                Ok(NasAuthOutcome::Kseaf(challenge.kseaf))
            }
            Err(m) => self.authentication_failure(&m, &auth_params, &challenge.rand),
        }
    }

    fn authentication_failure(
        &mut self,
        auth_failure: &NasAuthenticationFailure,
        auth_params: &SubscriberAuthParams,
        rand: &[u8; 16],
    ) -> Result<NasAuthOutcome, u8> {
        self.log_message(">> Nas AuthenticationFailure");
        match auth_failure.fgmm_cause.value {
            FGMM_CAUSE_SYNCH_FAILURE => {
                debug!(self.logger, "Synch failure");
                match self.try_sqn_resynchronization(auth_failure, &auth_params.sim_creds, rand) {
                    Ok(sqn) => Ok(NasAuthOutcome::ResyncSqn(sqn)),
                    Err(e) => {
                        if self.config().skip_ue_authentication_check {
                            warn!(
                                &self.logger,
                                "Skipping authentication failure for testability - {e}"
                            );
                            Ok(NasAuthOutcome::ResyncSqn(auth_params.sqn.0))
                        } else {
                            Err(ABORT_PROCEDURE)
                        }
                    }
                }
            }
            FGMM_CAUSE_NGKSI_ALREADY_IN_USE => {
                debug!(self.logger, "ngKSI already in use");
                Ok(NasAuthOutcome::RetryWithNewKSI)
            }
            cause => {
                warn!(self.logger, "UE failed authentication with cause {cause}");
                Err(cause)
            }
        }
    }

    fn try_sqn_resynchronization(
        &mut self,
        m: &NasAuthenticationFailure,
        sim_creds: &SimCreds,
        rand: &[u8; 16],
    ) -> Result<[u8; 6]> {
        let Some(ref auts) = m.authentication_failure_parameter else {
            bail!("Missing authentication failure parameter on NAS authentication synch failure");
        };
        let Ok(auts) = auts.value.clone().try_into() else {
            bail!(
                "Bad authentication failure parameter length on NAS authentication synch failure",
            );
        };

        debug!(self.logger, "auts: {:x?}", auts);
        resync_sqn(&auts, &sim_creds.ki, &sim_creds.opc, rand)
            .ok_or_else(|| anyhow!("Invalid AUTS signature on NAS authentication synch failure"))
    }

    fn check_registration_request(
        &self,
        registration_request: &NasRegistrationRequest,
    ) -> Result<(RegistrationType, NasUeSecurityCapability), u8> {
        let Some(ue_security_capability) = registration_request.ue_security_capability.clone()
        else {
            warn!(
                self.logger,
                "UE security capability missing from Registration Request"
            );
            return Err(FGMM_CAUSE_IE_NONEXISTENT_OR_NOT_IMPLEMENTED);
        };

        let (plmn, ret) =
            match crate::nas::parse::fgs_mobile_identity(&registration_request.fgs_mobile_identity)
                .map_err(|e| {
                    warn!(self.logger, "{e}");
                    FGMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED
                })? {
                MobileIdentity::Guti(Guti(plmn, _amf_ids, _tmsi)) => {
                    (plmn, (RegistrationType::Guti, ue_security_capability))
                }
                MobileIdentity::Supi(plmn, imsi) => {
                    (plmn, (RegistrationType::Supi(imsi), ue_security_capability))
                }
                x => {
                    warn!(
                        self.logger,
                        "Expected Guti or Supi identity on a registration request, got {x:?}",
                    );
                    return Err(FGMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED);
                }
            };

        if plmn != self.config().plmn {
            // This will cause authentication to fail, because the UE will form its
            // serving network name using its MCC/MNC, and we form ours using our MCC/MNC.
            warn!(
                self.logger,
                "UE PLMN {:?} doesn't match ours {:?}",
                &plmn,
                self.config().plmn
            );
            return Err(FGMM_CAUSE_PLMN_NOT_ALLOWED);
        }

        Ok(ret)
    }

    async fn generate_challenge(
        &mut self,
        imsi: &str,
    ) -> Result<(Challenge, SubscriberAuthParams)> {
        let auth_params = self
            .lookup_subscriber_creds_and_inc_sqn(imsi)
            .await
            .ok_or_else(|| anyhow!("Unknown IMSI"))?;

        debug!(self.logger, "SQN for challenge: {:02x?}", auth_params.sqn);

        // Generate a new KSI for each challenge.
        self.ue.core.ksi.inc();

        let challenge = security::generate_challenge(
            &auth_params.sim_creds.ki,
            &auth_params.sim_creds.opc,
            self.config().serving_network_name.as_bytes(),
            &auth_params.sqn,
        );

        // println!("Challenge generated:");
        // println!("SQN:      {:02x?}", auth_params.sqn);
        // println!("K:        {:02x?}", auth_params.sim_creds.ki);
        // println!("OPC:      {:02x?}", auth_params.sim_creds.opc);
        // println!("rand:     {:02x?}", challenge.rand);
        // println!("autn:     {:02x?}", challenge.autn);
        // println!("xresstar: {:02x?}", challenge.xres_star);
        // println!("kseaf:    {:02x?}", challenge.kseaf);

        Ok((challenge, auth_params))
    }

    fn check_authentication_response(
        &self,
        response: &NasAuthenticationResponse,
        challenge: &Challenge,
    ) -> Result<()> {
        let Some(ref authentication_response_parameter) =
            response.authentication_response_parameter
        else {
            bail!("Missing authentication response parameter on NasAuthenticationResponse")
        };

        if self.config().skip_ue_authentication_check {
            warn!(
                self.logger,
                "Skipping authentication checks for testability reasons"
            );
        } else if authentication_response_parameter.value != challenge.xres_star {
            bail!("Ue responded incorrectly to challenge")
        }

        Ok(())
    }

    fn check_nas_security_mode_complete(
        &mut self,
        security_mode_complete: Box<NasSecurityModeComplete>,
    ) -> Result<NasMessageContainer> {
        match *security_mode_complete {
            NasSecurityModeComplete {
                imeisv: _imeisv,
                nas_message_container: Some(nas_message_container),
                non_imeisv_pei: _non_imeisv_pei,
            } => Ok(nas_message_container),
            _ => {
                bail!(
                    "Nas Message container missing from {:?}",
                    security_mode_complete
                );
            }
        }
    }

    fn configure_nas_security(&mut self, ue_security_capabilities: &NasUeSecurityCapability) {
        self.ue.core.security_capabilities =
            crate::nas::parse::nas_ue_security_capability(ue_security_capabilities);

        // TS33.501, 6.7.2: AMF starts integrity protection before transmitting SecurityModeCommand.
        let knasint = security::derive_knasint(&self.ue.core.kamf);
        self.ue.core.nas.enable_security(knasint);
    }

    // TODO: commonize with service.rs
    async fn perform_configuration_update(&mut self) -> Result<()> {
        let command = crate::nas::build::configuration_update_command(
            Some(&self.config().network_display_name),
            None,
        );
        self.log_message("<< Nas ConfigurationUpdateCommand");
        let _configuration_update_complete = self
            .nas_request(
                command,
                nas_filter!(ConfigurationUpdateComplete),
                "Configuration update complete",
            )
            .await?;
        self.log_message(">> Nas ConfigurationUpdateComplete");
        Ok(())
    }
}
