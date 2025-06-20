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
use oxirush_nas::{
    Nas5gsSecurityHeaderType, NasMessageContainer, NasUeSecurityCapability, decode_nas_5gs_message,
};
use security::{Challenge, resync_sqn};

enum RegistrationType {
    Supi(Imsi),
    Guti(AmfIds, Tmsi),
}

#[derive(Debug)]
enum NasAuthOutcome {
    Kseaf([u8; 32]),
    RetryWithNewKSI,
    ResyncSqn([u8; 6]),
}

define_ue_procedure!(RegistrationProcedure);

impl<'a, A: HandlerApi> RegistrationProcedure<'a, A> {
    pub async fn run(
        mut self,
        r: Box<NasRegistrationRequest>,
        security_header: Option<Nas5gsSecurityHeader>,
    ) -> Result<()> {
        self.log_message(">> RegistrationRequest");
        match self.handle_registration(r, security_header).await {
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
                self.accept_registration().await?;
            }
            Err(cause) => {
                if cause != ABORT_PROCEDURE {
                    self.reject_registration(cause).await?
                } else {
                    bail!("Abort registration procedure")
                }
            }
        }

        Ok(())
    }

    async fn accept_registration(&mut self) -> Result<()> {
        let tmsi = Tmsi(rand::random()); // TODO: 0xffffffff is not a valid TMSI (TS23.003, 2.4))
        debug!(self.logger, "Assigned {}", tmsi);
        debug!(
            self.logger,
            "Allowed NSSAIs: SST {} with and without SD 0",
            self.config().sst
        );
        let r = crate::nas::build::registration_accept(
            self.config().sst,
            &self.config().plmn,
            &self.config().amf_ids,
            &tmsi.0,
        );
        // TODO: should register_new_tmsi be called allocate_tmsi() and return the TMSI?
        self.api
            .register_new_tmsi(tmsi.clone(), self.ue.key, self.logger)
            .await;
        self.ue.tmsi = Some(tmsi);
        self.log_message("<< NasRegistrationAccept");
        let _rsp = self
            .nas_request(
                r,
                nas_filter!(RegistrationComplete),
                "Registration complete",
            )
            .await?;
        self.log_message(">> NasRegistrationComplete");
        Ok(())
    }

    async fn reject_registration(&mut self, cause: u8) -> Result<()> {
        let reject = crate::nas::build::registration_reject(cause);
        self.log_message("<< NAS Registration Reject");
        self.nas_indication(reject).await
    }

    async fn handle_registration(
        &mut self,
        registration_request: Box<NasRegistrationRequest>,
        security_header: Option<Nas5gsSecurityHeader>,
    ) -> Result<(), u8> {
        match self.check_registration_request(registration_request)? {
            (RegistrationType::Supi(Imsi(imsi)), ue_security_capability) => {
                self.supi_registration(&imsi, ue_security_capability).await
            }
            (RegistrationType::Guti(amf_ids, tmsi), ue_security_capability) => {
                let identity_procedure_needed = self
                    .guti_registration(&amf_ids, &tmsi, security_header)
                    .await?;

                if identity_procedure_needed {
                    self.ue.reset_nas_security();
                    let imsi = self.query_ue_identity().await?;
                    self.supi_registration(&imsi, ue_security_capability)
                        .await?;
                }

                Ok(())
            }
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
        self.log_message("<< NasIdentityRequest");
        let rsp = self
            .nas_request(r, nas_filter!(IdentityResponse), "Identity response")
            .await?;
        self.log_message(">> NasIdentityResponse");
        crate::nas::parse::identity_response(&rsp)
    }

    async fn supi_registration(
        &mut self,
        imsi: &str,
        ue_security_capability: NasUeSecurityCapability,
    ) -> Result<(), u8> {
        info!(self.logger, "SUPI registration for imsi-{imsi}");

        self.authenticate_ue(imsi).await?;

        self.activate_nas_security(ue_security_capability)
            .await
            .map_err(|e| {
                warn!(self.logger, "NAS security failure - {e}");
                ABORT_PROCEDURE
            })
    }

    async fn authenticate_ue(&mut self, imsi: &str) -> Result<(), u8> {
        let mut ksi_retry_done = false;
        let mut resync_retry_done = false;
        loop {
            match self.perform_nas_authentication(imsi).await? {
                NasAuthOutcome::Kseaf(kseaf) => {
                    self.ue.kamf = security::derive_kamf(&kseaf, imsi.as_bytes());
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
    ) -> Result<()> {
        self.configure_nas_security(&ue_security_capabilities);
        let r = crate::nas::build::security_mode_command(ue_security_capabilities, self.ue.ksi);
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
        self.log_message(">> NasSecurityModeComplete");
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
            self.ue.ksi,
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
                self.log_message(">> NasAuthenticationResponse");
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
        self.log_message(">> NasAuthenticationFailure");
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

    // Ok(true) if identity request is needed, Ok(false) if no action is needed, and
    // Err(cause code) if we should reject the registration
    async fn guti_registration(
        &mut self,
        amf_ids: &AmfIds,
        tmsi: &Tmsi,
        security_header: Option<Nas5gsSecurityHeader>,
    ) -> Result<bool, u8> {
        info!(self.logger, "GUTI registration for {tmsi}");

        // We have already checked the PLMN, so we just need to check the AMF IDs
        // at this stage.
        let guami_matches = amf_ids == &self.config().amf_ids;
        if !guami_matches {
            warn!(
                self.logger,
                "Wrong AMF IDs in GUTI - theirs {} ours {}",
                amf_ids,
                self.config().amf_ids
            );
        }

        // Deal with the case of a reregistration within a previously secured RRC channel.
        if let Some(existing_tmsi) = &self.ue.tmsi {
            info!(
                self.logger,
                "UE reregistration when security context is already in place"
            );
            if !self.ue.nas.security_activated() {
                error!(self.logger, "Logic error - no security context exists");
                return Err(FGMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED);
            }
            if existing_tmsi == tmsi && guami_matches {
                // No need to activate either NAS or RRC security - just accept
                // TODO - refresh UE registration TTL
                return Ok(false);
            } else {
                warn!(self.logger, "UE not using GUTI it was given");
                return Err(FGMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED);
            }
        }

        // This leaves us in the mainline case of a GUTI registration on a new RRC channel,
        // where the UE is trying to reinstate its previous NAS security context.
        // In this case, the UE is meant to integrity protect its message.
        let security_type = security_header
            .map(|hdr| hdr.security_header_type)
            .unwrap_or(Nas5gsSecurityHeaderType::PlainNasMessage);

        if security_type != Nas5gsSecurityHeaderType::IntegrityProtected {
            warn!(
                self.logger,
                "GUTI registration with wrong security protection {:?}", security_type
            );
            return Err(FGMM_CAUSE_SEMANTICALLY_INCORRECT_MESSAGE);
        }

        // Integrity protected GUTI registration
        if guami_matches && self.restore_existing_nas_security_context(tmsi).await {
            // Successful GUTI registration.  We can accept the registration.
            return Ok(false);
        }

        // Identity procedure needed
        debug!(
            self.logger,
            "GUTI with unknown AMF IDs or TMSI - trigger Identity Request"
        );

        Ok(true)
    }

    async fn restore_existing_nas_security_context(&mut self, tmsi: &Tmsi) -> bool {
        match self.take_nas_context(tmsi).await {
            Some(c) => {
                self.ue.nas = c;
                true
            }
            None => {
                debug!(self.logger, "Unknown TMSI");
                false
            }
        }
    }

    fn check_registration_request(
        &self,
        registration_request: Box<NasRegistrationRequest>,
    ) -> Result<(RegistrationType, NasUeSecurityCapability), u8> {
        self.log_message(">> NAS Registration Request");
        let Some(ue_security_capability) = registration_request.ue_security_capability else {
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
                MobileIdentity::Guti(plmn, amf_ids, tmsi) => (
                    plmn,
                    (
                        RegistrationType::Guti(amf_ids, tmsi),
                        ue_security_capability,
                    ),
                ),
                MobileIdentity::Supi(plmn, imsi) => {
                    (plmn, (RegistrationType::Supi(imsi), ue_security_capability))
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

        // Generate a new KSI for each challenge.  KSI is a number in the range 0-6.
        self.ue.ksi = (self.ue.ksi + 1) % 7;

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
    ) -> Result<()> {
        match *security_mode_complete {
            NasSecurityModeComplete {
                imeisv: _imeisv,
                nas_message_container: Some(NasMessageContainer { value, .. }),
                non_imeisv_pei: _non_imeisv_pei,
            } => {
                // TS24.501, 4.4.6 "After activating a 5G NAS security context resulting from a security
                // mode control procedure... the UE shall include the entire REGISTRATION REQUEST ... in the ...
                // NAS message container IE in the SECURITY MODE COMPLETE message."
                // We must decode this message without using the security context - hence the direct call to
                // decode_nas_5gs_message() instead of self.nas_decode().
                let nas =
                    Box::new(decode_nas_5gs_message(&value).map_err(|e| {
                        anyhow!("NAS decode error - {e} - message bytes: {:?}", value)
                    })?);
                if let Nas5gsMessage::Gmm(
                    _,
                    Nas5gmmMessage::RegistrationRequest(_registration_request),
                ) = *nas
                {
                    // TODO: do something with the registration request
                } else {
                    bail!(
                        "Security mode complete contained non-registration nas message {:?}",
                        nas
                    )
                };
            }
            _ => {
                warn!(
                    self.logger,
                    "Registration request missing from {:?}", security_mode_complete
                );
            }
        }

        // TODO - do something with retransmitted registration request
        Ok(())
    }

    fn configure_nas_security(&mut self, ue_security_capabilities: &NasUeSecurityCapability) {
        self.ue.security_capabilities =
            crate::nas::parse::nas_ue_security_capability(ue_security_capabilities);

        // TS33.501, 6.7.2: AMF starts integrity protection before transmitting SecurityModeCommand.
        let knasint = security::derive_knasint(&self.ue.kamf);
        self.ue.nas.enable_security(knasint);
    }
}
