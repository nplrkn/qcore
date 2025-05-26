use super::UeProcedure;
use crate::HandlerApi;
use crate::SimCreds;
use crate::SubscriberAuthParams;
use crate::expect_nas;
use crate::nas::{
    FGMM_CAUSE_ILLEGAL_UE, FGMM_CAUSE_IMPLICITLY_DEREGISTERED, FGMM_CAUSE_SYNCH_FAILURE,
    FGMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED, Imsi, MobileIdentity, Tmsi,
};
use anyhow::{Result, anyhow, bail};
use derive_deref::{Deref, DerefMut};
use f1ap::SrbId;
use oxirush_nas::messages::{
    NasAuthenticationFailure, NasAuthenticationResponse, NasRegistrationRequest,
    NasSecurityModeComplete,
};
use oxirush_nas::{Nas5gmmMessage, Nas5gsMessage, NasUeSecurityCapability};
use security::{Challenge, resync_sqn};
use slog::debug;
use slog::{info, warn};

enum RegistrationType {
    Supi(Imsi, NasUeSecurityCapability),
    Guti(Tmsi),
}

enum NasAuthOutcome {
    Kseaf([u8; 32]),
    ResyncSqn([u8; 6]),
}

#[derive(Deref, DerefMut)]
pub struct RegistrationProcedure<'a, A: HandlerApi>(UeProcedure<'a, A>);

impl<'a, A: HandlerApi> RegistrationProcedure<'a, A> {
    pub fn new(inner: UeProcedure<'a, A>) -> Self {
        RegistrationProcedure(inner)
    }

    pub async fn run(mut self, r: NasRegistrationRequest) -> Result<()> {
        self.log_message(">> RegistrationRequest");
        match self.handle_registration(r).await {
            Ok(_) => self.accept_registration().await,
            Err(cause) => self.reject_registration(cause).await,
        }
    }

    async fn accept_registration(&mut self) -> Result<()> {
        // TODO: generate TMSI here
        let r = crate::nas::build::registration_accept(
            self.config().sst,
            &self.config().plmn, // TODO: provide self.guti() -> Guti
            &self.config().amf_ids,
            &self.ue.tmsi,
        );
        self.log_message("<< NasRegistrationAccept");
        let _rsp = expect_nas!(RegistrationComplete, self.nas_request(r).await?)?;
        self.log_message(">> NasRegistrationComplete");
        Ok(())
    }

    async fn reject_registration(&mut self, cause: u8) -> Result<()> {
        let reject = crate::nas::build::registration_reject(cause);
        self.nas_indication(reject).await
    }

    async fn handle_registration(
        &mut self,
        registration_request: NasRegistrationRequest,
    ) -> Result<(), u8> {
        match self.check_registration_request(registration_request)? {
            RegistrationType::Supi(Imsi(imsi), ue_security_capability) => {
                info!(self.logger, "Register imsi-{imsi}");
                self.authenticate_ue(&imsi)
                    .await
                    .map_err(|_e| FGMM_CAUSE_ILLEGAL_UE)?;
                self.activate_nas_security(ue_security_capability)
                    .await
                    .map_err(|_e| 0)?;
            }

            RegistrationType::Guti(tmsi) => {
                self.restore_existing_nas_security_context(&tmsi)
                    .await
                    .map_err(|_e| FGMM_CAUSE_IMPLICITLY_DEREGISTERED)?;
                {
                    info!(self.logger, "Register TMSI {:02x?}", tmsi.0);
                }
            }
        };
        let uplink_nas_count = 0; // TODO - put in UE context
        self.activate_rrc_security(uplink_nas_count)
            .await
            .map_err(|_| 0)
    }

    async fn authenticate_ue(&mut self, imsi: &String) -> Result<()> {
        for _ in 0..2 {
            match self.perform_nas_auth(imsi).await? {
                NasAuthOutcome::Kseaf(kseaf) => {
                    self.ue.kamf = security::derive_kamf(&kseaf, imsi.as_bytes());
                    return Ok(());
                }
                NasAuthOutcome::ResyncSqn(sqn) => {
                    debug!(self.logger, "Resynchronize SQN to {:02x?}", sqn);
                    self.resync_subscriber_sqn(&imsi, sqn).await?;
                }
            }
            // Getting here means we have resynchronized the SQN
        }
        bail!("Successive synch failure during NAS authentication")
    }

    // Returns Ok(kseaf) on success, Ok(None) on synch failure, and Err for anything else.
    async fn perform_nas_auth(&mut self, imsi: &String) -> Result<NasAuthOutcome> {
        let auth_params = self
            .lookup_subscriber_creds_and_inc_sqn(&imsi)
            .await
            .ok_or_else(|| anyhow!("Unknown IMSI"))?;

        debug!(self.logger, "SQN for challenge {:02x?}", auth_params.sqn);
        let challenge = self.generate_challenge(&auth_params);

        // println!("Challenge generated:");
        // println!("SQN:      {:02x?}", auth_params.sqn);
        // println!("K:        {:02x?}", sim.ki);
        // println!("OPC:      {:02x?}", sim.opc);
        // println!("rand:     {:02x?}", challenge.rand);
        // println!("autn:     {:02x?}", challenge.autn);
        // println!("xresstar: {:02x?}", challenge.xres_star);
        // println!("kseaf:    {:02x?}", challenge.kseaf);
        // println!("ak:       {:02x?}", challenge.ak);

        let r = crate::nas::build::authentication_request(&challenge.rand, &challenge.autn);
        self.log_message("<< NasAuthenticationRequest");

        let response = self.nas_request(r).await?;
        match response {
            Nas5gsMessage::Gmm(_header, Nas5gmmMessage::AuthenticationResponse(response)) => {
                self.log_message(">> NasAuthenticationResponse");
                self.check_authentication_response(response, &challenge)?;
                Ok(NasAuthOutcome::Kseaf(challenge.kseaf))
            }
            Nas5gsMessage::Gmm(_header, Nas5gmmMessage::AuthenticationFailure(m)) => {
                let sqn = self
                    .process_nas_authentication_failure(m, &auth_params.sim_creds, &challenge.rand)
                    .or_else(|e| {
                        if self.config().skip_ue_authentication_check {
                            warn!(
                                self.logger,
                                "Ignoring AUTS MAC-S signature failure for testability reasons"
                            );
                            Ok(auth_params.sqn)
                        } else {
                            Err(e)
                        }
                    })?;

                // None indicates to the caller that we resync'd the SQN.
                Ok(NasAuthOutcome::ResyncSqn(sqn))
            }
            m => bail!(
                "Expected NasAuthenticationResponse/NasAuthenticationFailure but got {:?}",
                m
            ),
        }
    }

    fn process_nas_authentication_failure(
        &mut self,
        m: NasAuthenticationFailure,
        sim_creds: &SimCreds,
        rand: &[u8; 16],
    ) -> Result<[u8; 6]> {
        let NasAuthenticationFailure {
            fgmm_cause,
            authentication_failure_parameter,
        } = m;
        self.log_message(">> NasAuthenticationFailure");

        if fgmm_cause.value != FGMM_CAUSE_SYNCH_FAILURE {
            bail!("UE failed authentication with cause {:?}", fgmm_cause);
        }
        let Some(auts) = authentication_failure_parameter else {
            bail!("Missing authentication failure parameter on NAS authentication synch failure");
        };
        let Ok(auts) = auts.value.try_into() else {
            bail!(
                "Bad authentication failure parameter length on NAS authentication synch failure",
            );
        };
        // println!("AUTS calculation inputs:");
        // println!("auts:     {:x?}", auts);

        resync_sqn(&auts, &sim_creds.ki, &sim_creds.opc, rand)
            .map_err(|_| anyhow!("Invalid AUTS signature on NAS authentication synch failure"))
    }

    async fn activate_nas_security(
        &mut self,
        ue_security_capabilities: NasUeSecurityCapability,
    ) -> Result<()> {
        self.configure_nas_security(&ue_security_capabilities);
        let r = crate::nas::build::security_mode_command(ue_security_capabilities);
        self.log_message("<< NasSecurityModeCommand");
        let rsp = expect_nas!(SecurityModeComplete, self.nas_request(r).await?)?;
        self.log_message(">> NasSecurityModeComplete");
        self.check_nas_security_mode_complete(rsp)
    }

    async fn restore_existing_nas_security_context(&mut self, tmsi: &Tmsi) -> Result<()> {
        match self.lookup_nas_context(tmsi).await {
            Some(c) => {
                self.ue.nas = c;
                Ok(())
            }
            None => bail!("Unknown TMSI"),
        }
    }

    async fn activate_rrc_security(&mut self, uplink_nas_count: u32) -> Result<()> {
        self.configure_rrc_security(uplink_nas_count);
        let r = crate::rrc::build::security_mode_command(1);
        self.log_message("<< RrcSecurityModeCommand");
        let _rrc_security_mode_complete = self.rrc_request(SrbId(1), r).await;
        self.log_message(">> RRcSecurityModeComplete");
        Ok(())
    }

    fn check_registration_request(
        &self,
        registration_request: NasRegistrationRequest,
    ) -> Result<RegistrationType, u8> {
        self.log_message(">> NAS Registration Request");

        let (plmn, registration_type) =
            match crate::nas::parse::fgs_mobile_identity(&registration_request.fgs_mobile_identity)
                .map_err(|e| {
                    warn!(self.logger, "{e}");
                    0
                })? {
                MobileIdentity::Guti(plmn, amf_ids, tmsi) => {
                    if amf_ids.0 != self.config().amf_ids {
                        warn!(
                            self.logger,
                            "Wrong AMF IDs in GUTI - theirs {:02x?} ours {:02x?}",
                            amf_ids.0,
                            self.config().amf_ids
                        );
                        return Err(FGMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED);
                    }
                    (plmn.0, RegistrationType::Guti(tmsi))
                }
                MobileIdentity::Supi(plmn, imsi) => {
                    let Some(ue_security_capability) = registration_request.ue_security_capability
                    else {
                        warn!(
                            self.logger,
                            "UE security capability missing from Registration Request"
                        );
                        return Err(0);
                    };
                    let ue_security_capability = ue_security_capability.to_owned();
                    (plmn.0, RegistrationType::Supi(imsi, ue_security_capability))
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
            return Err(0);
        }

        Ok(registration_type)
    }

    fn generate_challenge(&self, auth_params: &SubscriberAuthParams) -> Challenge {
        let challenge = security::generate_challenge(
            &auth_params.sim_creds.ki,
            &auth_params.sim_creds.opc,
            self.config().serving_network_name.as_bytes(),
            &auth_params.sqn,
        );
        challenge
    }

    fn check_authentication_response(
        &self,
        response: NasAuthenticationResponse,
        challenge: &Challenge,
    ) -> Result<()> {
        // On receipt of authentication response.
        // "SEAF shall then compute HRES* from RES* according to Annex A.5, and the SEAF shall compare HRES* and HXRES*."
        // However, we don't need the H(X)RES in the monolithic architecture.  This is a feature that conceals the XRES
        // from the visited network (so the visited network can't spoof UEs).
        let Some(authentication_response_parameter) = response.authentication_response_parameter
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
        security_mode_complete: NasSecurityModeComplete,
    ) -> Result<()> {
        match security_mode_complete {
            NasSecurityModeComplete {
                imeisv: _imeisv,
                nas_message_container: Some(container),
                non_imeisv_pei: _non_imeisv_pei,
            } => {
                // TS24.501, 4.4.6 "After activating a 5G NAS security context resulting from a security
                // mode control procedure... the UE shall include the entire REGISTRATION REQUEST ... in the ...
                // NAS message container IE in the SECURITY MODE COMPLETE message."
                let nas = self.ue.nas.decode(&container.value)?;
                let _registration_request = expect_nas!(RegistrationRequest, nas)?;
            }
            m => {
                warn!(self.logger, "Registration request missing from {:?}", m)
            }
        }

        // TODO - do something with retransmitted registration request
        Ok(())
    }

    fn configure_nas_security(&mut self, _ue_security_capabilities: &NasUeSecurityCapability) {
        let knasint = security::derive_knasint(&self.ue.kamf);
        // TODO - check UE security capabilities
        // TS33.501, 6.7.2: AMF starts integrity protection before transmitting SecurityModeCommand.
        self.ue.nas.enable_security(knasint);
    }

    fn configure_rrc_security(&mut self, uplink_nas_count: u32) {
        // Derive Kgnb, and from that kRRCInt.

        /* TS33.501, 6.8.1.1.2.3: "The NAS (uplink and downlink) COUNTs are set to start
        values, and the start value of the uplink NAS COUNT shall be used as freshness parameter in the KgNB derivation from
        the fresh KAMF (after primary authentication) when UE receives AS SMC the KgNB is derived from the current 5G NAS
        security context, i.e., the fresh KAMF is used to derive the KgNB." */

        /* 6.8.1.1.2.2: When the UE receives the AS SMC without having received a NAS Security Mode Command after the Registration Request
        with "PDU session(s) to be re-activated", it shall use the uplink NAS COUNT of the Registration Request message that
        triggered the AS SMC to be sent as freshness parameter in the derivation of the initial KgNB/KeNB.           */
        let kgnb = security::derive_kgnb(&self.ue.kamf, uplink_nas_count);
        let krrcint = security::derive_krrcint(&kgnb);

        // Tell the PDCP layer to add NIA2 integrity protection henceforth.
        self.ue.pdcp_tx.enable_security(krrcint);
    }
}
