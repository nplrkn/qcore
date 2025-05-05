//! initial_access - procedure in which UE makes first contact with the 5G core

use super::{HandlerApi, UeProcedure};
use crate::SimCreds;
use crate::expect_nas;
use crate::nas::parse::MobileIdentity;
use anyhow::{Result, anyhow, bail};
use asn1_per::SerDes;
use derive_deref::{Deref, DerefMut};
use f1ap::{DuToCuRrcContainer, InitialUlRrcMessageTransfer, SrbId};
use oxirush_nas::messages::{
    NasAuthenticationResponse, NasRegistrationRequest, NasSecurityModeComplete,
};
use oxirush_nas::{Nas5gmmMessage, Nas5gsMessage, NasUeSecurityCapability};
use rrc::UlDcchMessage;
use rrc::{
    C1_4, C1_6, CriticalExtensions22, RrcSetupComplete, RrcSetupRequest, UlCcchMessage,
    UlCcchMessageType, UlDcchMessageType,
};
use security::Challenge;
use slog::{info, warn};

#[derive(Deref, DerefMut)]
pub struct InitialAccessProcedure<'a, A: HandlerApi>(UeProcedure<'a, A>);

impl<'a, A: HandlerApi> InitialAccessProcedure<'a, A> {
    pub fn new(inner: UeProcedure<'a, A>) -> Self {
        InitialAccessProcedure(inner)
    }

    pub async fn run(mut self, r: InitialUlRrcMessageTransfer) -> Result<()> {
        let registration_request = self.handle_rrc_setup(r).await?;
        let (imsi, ue_security_capability) =
            self.check_registration_request(registration_request)?;
        let kamf = self.authenticate_ue(&imsi).await?;
        self.activate_nas_security(ue_security_capability, &kamf)
            .await?;
        self.activate_rrc_security(&kamf).await?;
        info!(self.logger, "Registered imsi-{imsi}");
        self.complete_nas_registration().await
    }

    async fn handle_rrc_setup(
        &mut self,
        r: InitialUlRrcMessageTransfer,
    ) -> Result<NasRegistrationRequest> {
        let cell_group_config = self.check_initial_transfer(r)?;
        self.log_message(">> RrcSetupRequest");
        let rrc_setup = crate::rrc::build::setup(0, cell_group_config);
        self.log_message("<< RrcSetup");
        let response = self.rrc_request(SrbId(0), rrc_setup).await?;
        let nas_bytes = self.check_rrc_setup_complete(response)?;
        self.log_message(">> RrcSetupComplete");
        expect_nas!(RegistrationRequest, self.ue.nas.decode(&nas_bytes)?)
    }

    async fn authenticate_ue(&mut self, imsi: &String) -> Result<[u8; 32]> {
        let Some(sim) = self.lookup_sim(&imsi) else {
            bail!("Unknown IMSI {} tried to register", imsi)
        };
        let challenge = self.generate_challenge(sim);
        let r = crate::nas::build::authentication_request(&challenge.rand, &challenge.autn);
        self.log_message("<< NasAuthenticationRequest");
        let response = expect_nas!(AuthenticationResponse, self.nas_request(r).await?)?;
        self.log_message(">> NasAuthenticationResponse");
        self.check_authentication_response(response, &challenge)?;
        let kamf = security::derive_kamf(&challenge.kseaf, imsi.as_bytes());
        Ok(kamf)
    }

    async fn activate_nas_security(
        &mut self,
        ue_security_capabilities: NasUeSecurityCapability,
        kamf: &[u8; 32],
    ) -> Result<()> {
        self.configure_nas_security(kamf, &ue_security_capabilities);
        let r = crate::nas::build::security_mode_command(ue_security_capabilities);
        self.log_message("<< NasSecurityModeCommand");
        let rsp = expect_nas!(SecurityModeComplete, self.nas_request(r).await?)?;
        self.log_message(">> NasSecurityModeComplete");
        self.check_nas_security_mode_complete(rsp)
    }

    async fn activate_rrc_security(&mut self, kamf: &[u8; 32]) -> Result<()> {
        self.configure_rrc_security(kamf);
        let r = crate::rrc::build::security_mode_command(1);
        self.log_message("<< RrcSecurityModeCommand");
        let _rrc_security_mode_complete = self.rrc_request(SrbId(1), r).await;
        self.log_message(">> RRcSecurityModeComplete");
        Ok(())
    }

    async fn complete_nas_registration(&mut self) -> Result<()> {
        let r = crate::nas::build::registration_accept(
            self.config().sst,
            &self.config().plmn,
            &self.config().amf_ids,
            &self.ue.tmsi,
        );
        self.log_message("<< NasRegistrationAccept");
        let _rsp = expect_nas!(RegistrationComplete, self.nas_request(r).await?)?;
        self.log_message(">> NasRegistrationComplete");
        Ok(())
    }

    fn check_initial_transfer(&self, r: InitialUlRrcMessageTransfer) -> Result<Vec<u8>> {
        let Some(DuToCuRrcContainer(cell_group_config)) = r.du_to_cu_rrc_container else {
            bail!("Missing DuToCuRrcContainer on initial UL RRC message")
        };

        let _rrc_setup_request = self.check_rrc_setup_request(&r.rrc_container.0)?;
        Ok(cell_group_config)
    }

    fn check_rrc_setup_request(&self, message: &[u8]) -> Result<RrcSetupRequest> {
        match UlCcchMessage::from_bytes(message)? {
            UlCcchMessage {
                message: UlCcchMessageType::C1(C1_4::RrcSetupRequest(x)),
            } => Ok(x),
            m => Err(anyhow!(format!("Not yet implemented Rrc message {:?}", m))),
        }
    }

    fn check_rrc_setup_complete(&self, m: UlDcchMessage) -> Result<Vec<u8>> {
        let UlDcchMessageType::C1(C1_6::RrcSetupComplete(RrcSetupComplete {
            critical_extensions: CriticalExtensions22::RrcSetupComplete(rrc_setup_complete_ies),
            ..
        })) = m.message
        else {
            bail!("Expected Rrc Setup complete, got {:?}", m)
        };
        Ok(rrc_setup_complete_ies.dedicated_nas_message.0)
    }

    fn check_registration_request(
        &self,
        registration_request: NasRegistrationRequest,
    ) -> Result<(String, NasUeSecurityCapability)> {
        self.log_message(">> NAS Registration Request");

        let Some(ue_security_capability) = registration_request.ue_security_capability else {
            bail!("UE security capability missing from Registration Request");
        };
        let ue_security_capability = ue_security_capability.to_owned();
        let MobileIdentity { imsi, plmn } =
            crate::nas::parse::fgs_mobile_identity(&registration_request.fgs_mobile_identity)?;

        if plmn != self.config().plmn {
            // This will cause authentication to fail, because the UE will form its
            // serving network name using its MCC/MNC, and we form ours using our MCC/MNC.
            bail!(
                "UE PLMN {:?} doesn't match ours {:?}",
                &plmn,
                self.config().plmn
            )
        }

        Ok((imsi, ue_security_capability))
    }

    fn generate_challenge(&self, sim: &SimCreds) -> Challenge {
        let mut sqn = [0, 0, 0, 0, 0, 0];
        let challenge = security::generate_challenge(
            &sim.ki,
            &sim.opc,
            self.config().serving_network_name.as_bytes(),
            &mut sqn,
        );
        // TODO: handle SQN properly
        //self.increment_sim_sqn(sim);
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

    fn configure_nas_security(
        &mut self,
        kamf: &[u8; 32],
        _ue_security_capabilities: &NasUeSecurityCapability,
    ) {
        let knasint = security::derive_knasint(kamf);
        // TODO - check UE security capabilities
        // TS33.501, 6.7.2: AMF starts integrity protection before transmitting SecurityModeCommand.
        self.ue.nas.enable_security(knasint);
    }

    fn configure_rrc_security(&mut self, kamf: &[u8; 32]) {
        // Derive Kgnb, and from that kRRCInt.

        /* TS33.501, 6.8.1.1.2.3: "The NAS (uplink and downlink) COUNTs are set to start
        values, and the start value of the uplink NAS COUNT shall be used as freshness parameter in the KgNB derivation from
        the fresh KAMF (after primary authentication) when UE receives AS SMC the KgNB is derived from the current 5G NAS
        security context, i.e., the fresh KAMF is used to derive the KgNB." */
        let uplink_nas_count = 0;
        let kgnb = security::derive_kgnb(kamf, uplink_nas_count);
        let krrcint = security::derive_krrcint(&kgnb);

        // Tell the PDCP layer to add NIA2 integrity protection henceforth.
        self.ue.pdcp_tx.enable_security(krrcint);
    }
}
