//! initial_access - procedure in which UE makes first contact with the 5G core

use super::registration::RegistrationProcedure;
use super::{HandlerApi, UeProcedure};
use crate::expect_nas;
use anyhow::{Result, anyhow, bail};
use asn1_per::SerDes;
use derive_deref::{Deref, DerefMut};
use f1ap::{DuToCuRrcContainer, InitialUlRrcMessageTransfer, SrbId};
use oxirush_nas::messages::NasRegistrationRequest;
use oxirush_nas::{Nas5gmmMessage, Nas5gsMessage};
use rrc::{
    C1_4, C1_6, CriticalExtensions22, RrcSetupComplete, RrcSetupRequest, UlCcchMessage,
    UlCcchMessageType, UlDcchMessage, UlDcchMessageType,
};

#[derive(Deref, DerefMut)]
pub struct RrcSetupProcedure<'a, A: HandlerApi>(UeProcedure<'a, A>);

impl<'a, A: HandlerApi> RrcSetupProcedure<'a, A> {
    pub fn new(inner: UeProcedure<'a, A>) -> Self {
        RrcSetupProcedure(inner)
    }

    pub async fn run(mut self, r: InitialUlRrcMessageTransfer) -> Result<()> {
        let registration_request = self.handle_rrc_setup(r).await?;
        RegistrationProcedure::new(self.0)
            .run(registration_request)
            .await
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

        // TODO

        // If this is a integrity protected message (e.g. Registration or Service Request), we need to retrieve
        // the NAS security context by GUTI in order to verify it.

        // This means we need to call security context check() on the message after we have gone in and got the GUTI.
        // Perhaps two entry points to the registration procedure - run_with_plain_register() and run_with_protected_register().

        expect_nas!(RegistrationRequest, self.ue.nas.decode(&nas_bytes)?)
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
}
