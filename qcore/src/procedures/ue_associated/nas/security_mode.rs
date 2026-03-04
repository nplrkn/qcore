use super::prelude::*;
use oxirush_nas::messages::NasSecurityModeComplete;
use oxirush_nas::{NasMessageContainer, NasUeSecurityCapability};

impl<'a, B: NasBase> NasProcedure<'a, B> {
    // Returns the NAS message container from the SecurityModeComplete
    pub async fn security_mode(&mut self) -> Result<NasMessageContainer> {
        let (caps, len) = self.ue.security_capabilities;
        let security_capabilities =
            NasUeSecurityCapability::new(caps[..len].to_vec());
        let r = crate::nas::build::security_mode_command(security_capabilities, self.ue.ksi.0);
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
}
