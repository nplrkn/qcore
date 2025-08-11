use super::prelude::*;
use oxirush_nas::NasFGsMobileIdentity;

impl<'a, B: NasBase> NasProcedure<'a, B> {
    // TODO: commonize with service.rs
    pub async fn perform_configuration_update(
        &mut self,
        guti: Option<NasFGsMobileIdentity>,
    ) -> Result<()> {
        let command = crate::nas::build::configuration_update_command(
            Some(self.api.config().network_display_name.as_bytes()),
            guti,
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
