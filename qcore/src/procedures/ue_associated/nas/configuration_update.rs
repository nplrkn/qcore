use super::prelude::*;
use oxirush_nas::NasFGsMobileIdentity;

impl<'a, B: NasBase> NasProcedure<'a, B> {
    pub async fn perform_configuration_update(
        &mut self,
        guti: Option<NasFGsMobileIdentity>,
    ) -> Result<()> {
        let command = crate::nas::build::configuration_update_command(
            Some(self.api.config().network_display_name.as_bytes()),
            guti,
        );
        self.log_message("<< Nas ConfigurationUpdateCommand");

        // TODO: this is a hack that we don't wait for a response.  See 'ue serialization' design doc for more.
        // Instead the response will be received by the dispatch function.
        self.send_nas(command).await?;

        // let _configuration_update_complete = self
        //     .nas_request(
        //         command,
        //         nas_filter!(ConfigurationUpdateComplete),
        //         "Configuration update complete",
        //     )
        //     .await?;
        // self.log_message(">> Nas ConfigurationUpdateComplete");
        Ok(())
    }
}
