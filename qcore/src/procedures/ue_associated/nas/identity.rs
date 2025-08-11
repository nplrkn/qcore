use super::prelude::*;
use crate::nas::*;

impl<'a, B: NasBase> NasProcedure<'a, B> {
    pub async fn identity(&mut self) -> Result<Imsi> {
        let r = crate::nas::build::identity_request();
        self.log_message("<< Nas IdentityRequest");
        let rsp = self
            .nas_request(r, nas_filter!(IdentityResponse), "Identity response")
            .await?;
        self.log_message(">> Nas IdentityResponse");
        crate::nas::parse::identity_response(&rsp)
    }
}
