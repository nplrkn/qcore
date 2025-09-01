use super::prelude::*;
use crate::nas::*;
use crate::{SimCreds, SubscriberAuthParams};
use oxirush_nas::messages::{NasAuthenticationFailure, NasAuthenticationResponse};
use security::{Challenge, resync_sqn};

#[derive(Debug)]
enum NasAuthOutcome {
    Kseaf([u8; 32]),
    RetryWithNewKSI,
    ResyncSqn([u8; 6]),
}

impl<'a, B: NasBase> NasProcedure<'a, B> {
    pub async fn authentication(&mut self, imsi: &str) -> Result<(), NasProcedureError> {
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
                    self.api
                        .resync_subscriber_sqn(imsi, sqn)
                        .await
                        .map_err(|e| {
                            NasProcedureError::Abort(anyhow!(e).context("Resync signature failure"))
                        })?;
                    resync_retry_done = true;
                    debug!(self.logger, "Resynchronized SQN to UE {:02x?}", sqn);
                    continue;
                }
                x => {
                    return Err(NasProcedureError::Abort(anyhow!(
                        "Successive auth failures {:?}",
                        x
                    )));
                }
            }
        }
    }

    async fn perform_nas_authentication(
        &mut self,
        imsi: &str,
    ) -> Result<NasAuthOutcome, NasProcedureError> {
        let (challenge, auth_params) = self.generate_challenge(imsi).await.map_err(|e| {
            NasProcedureError::Fail(FGMM_CAUSE_ILLEGAL_UE, e.context("generating challenge"))
        })?;
        let req = crate::nas::build::authentication_request(
            &challenge.rand,
            &challenge.autn,
            self.ue.ksi.0,
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
                NasProcedureError::Abort(anyhow!(e).context("waiting for authentication response"))
            })? {
            Ok(rsp) => {
                self.log_message(">> Nas AuthenticationResponse");
                self.check_authentication_response(&rsp, &challenge)
                    .map_err(|e| NasProcedureError::Abort(anyhow!(e)))?;
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
    ) -> Result<NasAuthOutcome, NasProcedureError> {
        self.log_message(">> Nas AuthenticationFailure");
        match auth_failure.fgmm_cause.value {
            FGMM_CAUSE_SYNCH_FAILURE => {
                debug!(self.logger, "Synch failure");
                match self.try_sqn_resynchronization(auth_failure, &auth_params.sim_creds, rand) {
                    Ok(sqn) => Ok(NasAuthOutcome::ResyncSqn(sqn)),
                    Err(e) => {
                        if self.api.config().skip_ue_auts_check {
                            warn!(
                                &self.logger,
                                "Skipping authentication failure for testability - {e}"
                            );
                            Ok(NasAuthOutcome::ResyncSqn(auth_params.sqn.0))
                        } else {
                            Err(NasProcedureError::Abort(e))
                        }
                    }
                }
            }
            FGMM_CAUSE_NGKSI_ALREADY_IN_USE => {
                debug!(self.logger, "ngKSI already in use");
                Ok(NasAuthOutcome::RetryWithNewKSI)
            }
            cause => Err(NasProcedureError::Fail(
                cause,
                anyhow!("Received authentication failure from UE cause {cause}"),
            )),
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

    async fn generate_challenge(
        &mut self,
        imsi: &str,
    ) -> Result<(Challenge, SubscriberAuthParams)> {
        let auth_params = self
            .api
            .lookup_subscriber_creds_and_inc_sqn(imsi)
            .await
            .ok_or_else(|| anyhow!("Unknown IMSI"))?;

        debug!(self.logger, "SQN for challenge: {:02x?}", auth_params.sqn);

        // Generate a new KSI for each challenge.
        self.ue.ksi.inc();

        let challenge = security::generate_challenge(
            &auth_params.sim_creds.ki,
            &auth_params.sim_creds.opc,
            self.api.config().serving_network_name.as_bytes(),
            &auth_params.sqn.0,
        );

        // println!("Challenge generated:");
        // println!("SQN:      {:02x?}", auth_params.sqn);
        // println!("K:        {:02x?}", auth_params.sim_creds.ki);
        // println!("OPC:      {:02x?}", auth_params.sim_creds.opc);
        // println!(
        //     "serving network name: {:02x?}",
        //     self.api.config().serving_network_name.as_bytes()
        // );
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

        if authentication_response_parameter.value != challenge.xres_star {
            bail!("Ue responded incorrectly to challenge")
        }

        Ok(())
    }
}
