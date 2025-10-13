//! uplink_nas - transfer of a Nas message from UE to AMF
use super::prelude::*;
use crate::protocols::nas::{
    FGMM_CAUSE_DNN_NOT_SUPPORTED_OR_NOT_SUBSCRIBED_IN_THE_SLICE, Guti, MobileIdentity,
};
use nas::DecodedNas;
use oxirush_nas::{
    Nas5gmmMessage, Nas5gsMessage, Nas5gsmMessage, decode_nas_5gs_message,
    messages::NasUlNasTransport,
};

impl<'a, B: NasBase> NasProcedure<'a, B> {
    pub async fn uplink_nas(&mut self, nas: Vec<u8>) -> Result<()> {
        let nas = self.nas_decode(&nas)?;
        self.dispatch(nas).await.context("uplink nas")
    }

    // Called for the first NAS message from the UE on a new RAN context.
    pub async fn initial_nas(&mut self, nas_bytes: Vec<u8>, stmsi: Option<&[u8]>) -> Result<()> {
        // If UE supplied a S-TMSI on its Rrc message, retrieve the UE context now, so the NAS context
        // is in place for the NAS decode.
        if let Some(stmsi) = stmsi {
            match self.retrieve_ue(None, &stmsi[0..2], &stmsi[2..6]).await {
                Ok(false) => debug!(self.logger, "Using TMSI from outer message for NAS admit"),
                Ok(true) => debug!(self.logger, "Unknown TMSI in outer message"),
                Err(e) => warn!(self.logger, "Error retrieving UE {e}"),
            }
        }

        // TODO - protect against retrieval of UE context by a TMSI that does not actually pass its integrity check
        // TODO - cross check inner TMSI against outer TMSI

        let nas = self.nas_decode(&nas_bytes)?;

        // If the NAS message is security protected but no TMSI was supplied, then in the normal case,
        // the UE is not registered in the tracking area.  See 38.331, 5.3.3.3:
        //   NOTE 1: Upper layers provide the 5G-S-TMSI if the UE is registered in the TA of the current cell.
        //
        // Therefore this is typically a GUTI initial registration.  We need to get hold of the security context now,
        // because this is the last point at which we have the raw message bytes to perform integrity checking.
        // We peek inside the message to get out the GUTI, retrieve the security context, and then admit the message.
        if let (nas, Some(security_header)) = &nas {
            // The test of stmsi.is_none() is to avoid pointlessly peeking inside the message if we already failed
            // the TMSI lookup on the TMSI in the outer message in the arm above.
            if stmsi.is_none() && !self.ue.nas.security_activated() {
                match peek_mobile_identity(nas) {
                    Ok(MobileIdentity::Guti(Guti(_plmn, amf_ids, tmsi))) => {
                        match self
                            .retrieve_ue(Some(amf_ids.0[0]), &amf_ids.0[1..3], &tmsi.0)
                            .await
                        {
                            Ok(false) => {
                                debug!(
                                    self.logger,
                                    "Using TMSI from message peek for initial NAS admit"
                                );
                                self.ue
                                    .nas
                                    .admit_message(Some(security_header), &nas_bytes)?;
                            }
                            Ok(true) => {
                                // TODO: should we stop processing at this point?
                                // For a register, we can carry on and do an identity request - is that the right step
                                // in other cases (e.g. service request) too?
                                debug!(self.logger, "Unknown TMSI in initial NAS message")
                            }
                            Err(e) => warn!(self.logger, "Error retrieving UE {e}"),
                        }
                    }
                    Ok(x) => warn!(
                        self.logger,
                        "Expected GUTI mobile identity on initial NAS message, got {:?}", x
                    ),
                    Err(e) => warn!(self.logger, "{e}"),
                }
            }
        }
        self.dispatch(nas).await
    }

    pub async fn dispatch(&mut self, nas: DecodedNas) -> Result<()> {
        let (message, security_header) = nas;
        let Nas5gsMessage::Gmm(_, mm_message) = *message else {
            warn!(self.logger, "Expected MM message, got {:?}", message);
            return Ok(());
        };

        match mm_message {
            Nas5gmmMessage::RegistrationRequest(r) => {
                self.registration(Box::new(r), security_header)
                    .await
                    .context("registration")?;
            }
            Nas5gmmMessage::ServiceRequest(r) => {
                self.service(Box::new(r)).await.context("service request")?;
            }
            Nas5gmmMessage::DeregistrationRequestFromUe(r) => {
                self.deregistration_from_ue(r)
                    .await
                    .context("deregistration from UE")?;
            }
            Nas5gmmMessage::UlNasTransport(NasUlNasTransport {
                payload_container,
                dnn,
                ..
            }) => {
                self.log_message(">> Nas UlNasTransport");
                let dnn = if let Some(dnn) = dnn {
                    let dnn = crate::nas::parse::dnn(dnn)?;
                    if !self.check_dnn(&dnn).await? {
                        return Ok(());
                    }
                    Some(dnn)
                } else {
                    None
                };

                let nas = Box::new(decode_nas_5gs_message(&payload_container.value)?);
                match *nas {
                    Nas5gsMessage::Gsm(
                        header,
                        Nas5gsmMessage::PduSessionEstablishmentRequest(ref r),
                    ) => {
                        self.session_establishment(header, r, dnn)
                            .await
                            .context("session establishment")?;
                    }
                    // TODO: PduSessionModificationRequest(NasPduSessionModificationRequest)
                    Nas5gsMessage::Gsm(header, Nas5gsmMessage::PduSessionReleaseRequest(ref r)) => {
                        self.ue_requested_session_release(header, r)
                            .await
                            .context("session release")?;
                    }
                    m => {
                        warn!(
                            self.logger,
                            "Unhandled NAS message in payload container {:?}", m
                        );
                    }
                }
            }
            Nas5gmmMessage::ConfigurationUpdateComplete(_) => {
                // Normally we shouldn't handle a response here, but see 'ue serialization' design doc,
                // this is a short term hack to allow parallel processing of ConfigurationUpdate and
                // SessionEstablishment.
                self.log_message(">> Nas ConfigurationUpdateComplete");
            }

            m => {
                warn!(self.logger, "Unimplemented NAS UL message {:?}", m);
            }
        }
        Ok(())
    }

    // Return true if the DNN is ok, otherwise send a NAS 5GMM Status and return false
    // A typical scenario is where the UE requests the 'ims' DNN and then falls back to the 'internet' DNN.
    // Right now we give the UE what it asks for, so long as it is not 'ims'.
    async fn check_dnn(&mut self, dnn: &[u8]) -> Result<bool> {
        if dnn == b"ims" {
            warn!(
                self.logger,
                "UE asked for 'ims' DNN - sending 5GMM Status and ignoring session establishment request"
            );
            let status = crate::nas::build::fgmm_status(
                FGMM_CAUSE_DNN_NOT_SUPPORTED_OR_NOT_SUBSCRIBED_IN_THE_SLICE,
            );
            self.send_nas(status).await?;
            Ok(false)
        } else {
            Ok(true)
        }
    }
}

// Called before the procedure starts to extract a GUTI mobile identity.
pub fn peek_mobile_identity(r: &Nas5gsMessage) -> Result<MobileIdentity> {
    match r {
        Nas5gsMessage::Gmm(_header, Nas5gmmMessage::RegistrationRequest(registration_request)) => {
            crate::nas::parse::fgs_mobile_identity(&registration_request.fgs_mobile_identity)
        }
        Nas5gsMessage::Gmm(
            _header,
            Nas5gmmMessage::DeregistrationRequestFromUe(deregistration_request),
        ) => crate::nas::parse::fgs_mobile_identity(&deregistration_request.fgs_mobile_identity),

        _ => bail!("Identity peek not implemented for message type"),
    }
}
