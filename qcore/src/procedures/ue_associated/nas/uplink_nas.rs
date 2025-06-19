//! uplink_nas - transfer of a Nas message from UE to AMF
use super::prelude::*;
use super::{DeregistrationProcedure, RegistrationProcedure, SessionEstablishmentProcedure};
use crate::data::DecodedNas;
use crate::procedures::ue_associated::SessionReleaseProcedure;
use crate::protocols::nas::FGMM_CAUSE_DNN_NOT_SUPPORTED_OR_NOT_SUBSCRIBED_IN_THE_SLICE;
use oxirush_nas::{
    Nas5gmmMessage, Nas5gsMessage, Nas5gsmMessage, decode_nas_5gs_message,
    messages::NasUlNasTransport,
};

define_ue_procedure!(UplinkNasProcedure);

impl<'a, A: HandlerApi> UplinkNasProcedure<'a, A> {
    pub async fn run(mut self, nas: DecodedNas) -> Result<()> {
        let (message, security_header) = nas;
        let Nas5gsMessage::Gmm(_, mm_message) = *message else {
            warn!(self.logger, "Expected MM message, got {:?}", message);
            return Ok(());
        };

        match mm_message {
            Nas5gmmMessage::RegistrationRequest(r) => {
                RegistrationProcedure::new(self.0)
                    .run(Box::new(r), security_header)
                    .await?;
            }
            Nas5gmmMessage::DeregistrationRequestFromUe(r) => {
                DeregistrationProcedure::new(self.0).run(r).await?;
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
                        SessionEstablishmentProcedure::new(self.0)
                            .run(header, r, dnn)
                            .await?;
                    }
                    // TODO: PduSessionModificationRequest(NasPduSessionModificationRequest)
                    Nas5gsMessage::Gsm(header, Nas5gsmMessage::PduSessionReleaseRequest(ref r)) => {
                        SessionReleaseProcedure::new(self.0)
                            .ue_requested(header, r)
                            .await?;
                    }
                    m => {
                        warn!(
                            self.logger,
                            "Unhandled NAS message in payload container {:?}", m
                        );
                    }
                }
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
            self.nas_indication(status).await?;
            Ok(false)
        } else {
            Ok(true)
        }
    }
}
