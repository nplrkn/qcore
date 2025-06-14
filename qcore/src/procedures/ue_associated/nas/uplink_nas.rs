//! uplink_nas - transfer of a Nas message from UE to AMF
use super::prelude::*;
use super::{DeregistrationProcedure, RegistrationProcedure, SessionEstablishmentProcedure};
use crate::protocols::nas::FGMM_CAUSE_DNN_NOT_SUPPORTED_OR_NOT_SUBSCRIBED_IN_THE_SLICE;
use oxirush_nas::{
    Nas5gmmMessage, Nas5gsMessage, Nas5gsmMessage, decode_nas_5gs_message,
    messages::NasUlNasTransport,
};

define_ue_procedure!(UplinkNasProcedure);

impl<'a, A: HandlerApi> UplinkNasProcedure<'a, A> {
    pub async fn run(mut self, nas_bytes: &mut [u8]) -> Result<()> {
        self.patch_nas_for_oai_deregistration_security_header(nas_bytes);

        let (message, security_header) = self.nas_decode_with_security_header(nas_bytes)?;
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
                    // TODO: PduSessionReleaseRequest(NasPduSessionReleaseRequest)
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

    // OAI UE sends a security protected deregistration request where the inner
    // message has security header type 0x0100 - INTEGRITY_PROTECTED_AND_CIPHERED_WITH_NEW_SECU_CTX -
    // but no security header.
    // Wireshark parses this OK, but our Oxirush NAS decoder doesn't.
    // Current hypothesis is that OAI is getting it wrong, and Wireshark is tolerating it because
    // it calculates inner messsage offsets assuming that it cannot have a security header.
    //
    // For now, we have this hack to patch the message to pacify the NAS decoder.
    fn patch_nas_for_oai_deregistration_security_header(&self, nas_bytes: &mut [u8]) {
        const INNER_SECURITY_HEADER_TYPE_OFFSET: usize = 8;
        if nas_bytes.len() < (INNER_SECURITY_HEADER_TYPE_OFFSET + 1) {
            return;
        }

        if nas_bytes[0] == 0x7e && nas_bytes[1] == 0x02 {
            // Security protected MM message.
            // The inner message header starts at byte 7, and its security header type is at byte 8.
            if nas_bytes[INNER_SECURITY_HEADER_TYPE_OFFSET] != 0x00 {
                warn!(
                    self.logger,
                    "Patching NAS message to change inner message security header type from {:?} to 0",
                    nas_bytes[INNER_SECURITY_HEADER_TYPE_OFFSET]
                );
                nas_bytes[INNER_SECURITY_HEADER_TYPE_OFFSET] = 0x00;
            }
        }
    }
}
