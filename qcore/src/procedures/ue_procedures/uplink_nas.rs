//! uplink_nas - transfer of a Nas message from UE to AMF

use super::{DeregistrationProcedure, SessionEstablishmentProcedure, UeProcedure};
use crate::HandlerApi;
use anyhow::Result;
use derive_deref::{Deref, DerefMut};
use oxirush_nas::{
    Nas5gmmMessage, Nas5gsMessage, Nas5gsmMessage, decode_nas_5gs_message,
    messages::NasUlNasTransport,
};
use slog::{Logger, warn};

#[derive(Deref, DerefMut)]
pub struct UplinkNasProcedure<'a, A: HandlerApi>(UeProcedure<'a, A>);

impl<'a, A: HandlerApi> UplinkNasProcedure<'a, A> {
    pub fn new(ue_procedure: UeProcedure<'a, A>) -> Self {
        UplinkNasProcedure(ue_procedure)
    }

    pub async fn run(mut self, mut nas_bytes: Vec<u8>) -> Result<()> {
        patch_nas_for_oai_deregistration_security_header(&mut nas_bytes, self.logger);

        match self.ue.nas.decode(&nas_bytes)? {
            Nas5gsMessage::Gmm(
                _header,
                Nas5gmmMessage::UlNasTransport(NasUlNasTransport {
                    payload_container, ..
                }),
            ) => {
                self.log_message(">> UlNasTransport");
                match decode_nas_5gs_message(&payload_container.value)? {
                    Nas5gsMessage::Gsm(
                        header,
                        Nas5gsmMessage::PduSessionEstablishmentRequest(r),
                    ) => {
                        SessionEstablishmentProcedure::new(self.0)
                            .run(header, r)
                            .await?;
                    }
                    m => {
                        warn!(
                            self.logger,
                            "Unhandled NAS message in payload container {:?}", m
                        );
                    }
                }
                // TODO: PduSessionModificationRequest(NasPduSessionModificationRequest)
                // TODO: PduSessionReleaseRequest(NasPduSessionReleaseRequest)
            }
            Nas5gsMessage::Gmm(_header, Nas5gmmMessage::DeregistrationRequestFromUe(r)) => {
                self.log_message(">> DeregistrationRequestFromUe");
                DeregistrationProcedure::new(self.0).run(r).await?;
            }

            m => {
                warn!(self.logger, "Unhandled NAS UL message {:?}", m);
            }
        }
        Ok(())
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
fn patch_nas_for_oai_deregistration_security_header(nas_bytes: &mut Vec<u8>, logger: &Logger) {
    const INNER_SECURITY_HEADER_TYPE_OFFSET: usize = 8;
    if nas_bytes.len() < (INNER_SECURITY_HEADER_TYPE_OFFSET + 1) {
        return;
    }

    if nas_bytes[0] == 0x7e && nas_bytes[1] == 0x02 {
        // Security protected MM message.
        // The inner message header starts at byte 7, and its security header type is at byte 8.
        if nas_bytes[INNER_SECURITY_HEADER_TYPE_OFFSET] != 0x00 {
            warn!(
                logger,
                "Patching NAS message to change inner message security header type from {:?} to 0",
                nas_bytes[INNER_SECURITY_HEADER_TYPE_OFFSET]
            );
            nas_bytes[INNER_SECURITY_HEADER_TYPE_OFFSET] = 0x00;
        }
    }
}
