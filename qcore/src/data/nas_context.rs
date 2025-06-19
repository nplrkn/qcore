use super::security_context::SecurityContext;
use anyhow::{Result, anyhow, bail};
use oxirush_nas::{
    Nas5gsMessage, decode_nas_5gs_message, encode_nas_5gs_message, messages::Nas5gsSecurityHeader,
};
use slog::Logger;

#[derive(Debug, Default)]
pub struct NasContext {
    security_context: Option<SecurityContext>,
}

pub type DecodedNas = (Box<Nas5gsMessage>, Option<Nas5gsSecurityHeader>);

impl NasContext {
    pub fn security_activated(&self) -> bool {
        self.security_context.is_some()
    }

    pub fn ul_nas_count(&self) -> u32 {
        self.security_context
            .as_ref()
            .map(|x| x.ul_count)
            .unwrap_or_default()
    }

    pub fn decode(&mut self, data: &[u8], logger: &Logger) -> Result<DecodedNas> {
        let nas_message = Box::new(
            decode_nas_5gs_message(data)
                .map_err(|e| anyhow!("NAS decode error - {e} - message bytes: {:?}", data))?,
        );
        let (nas, security_header) = match *nas_message {
            Nas5gsMessage::Gmm(_, _) => (nas_message, None),
            Nas5gsMessage::SecurityProtected(hdr, bx) => (bx, Some(hdr)),
            Nas5gsMessage::Gsm(_, _) => bail!("Unexpected Nas SM message {:?} ", nas_message),
        };

        if let Some(security_context) = &mut self.security_context {
            security_context.admit_message(security_header.as_ref(), data, logger)?;
        }

        Ok((nas, security_header))
    }

    pub fn enable_security(&mut self, knasint: [u8; 16]) {
        self.security_context = Some(SecurityContext::new(knasint));
    }

    pub fn encode(&mut self, nas: Box<Nas5gsMessage>) -> Result<Vec<u8>> {
        let nas = if let Some(security_context) = &mut self.security_context {
            security_context.encode_with_integrity(nas)?
        } else {
            encode_nas_5gs_message(&nas)?
        };
        Ok(nas)
    }
}
