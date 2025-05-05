use super::security_context::SecurityContext;
use anyhow::{Result, anyhow};
use oxirush_nas::{Nas5gsMessage, decode_nas_5gs_message, encode_nas_5gs_message};

#[derive(Debug, Default)]
pub struct NasContext {
    security_context: Option<SecurityContext>,
}

impl NasContext {
    pub fn decode(&mut self, data: &[u8]) -> Result<Nas5gsMessage> {
        let nas = decode_nas_5gs_message(data)
            .map_err(|e| anyhow!("NAS decode error - {e} - message bytes: {:?}", data))?;
        match nas {
            Nas5gsMessage::SecurityProtected(_security_header, body) => {
                // TODO: Check the security header
                Ok(*body)
            }
            nas => {
                // TODO: Check if this is meant to be secured and reject if not
                Ok(nas)
            }
        }
    }
    pub fn enable_security(&mut self, knasint: [u8; 16]) {
        self.security_context = Some(SecurityContext::new(knasint));
    }

    pub fn encode(&mut self, nas: Nas5gsMessage) -> Result<Vec<u8>> {
        let nas = if let Some(security_context) = &mut self.security_context {
            security_context.encode_with_integrity(nas)?
        } else {
            encode_nas_5gs_message(&nas)?
        };
        Ok(nas)
    }
}
