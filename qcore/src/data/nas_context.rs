use super::security_context::SecurityContext;
use anyhow::{Result, anyhow};
use oxirush_nas::{Nas5gsMessage, decode_nas_5gs_message, encode_nas_5gs_message};

#[derive(Debug, Default)]
pub struct NasContext {
    security_context: Option<SecurityContext>,
}

impl NasContext {
    pub fn ul_nas_count(&self) -> u32 {
        self.security_context
            .as_ref()
            .map(|x| x.ul_count)
            .unwrap_or_default()
    }

    pub fn decode(&mut self, data: &[u8]) -> Result<Nas5gsMessage> {
        if let Some(security_context) = &mut self.security_context {
            security_context.decode_and_check(data)
        } else {
            decode_nas_5gs_message(data)
                .map_err(|e| anyhow!("NAS decode error - {e} - message bytes: {:?}", data))
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
