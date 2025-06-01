use super::security_context::SecurityContext;
use anyhow::{Result, anyhow, bail};
use oxirush_nas::{
    Nas5gsMessage, decode_nas_5gs_message, encode_nas_5gs_message, messages::Nas5gsSecurityHeader,
};

#[derive(Debug, Default)]
pub struct NasContext {
    security_context: Option<SecurityContext>,
}

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

    pub fn decode(&mut self, data: &[u8]) -> Result<Box<Nas5gsMessage>> {
        let nas = Box::new(
            decode_nas_5gs_message(data)
                .map_err(|e| anyhow!("NAS decode error - {e} - message bytes: {:?}", data))?,
        );

        let security_header = if let Nas5gsMessage::SecurityProtected(ref hdr, _) = *nas {
            Some(hdr)
        } else {
            None
        };

        if let Some(security_context) = &mut self.security_context {
            security_context.admit_message(security_header, data)?;
        }

        Ok(nas)
    }

    // This is used for situations where the security context might need to be retrieved using a GUTI
    // (registration, service request).
    pub fn decode_with_security_header(
        &mut self,
        data: &[u8],
    ) -> Result<(Box<Nas5gsMessage>, Option<Nas5gsSecurityHeader>)> {
        let nas_message = Box::new(
            decode_nas_5gs_message(data)
                .map_err(|e| anyhow!("NAS decode error - {e} - message bytes: {:?}", data))?,
        );
        Ok(match *nas_message {
            Nas5gsMessage::Gmm(_, _) => (nas_message, None),
            Nas5gsMessage::SecurityProtected(hdr, bx) => (bx, Some(hdr)),
            Nas5gsMessage::Gsm(_, _) => bail!("Unexpected Nas SM message {:?} ", nas_message),
        })
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
