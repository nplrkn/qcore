mod authentication;
mod configuration_update;
mod deregistration;
mod identity;
mod nas_base;
mod registration;
mod security_mode;
mod service;
mod session_establishment;
mod session_release;
pub mod uplink_nas;

pub use nas_base::NasBase;

use crate::{
    data::UeContext5GC,
    protocols::nas::{ABORT_PROCEDURE, FGMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED, Tmsi, parse},
};
use anyhow::{Result, ensure};
use nas::DecodedNas;
use oxirush_nas::{
    Nas5gmmMessage, Nas5gsMessage, Nas5gsmMessage, NasFGsMobileIdentity, NasPduSessionStatus,
    NasUplinkDataStatus, decode_nas_5gs_message, messages::Nas5gsSecurityHeader,
};
use slog::{Logger, debug, warn};

pub struct NasProcedure<'a, B: NasBase> {
    pub ue: &'a mut UeContext5GC,
    pub logger: Logger,
    pub api: B,
}

impl<'a, B: NasBase> NasProcedure<'a, B> {
    async fn send_nas(&mut self, nas: Box<Nas5gsMessage>) -> Result<()> {
        let nas_bytes = self.ue.nas.encode(nas)?;
        self.api.send_nas(nas_bytes).await
    }

    async fn allocate_guti(&mut self) -> NasFGsMobileIdentity {
        let tmsi = self.api.register_new_tmsi().await;
        let guti = crate::protocols::nas::build::nas_mobile_identity_guti(
            &self.api.config().plmn,
            &self.api.config().amf_ids,
            &tmsi,
        );
        self.ue.tmsi = Some(Tmsi(tmsi));

        guti
    }

    async fn receive_nas_response<T>(
        &mut self,
        filter: fn(DecodedNas) -> Result<T, DecodedNas>,
        expected: &str,
    ) -> Result<T> {
        loop {
            let nas = self.api.receive_nas().await?;
            let nas = self.ue.nas.decode(&nas)?;
            match filter(nas) {
                Ok(extracted) => return Ok(extracted),
                Err(nas) => self.api.unexpected_nas_pdu(nas, expected)?,
            }
        }
    }

    async fn receive_nas_sm<T>(
        &mut self,
        filter: fn(Nas5gsmMessage) -> Option<T>,
        expected: &str,
    ) -> Result<T> {
        loop {
            let nas = self.api.receive_nas().await?;
            let nas = self.ue.nas.decode(&nas)?;
            if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::UlNasTransport(ref ul_nas_transport)) =
                *nas.0
            {
                let inner = Box::new(decode_nas_5gs_message(
                    &ul_nas_transport.payload_container.value,
                )?);
                if let Nas5gsMessage::Gsm(_, nas_sm) = *inner {
                    if let Some(extracted) = filter(nas_sm) {
                        return Ok(extracted);
                    }
                }
            }

            // This is not the message we are looking for.  Park the top level NAS PDU.  This is rather inefficient
            // since it means we will decode the inner message again later.
            self.api.unexpected_nas_pdu(nas, expected)?;
        }
    }

    async fn nas_request<T>(
        &mut self,
        nas: Box<Nas5gsMessage>,
        filter: fn(DecodedNas) -> Result<T, DecodedNas>,
        expected: &str,
    ) -> Result<T> {
        self.send_nas(nas).await?;
        self.receive_nas_response(filter, expected).await
    }

    async fn ran_context_create(&mut self, nas: Box<Nas5gsMessage>) -> Result<()> {
        let nas = self.ue.nas.encode(nas)?;
        debug!(
            self.logger,
            "UL NAS COUNT for kGNB derivation {}",
            self.ue.nas.ul_nas_count()
        );
        let kgnb = security::derive_kgnb(&self.ue.kamf, self.ue.nas.ul_nas_count());
        self.api
            .ran_context_create(
                &kgnb,
                nas,
                &mut self.ue.pdu_sessions,
                &self.ue.security_capabilities,
            )
            .await
    }

    pub async fn retrieve_ue(
        &mut self,
        amf_region: Option<u8>,
        amf_set_and_pointer: &[u8],
        tmsi: &[u8],
    ) -> Result<bool, u8> {
        let guami_matches = amf_set_and_pointer == &self.api.config().amf_ids.0[1..3]
            && amf_region
                .map(|x| x == self.api.config().amf_ids.0[0])
                .unwrap_or(true);
        if !guami_matches {
            warn!(
                self.logger,
                "Wrong AMF IDs in GUTI/STMSI - theirs {:?}, {:?} ours {}",
                amf_region,
                amf_set_and_pointer,
                self.api.config().amf_ids
            );
        }

        // Has the UE already obtained a TMSI on its current radio channel?
        if let Some(existing_tmsi) = &self.ue.tmsi {
            if existing_tmsi.0 == tmsi && guami_matches {
                return Ok(false);
            } else {
                warn!(self.logger, "UE not using GUTI it was given");
                return Err(FGMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED);
            }
        }

        // If we know about this GUTI, retrieve the core context and attach it to this UE.
        if guami_matches {
            match self.api.take_core_context(tmsi).await {
                Some(c) => {
                    *self.ue = c;
                    self.ue.tmsi = Some(Tmsi(tmsi.try_into().map_err(|_| ABORT_PROCEDURE)?));
                    return Ok(false);
                }
                None => {
                    debug!(self.logger, "Unknown TMSI");
                }
            }
        }

        // Identity procedure needed
        debug!(self.logger, "GUTI/TMSI with unknown AMF IDs or TMSI");

        Ok(true)
    }

    pub fn log_message(&self, s: &str) {
        debug!(self.logger, "{}", s)
    }

    pub fn nas_decode(
        &mut self,
        bytes: &[u8],
    ) -> Result<(Box<Nas5gsMessage>, Option<Nas5gsSecurityHeader>)> {
        self.ue.nas.decode(bytes)
    }

    // Removes any sessions that the UE doesn't know about from our UE context.
    // Returns (current sessions, reactivation result).
    async fn reconcile_sessions(
        &mut self,
        uplink_data_status_request: &Option<NasUplinkDataStatus>,
        pdu_session_status: &Option<NasPduSessionStatus>,
    ) -> Result<(u16, Option<u16>)> {
        let uplink_data_status = parse::uplink_data_status(uplink_data_status_request);
        let pdu_session_status = parse::pdu_session_status(pdu_session_status);

        debug!(
            self.logger,
            "Reconcile sessions: uplink_data_status={:016b}, pdu_session_status={:016b}",
            uplink_data_status,
            pdu_session_status
        );

        // Currently, we ignore the uplink data status and just work off the PDU session status.
        let mut sessions_to_reactivate: u16 = pdu_session_status;

        // Rebuild the UE session list to contain only sessions that the UE knows about.
        let sessions = std::mem::take(&mut self.ue.pdu_sessions);
        for session in sessions.into_iter() {
            ensure!(session.id < 16, "Session ID >= 16 not supported");
            let session_id_bit = 1 << session.id;
            if sessions_to_reactivate & session_id_bit == 0 {
                debug!(
                    self.logger,
                    "UE not aware of session {} so delete it", session.id
                );
                self.api
                    .delete_userplane_session(&session.userplane_info)
                    .await;
            } else {
                debug!(self.logger, "UE confirms existing session {}", session.id);
                self.ue.pdu_sessions.push(session);

                // Clear the bit in the sessions_to_reactivate bitmask.  Any bits still left set after this process will indicate
                // reactivation failures - cases where the UE thought there was a session but we don't know about it.
                sessions_to_reactivate &= !session_id_bit;
            }
        }

        if sessions_to_reactivate != 0 {
            warn!(
                self.logger,
                "UE asked to reactivate session(s) that we don't know about: {:016b}",
                sessions_to_reactivate
            );
        }

        let active_sessions = pdu_session_status & !sessions_to_reactivate;

        // We only return a reactivation result if the UE requested reactivation.
        let reactivation_result = uplink_data_status_request
            .as_ref()
            .map(|_| sessions_to_reactivate);

        Ok((active_sessions, reactivation_result))
    }
}

mod prelude {
    pub use super::super::prelude::*;
    pub use super::{NasBase, NasProcedure};
    pub use crate::{nas_filter, nas_request_filter};
}

#[macro_export]
macro_rules! nas_request_filter {
    ($s:ident, $f:ident) => {{
        |m| match *m.0 {
            oxirush_nas::Nas5gsMessage::Gmm(_header, oxirush_nas::Nas5gmmMessage::$s(message)) => {
                Ok(Ok(message))
            }
            oxirush_nas::Nas5gsMessage::Gmm(_header, oxirush_nas::Nas5gmmMessage::$f(message)) => {
                Ok(Err(message))
            }
            _ => Err(m),
        }
    }};
}

#[macro_export]
macro_rules! nas_filter {
    ($m:ident) => {{
        |m| match *m.0 {
            oxirush_nas::Nas5gsMessage::Gmm(_header, oxirush_nas::Nas5gmmMessage::$m(message)) => {
                Ok(message)
            }
            _ => Err(m),
        }
    }};
}
