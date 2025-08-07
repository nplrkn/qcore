mod initial_context_setup;
use asn1_per::SerDes;
mod initial_ue_message;
mod uplink_nas_transport;
use ngap::{
    AmfUeNgapId, Cause, NgapPdu, PduSessionResourceSetupResponseTransfer,
    UpTransportLayerInformation,
};
use slog::{Logger, debug, info};
mod pdu_session_resource_release;
mod pdu_session_resource_setup;
mod ue_context_release;
use super::prelude::*;
use xxap::{Indication, Procedure, RequestError};

use crate::{
    Config,
    data::{
        DecodedNas, PduSession, SubscriberAuthParams, UeContext5GC, UeRanContext, UserplaneSession,
    },
    procedures::{
        UeMessage,
        ue_associated::{NasBase, NasProcedure},
    },
    protocols::nas::Tmsi,
};

pub struct NgapUeProcedure<'a, B: RanUeBase> {
    pub ue: &'a mut UeRanContext,
    pub logger: &'a Logger,
    pub api: B,
    pub release_cause: Cause,
}

impl<'a, B: RanUeBase> NgapUeProcedure<'a, B> {
    pub async fn dispatch(
        &mut self,
        pdu: Box<NgapPdu>,
        core_context: &mut UeContext5GC,
    ) -> Result<()> {
        match *pdu {
            NgapPdu::InitiatingMessage(ngap::InitiatingMessage::InitialUeMessage(r)) => {
                self.initial_ue_message(Box::new(r), core_context).await?
            }
            NgapPdu::InitiatingMessage(ngap::InitiatingMessage::UplinkNasTransport(r)) => {
                self.uplink_nas_transport(Box::new(r), core_context).await?
            }
            NgapPdu::InitiatingMessage(
                ngap::InitiatingMessage::UeRadioCapabilityInfoIndication(_r),
            ) => {
                self.log_message(">> Ngap UeRadioCapabilityInfoIndication");
                debug!(self.logger, "Ignoring UeRadioCapabilityInfoIndication");
            }
            NgapPdu::InitiatingMessage(ngap::InitiatingMessage::UeContextReleaseRequest(r)) => {
                self.log_message(">> Ngap UeContextReleaseRequest");
                info!(
                    self.logger,
                    "GNB initiated context release, cause {:?}", r.cause
                );
                self.release_cause = r.cause.clone();
                bail!("Context release");
            }

            pdu => {
                debug!(self.logger, "Unsupported NgapPdu");
                bail!("Unsupported NgapPdu {pdu:?}");
            }
        }
        Ok(())
    }

    pub async fn dispatch_nas(
        &mut self,
        pdu: DecodedNas,
        core_context: &mut UeContext5GC,
    ) -> Result<()> {
        NasProcedure {
            ue: core_context,
            logger: &self.logger.clone(),
            api: self,
        }
        .dispatch(pdu)
        .await
    }

    pub fn log_message(&self, s: &str) {
        debug!(self.logger, "{}", s)
    }
}

use delegate::delegate;

impl<'a, B: RanUeBase> NasBase for &mut NgapUeProcedure<'a, B> {
    delegate! {
    to self.api {
        fn config(&self) -> &Config;
        async fn reserve_userplane_session(&self, logger: &Logger) -> Result<UserplaneSession>;
        async fn lookup_subscriber_creds_and_inc_sqn(&self, imsi: &str) -> Option<SubscriberAuthParams>;
        async fn resync_subscriber_sqn(&self, imsi: &str, sqn: [u8; 6]) -> Result<()>;
        async fn take_core_context(&self, tmsi: &[u8]) -> Option<UeContext5GC>;
        async fn delete_userplane_session(
            &self,
            session: &UserplaneSession,
            logger: &Logger,
        );
        fn unexpected_nas_pdu(&mut self, pdu: DecodedNas, expected: &str) -> Result<()>;
        async fn register_new_tmsi(
            &self,
            tmsi: crate::protocols::nas::Tmsi,
            ue_id: u32,
            logger: &Logger,
        );
    }}

    async fn ran_session_setup(
        &mut self,
        pdu_session: &mut PduSession,
        nas: Vec<u8>,
    ) -> Result<()> {
        self.pdu_session_resource_setup(nas, pdu_session).await?;
        self.api
            .commit_userplane_session(&pdu_session.userplane_info, self.logger)
            .await
    }

    async fn ran_context_create(
        &mut self,
        kgnb: &[u8; 32],
        nas: Vec<u8>,
        ue_session_list: &mut Vec<PduSession>,
    ) -> Result<()> {
        self.initial_context_setup(kgnb, nas, ue_session_list).await
    }

    async fn ran_session_release(
        &mut self,
        released_session: &PduSession,
        nas: Vec<u8>,
    ) -> Result<()> {
        self.pdu_session_resource_release(released_session, nas)
            .await
    }

    async fn nas_indication(&mut self, nas_bytes: Vec<u8>) -> Result<()> {
        let ngap = crate::ngap::build::downlink_nas_transport(
            AmfUeNgapId(self.ue.local_ran_ue_id as u64),
            self.ue.ran_ue_ngap_id(),
            nas_bytes,
        );

        self.api
            .xxap_indication::<ngap::DownlinkNasTransportProcedure>(ngap, self.logger)
            .await;
        Ok(())
    }

    async fn receive_nas_inner(&mut self) -> Result<Vec<u8>> {
        let uplink_nas_transport = self
            .api
            .receive_xxap_pdu(
                |m: Box<NgapPdu>| match *m {
                    NgapPdu::InitiatingMessage(ngap::InitiatingMessage::UplinkNasTransport(x)) => {
                        Ok(x)
                    }
                    _ => Err(m),
                },
                "Uplink Nas Transport",
            )
            .await?;
        self.log_message(">> Ngap UplinkNasTransport");
        Ok(uplink_nas_transport.nas_pdu.0)
    }
}

mod prelude {
    pub use super::super::prelude::*;
    pub use super::NgapUeProcedure;
}

use anyhow::{Result, bail};

fn connect_session_downlink(
    pdu_session_resource_setup_response_transfer_bytes: &[u8],
    session: &mut PduSession,
) -> Result<()> {
    let pdu_session_resource_setup_response_transfer =
        PduSessionResourceSetupResponseTransfer::from_bytes(
            pdu_session_resource_setup_response_transfer_bytes,
        )?;

    let UpTransportLayerInformation::GtpTunnel(gtp_tunnel) =
        pdu_session_resource_setup_response_transfer
            .dl_qos_flow_per_tnl_information
            .up_transport_layer_information;

    session.userplane_info.remote_tunnel_info = Some(gtp_tunnel);
    Ok(())
}
