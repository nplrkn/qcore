mod initial_context_setup;
mod initial_ue_message;
mod pdu_session_resource_release;
mod pdu_session_resource_setup;
mod ue_context_release;
mod uplink_nas_transport;

use super::prelude::*;
use crate::{
    Config,
    data::{PduSession, SubscriberAuthParams, UeContext5GC, UeContextRan, UserplaneSession},
    procedures::ue_associated::{NasBase, NasProcedure, ran_ue_base::ReleaseCause},
};
use asn1_per::SerDes;
use nas::DecodedNas;
use ngap::{
    AmfUeNgapId, CauseNas, NgapPdu, PduSessionResourceSetupResponseTransfer,
    UpTransportLayerInformation,
};
use slog::{Logger, debug, info};

pub struct NgapUeProcedure<'a, B: RanUeBase> {
    pub ue: &'a mut UeContextRan,
    pub logger: Logger,
    pub api: B,
}

impl<'a, B: RanUeBase> NgapUeProcedure<'a, B> {
    pub async fn dispatch(
        &mut self,
        pdu: Box<NgapPdu>,
        core_context: &'a mut UeContext5GC,
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
                    "gNB initiated context release, cause {:?}", r.cause
                );
                self.api.disconnect_ue(ReleaseCause::Ngap(r.cause));
            }

            pdu => {
                debug!(self.logger, "Unsupported NgapPdu");
                bail!("Unsupported NgapPdu {pdu:?}");
            }
        }
        Ok(())
    }

    fn nas_procedure(&mut self, core_context: &'a mut UeContext5GC) -> NasProcedure<'a, &mut Self> {
        NasProcedure {
            ue: core_context,
            logger: self.logger.clone(),
            api: self,
        }
    }

    pub async fn dispatch_nas(
        &mut self,
        pdu: DecodedNas,
        core_context: &'a mut UeContext5GC,
    ) -> Result<()> {
        self.nas_procedure(core_context).dispatch(pdu).await
    }

    pub fn log_message(&self, s: &str) {
        debug!(self.logger, "{}", s)
    }

    async fn connect_session_downlink(
        &self,
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
        self.api
            .commit_userplane_session(&session.userplane_info, &self.logger)
            .await
    }
}

use delegate::delegate;

impl<'a, B: RanUeBase> NasBase for &mut NgapUeProcedure<'a, B> {
    delegate! {
        to self.api {
            fn config(&self) -> &Config;
            async fn lookup_subscriber_creds_and_inc_sqn(&self, imsi: &str) -> Option<SubscriberAuthParams>;
            async fn resync_subscriber_sqn(&self, imsi: &str, sqn: [u8; 6]) -> Result<()>;
            async fn take_core_context(&self, tmsi: &[u8]) -> Option<UeContext5GC>;
            #[call(unexpected_pdu)]
            fn unexpected_nas_pdu(&mut self, pdu: DecodedNas, expected: &str) -> Result<()>;
            async fn allocate_userplane_session(&self, [&self.logger]) -> Result<UserplaneSession>;
            async fn delete_userplane_session(
                &self,
                session: &UserplaneSession,
                [&self.logger],
            );
            async fn register_new_tmsi(&self, [self.ue.local_ran_ue_id], [&self.logger]) -> [u8;4];
            async fn delete_tmsi(&self, tmsi: [u8; 4]);
    }}

    fn disconnect_ue(&mut self) {
        // Currently this can only be called in the case of a UE deregistration
        // so there is no need for the cause to be a parameter.
        self.api
            .disconnect_ue(ReleaseCause::Ngap(ngap::Cause::Nas(CauseNas::Deregister)));
    }

    fn ue_tac(&self) -> &[u8; 3] {
        &self.ue.tac
    }

    async fn ran_session_setup(
        &mut self,
        pdu_session: &mut PduSession,
        nas: Vec<u8>,
    ) -> Result<()> {
        self.pdu_session_resource_setup(nas, pdu_session).await
    }

    async fn ran_context_create(
        &mut self,
        kgnb: &[u8; 32],
        nas: Vec<u8>,
        session_list: &mut Vec<PduSession>,
        ue_security_capabilities: &[u8; 2],
    ) -> Result<()> {
        self.initial_context_setup(kgnb, nas, session_list, ue_security_capabilities)
            .await
    }

    async fn ran_session_release(
        &mut self,
        released_session: &PduSession,
        nas: Vec<u8>,
    ) -> Result<()> {
        self.pdu_session_resource_release(released_session, nas)
            .await
    }

    async fn send_nas(&mut self, nas_bytes: Vec<u8>) -> Result<()> {
        let ngap = crate::ngap::build::downlink_nas_transport(
            AmfUeNgapId(self.ue.local_ran_ue_id as u64),
            self.ue.ran_ue_ngap_id(),
            nas_bytes,
        );

        self.api
            .xxap_indication::<ngap::DownlinkNasTransportProcedure>(ngap, &self.logger)
            .await;
        Ok(())
    }

    async fn receive_nas(&mut self) -> Result<Vec<u8>> {
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
