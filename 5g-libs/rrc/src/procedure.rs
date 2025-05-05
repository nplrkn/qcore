use crate::*;
use crate::{RrcSetupComplete, UlDcchMessage};
use async_trait::async_trait;
//use xxap::{SerDes, Procedure, RequestError, RequestProvider, ResponseAction};
use slog::Logger;

pub struct RrcSetupProcedure {}

#[async_trait]
impl Procedure for RrcSetupProcedure {
    type TopPdu = UlDcchMessage;
    type Request = RrcSetup;
    type Success = RrcSetupComplete;
    type Failure = ();
    const CODE: u8 = 0;

    async fn call_provider<T: RequestProvider<Self>>(
        _provider: &T,
        _req: RrcSetup,
        _logger: &Logger,
    ) -> Option<ResponseAction<UlDcchMessage>> {
        todo!()
    }

    fn encode_request(r: Self::Request) -> Result<Vec<u8>, PerCodecError> {
        DlCcchMessage {
            message: DlCcchMessageType::C1(C1_1::RrcSetup(r)),
        }
        .into_bytes()
    }

    fn decode_response(bytes: &[u8]) -> Result<Self::Success, RequestError<Self::Failure>> {
        let message = UlDcchMessage::from_bytes(bytes)?;
        match message.message {
            UlDcchMessageType::C1(C1_6::RrcSetupComplete(x)) => Ok(x),
            _ => Err(RequestError::Other(format!(
                "Unexpected message - expected RrcSetupComplete, got {:?}",
                message
            ))),
        }
    }
}
