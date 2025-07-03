use std::fmt::Display;

use async_std::channel::Sender;
use f1ap::F1apPdu;
use ngap::NgapPdu;
use rrc::UlDcchMessage;

use crate::data::{DecodedNas, NasContext};

#[derive(Debug)]
pub enum UeMessage {
    F1ap(Box<F1apPdu>),
    Ngap(Box<NgapPdu>),
    Nas(DecodedNas),
    Rrc(Box<UlDcchMessage>),
    TakeContext(Sender<NasContext>),

    // Send this message to a message handler to get a notification when the current procedure has finished processing.
    // Useful for testing purposes, to ensure that QCore has finished processing a response that the test framework
    // has sent in.
    Ping(Sender<()>),
}

impl Display for UeMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = format!("{:?}", self);
        s.truncate(64);
        write!(f, "{}", s)
    }
}

impl TryFrom<UeMessage> for Box<F1apPdu> {
    type Error = UeMessage;

    fn try_from(value: UeMessage) -> Result<Self, Self::Error> {
        if let UeMessage::F1ap(pdu) = value {
            Ok(pdu)
        } else {
            Err(value)
        }
    }
}

impl TryFrom<UeMessage> for Box<NgapPdu> {
    type Error = UeMessage;

    fn try_from(value: UeMessage) -> Result<Self, Self::Error> {
        if let UeMessage::Ngap(pdu) = value {
            Ok(pdu)
        } else {
            Err(value)
        }
    }
}

impl From<Box<NgapPdu>> for UeMessage {
    fn from(value: Box<NgapPdu>) -> Self {
        UeMessage::Ngap(value)
    }
}

impl From<Box<F1apPdu>> for UeMessage {
    fn from(value: Box<F1apPdu>) -> Self {
        UeMessage::F1ap(value)
    }
}
