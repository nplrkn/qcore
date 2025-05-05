use asn1_per::{Msb0, bitvec};
use rrc::*;

pub fn setup_request() -> UlCcchMessage {
    UlCcchMessage {
        message: UlCcchMessageType::C1(C1_4::RrcSetupRequest(RrcSetupRequest {
            rrc_setup_request: RrcSetupRequestIEs {
                ue_identity: InitialUeIdentity::Ng5gSTmsiPart1(bitvec![u8, Msb0; 0;39]),
                establishment_cause: EstablishmentCause::MtAccess,
                spare: bitvec![u8, Msb0;0;1],
            },
        })),
    }
}

pub fn setup_complete(
    rrc_transaction_identifier: RrcTransactionIdentifier,
    nas_bytes: Vec<u8>,
) -> UlDcchMessage {
    UlDcchMessage {
        message: UlDcchMessageType::C1(C1_6::RrcSetupComplete(RrcSetupComplete {
            rrc_transaction_identifier,
            critical_extensions: CriticalExtensions22::RrcSetupComplete(RrcSetupCompleteIEs {
                selected_plmn_identity: 1,
                registered_amf: None,
                guami_type: None,
                snssai_list: None,
                dedicated_nas_message: DedicatedNasMessage(nas_bytes),
                ng_5g_s_tmsi_value: None,
                late_non_critical_extension: None,
                non_critical_extension: None,
            }),
        })),
    }
}

pub fn security_mode_complete(
    rrc_transaction_identifier: RrcTransactionIdentifier,
) -> UlDcchMessage {
    UlDcchMessage {
        message: UlDcchMessageType::C1(C1_6::SecurityModeComplete(SecurityModeComplete {
            rrc_transaction_identifier,
            critical_extensions: CriticalExtensions27::SecurityModeComplete(
                SecurityModeCompleteIEs {
                    late_non_critical_extension: None,
                },
            ),
        })),
    }
}

pub fn ul_information_transfer(nas_bytes: Vec<u8>) -> UlDcchMessage {
    UlDcchMessage {
        message: UlDcchMessageType::C1(C1_6::UlInformationTransfer(UlInformationTransfer {
            critical_extensions: CriticalExtensions37::UlInformationTransfer(
                UlInformationTransferIEs {
                    dedicated_nas_message: Some(DedicatedNasMessage(nas_bytes)),
                    late_non_critical_extension: None,
                },
            ),
        })),
    }
}

pub fn reconfiguration_complete(
    rrc_transaction_identifier: RrcTransactionIdentifier,
) -> UlDcchMessage {
    UlDcchMessage {
        message: UlDcchMessageType::C1(C1_6::RrcReconfigurationComplete(
            RrcReconfigurationComplete {
                rrc_transaction_identifier,
                critical_extensions: CriticalExtensions16::RrcReconfigurationComplete(
                    RrcReconfigurationCompleteIEs {
                        late_non_critical_extension: None,
                        non_critical_extension: None,
                    },
                ),
            },
        )),
    }
}
