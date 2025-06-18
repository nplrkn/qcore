use crate::{PdcpSequenceNumberLength, data::PduSession};
use anyhow::Result;
use asn1_per::{NonEmpty, SerDes, nonempty};
use rrc::*;
use std::collections::HashSet;

pub fn setup(rrc_transaction_identifier: u8, master_cell_group: Vec<u8>) -> Box<DlCcchMessage> {
    Box::new(DlCcchMessage {
        message: DlCcchMessageType::C1(C1_1::RrcSetup(RrcSetup {
            rrc_transaction_identifier: RrcTransactionIdentifier(rrc_transaction_identifier),
            critical_extensions: CriticalExtensions21::RrcSetup(RrcSetupIEs {
                radio_bearer_config: RadioBearerConfig {
                    // Create SRB1
                    srb_to_add_mod_list: Some(SrbToAddModList(nonempty![SrbToAddMod {
                        srb_identity: SrbIdentity(1),
                        reestablish_pdcp: None,
                        discard_on_pdcp: None,
                        pdcp_config: None,
                    }])),
                    srb_3_to_release: None,
                    drb_to_add_mod_list: None,
                    drb_to_release_list: None,
                    security_config: None,
                },
                master_cell_group,
                late_non_critical_extension: None,
            }),
        })),
    })
}

pub fn security_mode_command(rrc_transaction_identifier: u8) -> Box<DlDcchMessage> {
    let rrc_transaction_identifier = RrcTransactionIdentifier(rrc_transaction_identifier);

    Box::new(DlDcchMessage {
        message: DlDcchMessageType::C1(C1_2::SecurityModeCommand(rrc::SecurityModeCommand {
            rrc_transaction_identifier,
            critical_extensions: CriticalExtensions26::SecurityModeCommand(
                SecurityModeCommandIEs {
                    security_config_smc: SecurityConfigSmc {
                        security_algorithm_config: SecurityAlgorithmConfig {
                            ciphering_algorithm: CipheringAlgorithm::Nea0,
                            integrity_prot_algorithm: Some(IntegrityProtAlgorithm::Nia2),
                        },
                    },
                    late_non_critical_extension: None,
                },
            ),
        })),
    })
}

pub fn dl_information_transfer(
    rrc_transaction_identifier: u8,
    dedicated_nas_message: DedicatedNasMessage,
) -> Box<DlDcchMessage> {
    Box::new(DlDcchMessage {
        message: DlDcchMessageType::C1(C1_2::DlInformationTransfer(DlInformationTransfer {
            rrc_transaction_identifier: RrcTransactionIdentifier(rrc_transaction_identifier),
            critical_extensions: CriticalExtensions4::DlInformationTransfer(
                DlInformationTransferIEs {
                    dedicated_nas_message: Some(dedicated_nas_message),
                    late_non_critical_extension: None,
                    non_critical_extension: None,
                },
            ),
        })),
    })
}

pub fn reconfiguration(
    rrc_transaction_identifier: u8,
    nas_messages: Option<NonEmpty<Vec<u8>>>,
    session_to_add: Option<&PduSession>,
    session_to_delete: Option<&PduSession>,
    master_cell_group: Option<Vec<u8>>,
) -> Box<DlDcchMessage> {
    let dedicated_nas_message_list = nas_messages.map(|x| (x.map(DedicatedNasMessage)));

    let (srb_to_add_mod_list, drb_to_add_mod_list) = if let Some(session_to_add) = session_to_add {
        let (pdcp_sn_size_ul, pdcp_sn_size_dl) = match session_to_add.userplane_info.pdcp_sn_length
        {
            PdcpSequenceNumberLength::TwelveBits => {
                (Some(PdcpSnSizeUl::Len12bits), Some(PdcpSnSizeDl::Len12bits))
            }
            PdcpSequenceNumberLength::EighteenBits => {
                (Some(PdcpSnSizeUl::Len18bits), Some(PdcpSnSizeDl::Len18bits))
            }
        };
        (
            Some(SrbToAddModList(nonempty![SrbToAddMod {
                srb_identity: SrbIdentity(2),
                reestablish_pdcp: None,
                discard_on_pdcp: None,
                pdcp_config: None,
            }])),
            Some(DrbToAddModList(nonempty![DrbToAddMod {
                cn_association: Some(CnAssociation::SdapConfig(SdapConfig {
                    pdu_session: PduSessionId(session_to_add.id),
                    // SRS RAN UE does not support SdapHeaderDl::Present
                    sdap_header_dl: SdapHeaderDl::Absent,
                    sdap_header_ul: SdapHeaderUl::Present,
                    default_drb: true,
                    mapped_qos_flows_to_add: Some(nonempty![Qfi(session_to_add
                        .userplane_info
                        .qfi)]),
                    mapped_qos_flows_to_release: None
                })),
                drb_identity: DrbIdentity(1),
                reestablish_pdcp: None,
                recover_pdcp: None,
                pdcp_config: Some(PdcpConfig {
                    drb: Some(Drb {
                        discard_timer: Some(DiscardTimer::Ms10),
                        pdcp_sn_size_ul,
                        pdcp_sn_size_dl,
                        header_compression: HeaderCompression::NotUsed,
                        integrity_protection: None,
                        status_report_required: None,
                        out_of_order_delivery: None
                    }),
                    more_than_one_rlc: None,
                    t_reordering: None
                })
            }])),
        )
    } else {
        (None, None)
    };

    let drb_to_release_list =
        session_to_delete.map(|_| DrbToReleaseList(nonempty![DrbIdentity(1)]));

    // TODO - lots of hardcoding here

    Box::new(DlDcchMessage {
        message: DlDcchMessageType::C1(C1_2::RrcReconfiguration(rrc::RrcReconfiguration {
            rrc_transaction_identifier: RrcTransactionIdentifier(rrc_transaction_identifier),
            critical_extensions: CriticalExtensions15::RrcReconfiguration(RrcReconfigurationIEs {
                radio_bearer_config: Some(RadioBearerConfig {
                    // This matches the SRB that we previously asked the DU to establish
                    srb_to_add_mod_list,
                    srb_3_to_release: None,
                    drb_to_add_mod_list,
                    drb_to_release_list,
                    security_config: None,
                }),
                secondary_cell_group: None,
                meas_config: None,
                late_non_critical_extension: None,
                non_critical_extension: Some(RrcReconfigurationV1530IEs {
                    master_cell_group,
                    full_config: None,
                    dedicated_nas_message_list,
                    master_key_update: None,
                    dedicated_sib_1_delivery: None,
                    dedicated_system_information_delivery: None,
                    other_config: None,
                    non_critical_extension: None,
                }),
            }),
        })),
    })
}

pub fn ue_capability_enquiry(
    rrc_transaction_identifier: u8,
    bands: &HashSet<u16>,
) -> Result<Box<DlDcchMessage>> {
    let freq_band_list = NonEmpty::collect(bands.iter().map(|band| {
        FreqBandInformation::BandInformationNr(FreqBandInformationNr {
            band_nr: FreqBandIndicatorNr(*band),
            max_bandwidth_requested_dl: None,
            max_bandwidth_requested_ul: None,
            max_carriers_requested_dl: None,
            max_carriers_requested_ul: None,
        })
    }))
    .map(FreqBandList);

    let capability_request_filter = if freq_band_list.is_some() {
        Some(
            UeCapabilityRequestFilterNr {
                frequency_band_list_filter: freq_band_list,
                non_critical_extension: None,
            }
            .as_bytes()?,
        )
    } else {
        None
    };

    Ok(Box::new(DlDcchMessage {
        message: DlDcchMessageType::C1(C1_2::UeCapabilityEnquiry(UeCapabilityEnquiry {
            rrc_transaction_identifier: RrcTransactionIdentifier(rrc_transaction_identifier),
            critical_extensions: CriticalExtensions32::UeCapabilityEnquiry(
                UeCapabilityEnquiryIEs {
                    ue_capability_rat_request_list: UeCapabilityRatRequestList(nonempty![
                        UeCapabilityRatRequest {
                            rat_type: RatType::Nr,
                            capability_request_filter
                        }
                    ]),
                    late_non_critical_extension: None,
                    ue_capability_enquiry_ext: None,
                },
            ),
        })),
    }))
}
