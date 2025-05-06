//! build_rrc - construction of RRC messages

use asn1_per::{NonEmpty, nonempty};
use rrc::*;

pub fn setup(rrc_transaction_identifier: u8, master_cell_group: Vec<u8>) -> DlCcchMessage {
    DlCcchMessage {
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
    }
}

pub fn security_mode_command(rrc_transaction_identifier: u8) -> DlDcchMessage {
    let rrc_transaction_identifier = RrcTransactionIdentifier(rrc_transaction_identifier);

    DlDcchMessage {
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
    }
}

pub fn dl_information_transfer(
    rrc_transaction_identifier: u8,
    dedicated_nas_message: DedicatedNasMessage,
) -> DlDcchMessage {
    DlDcchMessage {
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
    }
}

pub fn reconfiguration(
    rrc_transaction_identifier: u8,
    nas_messages: Option<NonEmpty<Vec<u8>>>,
    cell_group_config: Vec<u8>,
    session_id: u8,
) -> DlDcchMessage {
    let dedicated_nas_message_list = nas_messages.map(|x| (x.map(DedicatedNasMessage)));

    // TODO - lots of hardcoding here

    DlDcchMessage {
        message: DlDcchMessageType::C1(C1_2::RrcReconfiguration(rrc::RrcReconfiguration {
            rrc_transaction_identifier: RrcTransactionIdentifier(rrc_transaction_identifier),
            critical_extensions: CriticalExtensions15::RrcReconfiguration(RrcReconfigurationIEs {
                radio_bearer_config: Some(RadioBearerConfig {
                    srb_to_add_mod_list: None,
                    srb_3_to_release: None,
                    drb_to_add_mod_list: Some(DrbToAddModList(nonempty![DrbToAddMod {
                        cn_association: Some(CnAssociation::SdapConfig(SdapConfig {
                            pdu_session: PduSessionId(session_id),
                            // SRS RAN UE does not support SdapHeaderDl::Present
                            sdap_header_dl: SdapHeaderDl::Absent,
                            sdap_header_ul: SdapHeaderUl::Present,
                            default_drb: true,
                            mapped_qos_flows_to_add: Some(nonempty![Qfi(1)]),
                            mapped_qos_flows_to_release: None
                        })),
                        drb_identity: DrbIdentity(1),
                        reestablish_pdcp: None,
                        recover_pdcp: None,
                        pdcp_config: Some(PdcpConfig {
                            drb: Some(Drb {
                                discard_timer: Some(DiscardTimer::Ms10),
                                pdcp_sn_size_ul: Some(PdcpSnSizeUl::Len12bits),
                                pdcp_sn_size_dl: Some(PdcpSnSizeDl::Len12bits),
                                header_compression: HeaderCompression::NotUsed,
                                integrity_protection: None,
                                status_report_required: None,
                                out_of_order_delivery: None
                            }),
                            more_than_one_rlc: None,
                            t_reordering: None
                        })
                    }])),
                    drb_to_release_list: None,
                    security_config: None,
                }),
                secondary_cell_group: None,
                meas_config: None,
                late_non_critical_extension: None,
                non_critical_extension: Some(RrcReconfigurationV1530IEs {
                    master_cell_group: Some(cell_group_config),
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
    }
}
