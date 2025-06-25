use super::prelude::*;
use crate::rrc_filter;
use asn1_per::SerDes;
use f1ap::{FddInfo, NrFreqInfo, NrModeInfo, SrbId, TddInfo};
use rrc::{
    C1_6, CriticalExtensions33, UeCapabilityInformation, UeCapabilityInformationIEs, UlDcchMessage,
    UlDcchMessageType,
};
use std::collections::HashSet;
use xxap::NrCgi;

define_ue_procedure!(RrcUeCapabilityEnquiryProcedure);

impl<'a, A: HandlerApi> RrcUeCapabilityEnquiryProcedure<'a, A> {
    pub async fn run(mut self) -> Result<UeProcedure<'a, A>> {
        // The capability information response can be exceptionally long (multiple SCTP chunks) unless we filter it.
        let Some(nr_cgi) = &self.ue.nr_cgi else {
            bail!("Logic error - NR CGI missing")
        };

        let bands = self.get_bands_for_served_cell(nr_cgi).await?;
        debug!(self.logger, "Asking UE about bands: {:?}", bands);

        let r = crate::rrc::build::ue_capability_enquiry(1, &bands)?;
        self.log_message("<< Rrc UeCapabilityEnquiry");

        let ue_capability_information = self
            .rrc_request(
                SrbId(1),
                &r,
                rrc_filter!(UeCapabilityInformation),
                "Rrc Ue Capability Information",
            )
            .await?;
        self.log_message(">> Rrc UeCapabilityInformation");

        if let UeCapabilityInformation {
            critical_extensions:
                CriticalExtensions33::UeCapabilityInformation(UeCapabilityInformationIEs {
                    ue_capability_rat_container_list: Some(capabilities),
                    ..
                }),
            ..
        } = ue_capability_information
        {
            self.ue.rat_capabilities = Some(capabilities.as_bytes()?);
        }
        Ok(self.0)
    }

    async fn get_bands_for_served_cell(&self, nr_cgi: &NrCgi) -> Result<HashSet<u16>> {
        let mut bands: HashSet<u16> = HashSet::new();

        // TODO: surely this calls for a HashMap by NrCgi?
        for du in self.served_cells().lock().await.iter() {
            for item in du.1.iter() {
                if item.served_cell_information.nr_cgi == *nr_cgi {
                    match &item.served_cell_information.nr_mode_info {
                        NrModeInfo::Fdd(FddInfo {
                            ul_nr_freq_info,
                            dl_nr_freq_info,
                            ..
                        }) => {
                            add_bands(&mut bands, ul_nr_freq_info);
                            add_bands(&mut bands, dl_nr_freq_info);
                        }
                        NrModeInfo::Tdd(TddInfo { nr_freq_info, .. }) => {
                            add_bands(&mut bands, nr_freq_info);
                        }
                        NrModeInfo::NrUChannelInfoList(_) => {
                            bail!("NRU channel info list not supported")
                        }
                    }
                    break;
                }
            }
        }
        Ok(bands)
    }
}

fn add_bands(bands: &mut HashSet<u16>, freq_info: &NrFreqInfo) {
    for band in freq_info.freq_band_list_nr.iter() {
        bands.insert(band.freq_band_indicator_nr);
    }
}
