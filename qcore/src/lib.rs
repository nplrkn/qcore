mod cluster;
mod data;
mod procedures;
mod protocols;
mod qcore;
mod subscriber_db;
mod userplane;

use data::*;
use procedures::ProcedureBase;
use protocols::*;

pub use crate::nas::AmfIds;
pub use ::xxap::PlmnIdentity;
use anyhow::{Result, ensure};
pub use data::{
    ClusterConfig, Config, DhcpConfig, NetworkDisplayName, PdcpSequenceNumberLength, SimCreds, Sqn,
    Subscriber, SubscriberAuthParams, UeIpAllocationConfig,
};
pub use qcore::{ProgramHandle, QCore};
pub use subscriber_db::SubscriberDb;
pub use userplane::get_if_index;
pub use userplane::netlink::Netlink;

pub fn ue_dhcp_identifier(imsi: &str) -> Result<Vec<u8>> {
    // When getting a DHCP address, we need to provide a client identifier that is unique on the
    // subnet (RFC2131, section 2).  An IP UE does not have a MAC address.
    // We want the client identifier to be transferable to another QCore instance in the case of handover/failover.
    // Finally, we want to support static IPs via a DHCP reservation.  This means we have to use a deterministic and
    // easily derivable ID that can be configured ahead of time in the DHCP reservation.
    //
    // Some valid options might be:
    // -  IMSI
    // -  IMEI
    // -  fake MAC address.
    //
    // I am not sure whether the session ID could be part of the client identifier or whether two
    // sessions should be modelled as a single DHCP client wanting two addresses.  Anyway, QCore
    // only supports 1 session per UE right now.
    //
    // Based on the dhcpcd.conf man pages ("in order for a bootp client to be recognized..."),
    // we do not assume that DHCP servers can configure reservations off anything other than MAC.
    // Therefore, we go with the fake MAC address model.
    //
    // QCore does not currently support per IMSI or IMEI configuration, so we can't get all of part of the
    // fake MAC from configuration, though that might be an option in future.
    //
    // In the long run we might want a customizable MAC generation function like:
    // -  fn(imsi, imei, session ID, per-imsi configuration, per-imei configuration, mac prefix) -> [u8;6]
    //
    // For now, we form a MAC with the prefix 02 followed by the rightmost 10 digits of IMSI.  For example,
    // IMSI 00101234554321 -> 00101[1234554321] -> MAC 02:12:34:55:43:21.
    let imsi_bytes = imsi.as_bytes();
    ensure!(imsi_bytes.len() >= 10);
    let digits: Vec<u8> = imsi_bytes[imsi_bytes.len() - 10..]
        .iter()
        .map(|byte| byte - b'0')
        .collect();
    Ok(vec![
        0x02,
        (digits[0] << 4) | digits[1],
        (digits[2] << 4) | digits[3],
        (digits[4] << 4) | digits[5],
        (digits[6] << 4) | digits[7],
        (digits[8] << 4) | digits[9],
    ])
}
