// Subset of the bindgen bindings for netinet/sctp.h
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
pub type __s8 = ::std::os::raw::c_schar;
pub type __u8 = ::std::os::raw::c_uchar;
pub type __s16 = ::std::os::raw::c_short;
pub type __u16 = ::std::os::raw::c_ushort;
pub type __s32 = ::std::os::raw::c_int;
pub type __u32 = ::std::os::raw::c_uint;
pub type __s64 = ::std::os::raw::c_longlong;
pub type __u64 = ::std::os::raw::c_ulonglong;
pub type sctp_assoc_t = __s32;
pub type sctp_cmsg_type = ::std::os::raw::c_uint;
//pub const SCTP_NODELAY: u32 = 3;
pub const SCTP_PEER_ADDR_PARAMS: u32 = 9;
pub const SCTP_RECVRCVINFO: u32 = 32;
pub const SOL_SCTP: u32 = 132;
pub const sctp_cmsg_type_SCTP_SNDINFO: sctp_cmsg_type = 2;
pub const sctp_spp_flags_SPP_HB_ENABLE: sctp_spp_flags = 1;
pub type sctp_spp_flags = ::std::os::raw::c_uint;

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct sctp_rcvinfo {
    pub rcv_sid: __u16,
    pub rcv_ssn: __u16,
    pub rcv_flags: __u16,
    pub rcv_ppid: __u32,
    pub rcv_tsn: __u32,
    pub rcv_cumtsn: __u32,
    pub rcv_context: __u32,
    pub rcv_assoc_id: sctp_assoc_t,
}

#[repr(C, packed(2))] // bindgen seems to have got this wrong - was packed(4)
#[derive(Debug, Copy, Clone)]
pub struct sctp_paddrparams {
    pub spp_assoc_id: sctp_assoc_t,
    pub spp_address: sockaddr_storage,
    pub spp_hbinterval: __u32,
    pub spp_pathmaxrxt: __u16,
    pub spp_pathmtu: __u32,
    pub spp_sackdelay: __u32,
    pub spp_flags: __u32,
    pub spp_ipv6_flowlabel: __u32,
    pub spp_dscp: __u8,
}

pub type sa_family_t = ::std::os::raw::c_ushort;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sockaddr_storage {
    pub ss_family: sa_family_t,
    pub __ss_padding: [::std::os::raw::c_char; 118usize],
    pub __ss_align: ::std::os::raw::c_ulong,
}
