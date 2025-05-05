pub mod build;

// TS38.472, 7
// The Payload Protocol Identifier (ppid) assigned by IANA to be used by SCTP for the application layer protocol F1AP is 62,
// and 68 for DTLS over SCTP (IETF RFC 6083 [9]).
pub const F1AP_SCTP_PPID: u32 = 62;
pub const F1AP_BIND_PORT: u16 = 38472;
