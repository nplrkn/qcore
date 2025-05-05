mod sctp_association;
mod sctp_bindings;
mod sctp_listener;
mod sock_opt;
mod try_io;

pub use sctp_association::SctpAssociation;
pub use sctp_listener::Listener;

pub type Message = Vec<u8>;
