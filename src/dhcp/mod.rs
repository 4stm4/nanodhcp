//! DHCPv4 wire protocol: message types, options, packet parsing, reply
//! building. This layer is pure (no sockets) so it can be tested without root.

pub mod builder;
pub mod message;
pub mod options;
pub mod packet;
