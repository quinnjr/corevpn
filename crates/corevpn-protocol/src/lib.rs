//! OpenVPN Protocol Implementation
//!
//! This crate implements the OpenVPN protocol for compatibility with
//! standard OpenVPN clients.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod control;
pub mod data;
pub mod error;
pub mod opcode;
pub mod packet;
pub mod reliable;
pub mod session;
pub mod tls;

pub use control::{ControlMessage, ControlPacket, KeyMethodV2, PushReply, PushRoute, Topology};
pub use data::{DataChannel, DataPacket};
pub use error::{ProtocolError, Result};
pub use opcode::{KeyId, OpCode};
pub use packet::{Packet, PacketHeader};
pub use reliable::{ReliableConfig, ReliableTransport, TlsRecordReassembler};
pub use session::{ProcessedPacket, ProtocolSession, ProtocolState};
pub use tls::{
    TlsClientHandler, TlsHandler, create_client_config, create_server_config, load_certs_from_pem,
    load_key_from_pem,
};
