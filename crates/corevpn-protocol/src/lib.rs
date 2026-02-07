//! OpenVPN Protocol Implementation
//!
//! This crate implements the OpenVPN protocol for compatibility with
//! standard OpenVPN clients.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod error;
pub mod opcode;
pub mod packet;
pub mod control;
pub mod data;
pub mod reliable;
pub mod session;
pub mod tls;

pub use error::{ProtocolError, Result};
pub use opcode::{OpCode, KeyId};
pub use packet::{Packet, PacketHeader};
pub use control::{ControlPacket, ControlMessage, KeyMethodV2, PushReply, PushRoute, Topology};
pub use data::{DataPacket, DataChannel};
pub use reliable::{ReliableTransport, ReliableConfig, TlsRecordReassembler};
pub use session::{ProtocolSession, ProtocolState, ProcessedPacket};
pub use tls::{TlsHandler, create_server_config, load_certs_from_pem, load_key_from_pem};
