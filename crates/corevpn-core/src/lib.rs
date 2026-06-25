//! CoreVPN Core Types and Utilities
//!
//! This crate provides the fundamental types used throughout CoreVPN.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod error;
pub mod network;
pub mod session;
pub mod user;

pub use error::{CoreError, Result};
pub use network::{AddressPool, Route, VpnAddress};
pub use session::{Session, SessionId, SessionManager, SessionState};
pub use user::{User, UserId, UserRole};
