//! CoreVPN Desktop UI
//!
//! A modern VPN client interface built with the egui UI framework.
//!
//! ## Features
//!
//! - Import .ovpn profiles
//! - Real VPN connections via corevpn-cli backend
//! - TLS 1.3 with tls-auth support
//! - OAuth2/SSO authentication support
//! - Connection logs and statistics

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod app;
pub mod backend;
pub mod config;
pub mod state;
pub mod types;
pub mod views;

pub use app::CoreVpnApp;
pub use config::UiConfig;
pub use state::{AppState, AuthState, ConnectionState};
pub use types::{AuthMethod, ConnectionStats, VpnConnectionStatus};
