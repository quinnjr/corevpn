//! CoreVPN Desktop UI
//!
//! A modern VPN client interface similar to OpenVPN Connect,
//! built with the egui UI framework.
//!
//! ## Features
//!
//! - Clean, modern UI similar to OpenVPN Connect
//! - OAuth2/SAML SSO authentication support
//! - Server list with load and latency indicators
//! - Connection statistics display
//! - Profile management
//!
//! ## Authentication Methods
//!
//! The UI supports multiple authentication methods:
//! - Username/Password (traditional)
//! - Certificate-based
//! - OAuth2/OIDC (Google, Microsoft, Okta, etc.)
//! - SAML (enterprise SSO)
//!
//! When OAuth2 or SAML is configured, the password field is hidden
//! and the user is redirected to the identity provider.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod app;
pub mod config;
pub mod state;
pub mod types;
pub mod views;

pub use app::CoreVpnApp;
pub use config::UiConfig;
pub use state::{AppState, AuthState, ConnectionState};
pub use types::{AuthMethod, ConnectionStats, VpnConnectionStatus, VpnServer};