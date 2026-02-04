//! CoreVPN Web UI
//!
//! A beautiful, modern HTML-only web interface with Tailwind CSS via CDN.
//!
//! ## Authentication
//!
//! The admin UI is protected by HTTP Basic Authentication.
//! Set the `COREVPN_ADMIN_PASSWORD` environment variable to enable access.
//! The username is always `admin`.
//!
//! ```bash
//! export COREVPN_ADMIN_PASSWORD="your-secure-password"
//! ```

pub mod auth;
pub mod csrf;
pub mod templates;
pub mod routes;
pub mod state;

pub use auth::{ADMIN_PASSWORD_ENV, ADMIN_USERNAME, is_auth_configured};
pub use routes::create_router;
pub use state::WebUiState;
