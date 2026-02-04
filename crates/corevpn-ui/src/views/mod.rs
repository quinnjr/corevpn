//! UI Views
//!
//! Contains all the different views/screens for the application.

mod connection;
mod server_list;
mod settings;
mod profiles;
mod logs;
mod about;

pub use connection::connection_view;
pub use server_list::server_list_view;
pub use settings::settings_view;
pub use profiles::profiles_view;
pub use logs::logs_view;
pub use about::about_view;
