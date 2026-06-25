//! UI Views
//!
//! Contains all the different views/screens for the application.

mod about;
mod connection;
mod logs;
mod profiles;
mod server_list;
mod settings;

pub use about::about_view;
pub use connection::connection_view;
pub use logs::logs_view;
pub use profiles::profiles_view;
pub use server_list::server_list_view;
pub use settings::settings_view;
