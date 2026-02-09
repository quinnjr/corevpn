//! Main Application Logic
//!
//! Contains the core application struct and UI building logic using egui.

use std::path::PathBuf;

use eframe::egui;

use crate::backend::{VpnBackend, VpnEvent};
use crate::state::{AppState, AppView, LogLevel};
use crate::types::VpnConnectionStatus;
use crate::views;

/// CoreVPN Desktop Application.
pub struct CoreVpnApp {
    /// Application state
    pub state: AppState,
    /// VPN backend (async connection manager)
    backend: VpnBackend,
    /// Pending file dialog result
    pending_file: Option<PathBuf>,
}

impl CoreVpnApp {
    /// Create a new CoreVPN application instance.
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            state: AppState::new(),
            backend: VpnBackend::new(),
            pending_file: None,
        }
    }

    /// Import an .ovpn file, validating it and adding it as a profile.
    pub fn import_ovpn(&mut self, path: PathBuf) {
        match crate::backend::validate_ovpn(&path) {
            Ok(summary) => {
                let file_name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("Imported")
                    .to_string();

                // Create a profile from the .ovpn
                let profile = crate::state::VpnProfile {
                    name: file_name.clone(),
                    config_path: Some(path),
                    server_addr: summary.remote.clone(),
                    protocol: summary.protocol,
                    cipher: summary.cipher,
                    has_tls_auth: summary.has_tls_auth,
                    auto_connect: false,
                };

                self.state.add_log(
                    LogLevel::Info,
                    &format!("Imported profile '{}' ({})", file_name, summary.remote),
                );
                self.state.profiles.push(profile);
                if self.state.active_profile.is_none() {
                    self.state.active_profile = Some(file_name);
                }
            }
            Err(e) => {
                self.state.set_error(format!("Failed to import: {}", e));
            }
        }
    }

    /// Start a VPN connection using the active profile.
    pub fn start_connection(&mut self) {
        let config_path = self
            .state
            .active_profile
            .as_ref()
            .and_then(|name| {
                self.state
                    .profiles
                    .iter()
                    .find(|p| &p.name == name)
                    .and_then(|p| p.config_path.clone())
            });

        if let Some(path) = config_path {
            self.state.start_connecting();
            self.backend.connect(path);
        } else {
            self.state
                .set_error("No active profile selected. Import an .ovpn file first.");
        }
    }

    /// Stop the active VPN connection.
    pub fn stop_connection(&mut self) {
        self.state.start_disconnecting();
        self.backend.disconnect();
    }

    /// Process events from the VPN backend.
    fn process_backend_events(&mut self) {
        for event in self.backend.poll_events() {
            match event {
                VpnEvent::Connecting => {
                    self.state.connection.status = VpnConnectionStatus::Connecting;
                    self.state.add_log(LogLevel::Info, "Connecting...");
                }
                VpnEvent::Handshaking => {
                    self.state
                        .add_log(LogLevel::Info, "TLS handshake in progress...");
                }
                VpnEvent::Authenticating { url } => {
                    self.state.connection.status = VpnConnectionStatus::Authenticating;
                    if let Some(ref auth_url) = url {
                        self.state.add_log(
                            LogLevel::Info,
                            &format!("Open in browser to authenticate: {}", auth_url),
                        );
                    } else {
                        self.state.add_log(LogLevel::Info, "Authenticating...");
                    }
                }
                VpnEvent::Connected { vpn_ip, server } => {
                    self.state.set_connected();
                    if let Some(ip) = vpn_ip {
                        self.state
                            .add_log(LogLevel::Info, &format!("VPN IP: {}", ip));
                    }
                    self.state
                        .add_log(LogLevel::Info, &format!("Connected to {}", server));
                }
                VpnEvent::Disconnected => {
                    if self.state.connection.status != VpnConnectionStatus::Disconnected {
                        self.state.set_disconnected();
                    }
                }
                VpnEvent::Error(msg) => {
                    self.state.set_error(&msg);
                }
                VpnEvent::Log { level, message } => {
                    let log_level = match level {
                        crate::backend::LogLevel::Debug => LogLevel::Debug,
                        crate::backend::LogLevel::Info => LogLevel::Info,
                        crate::backend::LogLevel::Warn => LogLevel::Warn,
                        crate::backend::LogLevel::Error => LogLevel::Error,
                    };
                    self.state.add_log(log_level, &message);
                }
            }
        }
    }
}

impl eframe::App for CoreVpnApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Process any pending backend events
        self.process_backend_events();

        // Handle pending file dialog result
        if let Some(path) = self.pending_file.take() {
            self.import_ovpn(path);
        }

        // Configure the visual style
        configure_style(ctx);

        // Top panel with header
        egui::TopBottomPanel::top("header")
            .frame(egui::Frame::new().inner_margin(egui::Margin::symmetric(16, 10)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.heading(
                        egui::RichText::new("CoreVPN")
                            .strong()
                            .size(20.0),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // Status indicator
                        let status = self.state.connection.status;
                        let dot = egui::RichText::new("●")
                            .color(status.color())
                            .size(14.0);
                        ui.label(dot);
                        ui.label(
                            egui::RichText::new(status.as_str())
                                .color(status.color())
                                .size(13.0),
                        );
                    });
                });
            });

        // Bottom panel with navigation
        egui::TopBottomPanel::bottom("navigation")
            .frame(egui::Frame::new().inner_margin(egui::Margin::symmetric(16, 8)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let current_view = self.state.current_view;

                    ui.with_layout(
                        egui::Layout::centered_and_justified(egui::Direction::LeftToRight),
                        |ui| {
                            ui.spacing_mut().item_spacing.x = 40.0;

                            if nav_button(
                                ui,
                                "Home",
                                current_view == AppView::Connection,
                            ) {
                                self.state.current_view = AppView::Connection;
                            }
                            if nav_button(
                                ui,
                                "Profiles",
                                current_view == AppView::Profiles,
                            ) {
                                self.state.current_view = AppView::Profiles;
                            }
                            if nav_button(
                                ui,
                                "Settings",
                                current_view == AppView::Settings,
                            ) {
                                self.state.current_view = AppView::Settings;
                            }
                        },
                    );
                });
            });

        // Central panel with main content
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                match self.state.current_view {
                    AppView::Connection => {
                        views::connection_view(ui, &mut self.state, &mut self.backend, &mut self.pending_file);
                    }
                    AppView::ServerList => views::server_list_view(ui, &mut self.state),
                    AppView::Settings => views::settings_view(ui, &mut self.state),
                    AppView::Profiles => {
                        views::profiles_view(ui, &mut self.state, &mut self.pending_file);
                    }
                    AppView::Logs => views::logs_view(ui, &mut self.state),
                    AppView::About => views::about_view(ui, &mut self.state),
                }
            });
        });

        // Request repaint when actively connected or in transition
        if self.state.connection.status.is_transitioning() || self.backend.is_active() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}

/// Configure the egui visual style for a modern VPN client look.
fn configure_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);
    ctx.set_style(style);
}

/// Create a navigation button.
fn nav_button(ui: &mut egui::Ui, label: &str, active: bool) -> bool {
    let color = if active {
        egui::Color32::from_rgb(100, 180, 255)
    } else {
        egui::Color32::GRAY
    };

    let response = ui.add(
        egui::Button::new(egui::RichText::new(label).size(13.0).color(color)).frame(false),
    );

    response.clicked()
}
