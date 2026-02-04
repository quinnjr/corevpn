//! Connection View
//!
//! Main connection view with status, server selection, and connect/disconnect buttons.

use eframe::egui;

use crate::state::{AppState, AppView, validate_password, validate_username};
use crate::types::{ConnectionStats, VpnConnectionStatus};

/// Build the main connection view.
pub fn connection_view(ui: &mut egui::Ui, state: &mut AppState) {
    ui.add_space(20.0);

    ui.vertical_centered(|ui| {
        // Connection status card
        connection_card(ui, state);

        ui.add_space(20.0);

        // Server selection button
        let server_name = state
            .selected_server()
            .map(|s| format!("📍 {}", s.name))
            .unwrap_or_else(|| "📍 No server selected".to_string());

        if ui
            .add(
                egui::Button::new(egui::RichText::new(&server_name).size(14.0))
                    .min_size(egui::vec2(200.0, 36.0)),
            )
            .clicked()
        {
            state.current_view = AppView::ServerList;
        }

        ui.add_space(16.0);

        // Authentication section (only for username/password auth)
        if state.auth_method.requires_password()
            && state.connection.status == VpnConnectionStatus::Disconnected
        {
            auth_section(ui, state);
        }

        // SSO indicator for OAuth2/SAML
        if state.auth_method.is_sso()
            && state.connection.status == VpnConnectionStatus::Disconnected
        {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label("🔐");
                ui.label(
                    egui::RichText::new("Sign in with your organization")
                        .size(13.0)
                        .color(egui::Color32::GRAY),
                );
            });
        }
    });
}

/// Build the connection status card.
fn connection_card(ui: &mut egui::Ui, state: &mut AppState) {
    let status = state.connection.status;
    let server_name = state
        .selected_server()
        .map(|s| s.name.clone())
        .unwrap_or_else(|| "No server selected".to_string());

    egui::Frame::new()
        .fill(ui.visuals().extreme_bg_color)
        .corner_radius(12.0)
        .inner_margin(24.0)
        .show(ui, |ui| {
            ui.set_min_width(300.0);

            ui.vertical_centered(|ui| {
                // Large status icon
                let icon = match status {
                    VpnConnectionStatus::Disconnected => "🔓",
                    VpnConnectionStatus::Connecting | VpnConnectionStatus::Authenticating => "⏳",
                    VpnConnectionStatus::Connected => "🔒",
                    VpnConnectionStatus::Disconnecting | VpnConnectionStatus::Reconnecting => "⏳",
                    VpnConnectionStatus::Error => "⚠️",
                };
                ui.label(egui::RichText::new(icon).size(48.0));

                ui.add_space(8.0);

                // Status text
                ui.label(
                    egui::RichText::new(status.as_str())
                        .size(18.0)
                        .color(status.color()),
                );

                ui.add_space(4.0);

                // Server name
                ui.label(egui::RichText::new(&server_name).size(14.0).color(egui::Color32::GRAY));

                // Connection statistics (when connected)
                if status.is_connected() {
                    ui.add_space(16.0);
                    connection_stats(ui, &state.connection.stats);
                }

                ui.add_space(16.0);

                // Action button
                match status {
                    VpnConnectionStatus::Disconnected | VpnConnectionStatus::Error => {
                        if ui
                            .add(
                                egui::Button::new(egui::RichText::new("Connect").size(16.0))
                                    .fill(egui::Color32::from_rgb(46, 160, 67))
                                    .min_size(egui::vec2(180.0, 44.0)),
                            )
                            .clicked()
                        {
                            if state.is_sso() {
                                state.start_connecting();
                                state.set_authenticating();
                                tracing::info!("Starting OAuth2 authentication flow");
                            } else {
                                // Validate credentials before connecting
                                if let Some(err) = validate_username(&state.username) {
                                    state.set_error(format!("Invalid username: {}", err));
                                    return;
                                }
                                if let Some(err) = validate_password(state.password()) {
                                    state.set_error(format!("Invalid password: {}", err));
                                    return;
                                }
                                state.start_connecting();
                            }
                        }
                    }
                    VpnConnectionStatus::Connected => {
                        if ui
                            .add(
                                egui::Button::new(egui::RichText::new("Disconnect").size(16.0))
                                    .fill(egui::Color32::from_rgb(200, 60, 60))
                                    .min_size(egui::vec2(180.0, 44.0)),
                            )
                            .clicked()
                        {
                            state.start_disconnecting();
                            state.set_disconnected();
                        }
                    }
                    _ => {
                        ui.add_enabled(
                            false,
                            egui::Button::new(egui::RichText::new("...").size(16.0))
                                .min_size(egui::vec2(180.0, 44.0)),
                        );
                    }
                }
            });
        });
}

/// Display connection statistics.
fn connection_stats(ui: &mut egui::Ui, stats: &ConnectionStats) {
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(egui::RichText::new("↓ Download").size(11.0).color(egui::Color32::GRAY));
            ui.label(egui::RichText::new(ConnectionStats::format_bytes(stats.bytes_rx)).size(14.0));
            ui.label(
                egui::RichText::new(ConnectionStats::format_speed(stats.speed_rx))
                    .size(11.0)
                    .color(egui::Color32::GRAY),
            );
        });

        ui.add_space(40.0);

        ui.vertical(|ui| {
            ui.label(egui::RichText::new("↑ Upload").size(11.0).color(egui::Color32::GRAY));
            ui.label(egui::RichText::new(ConnectionStats::format_bytes(stats.bytes_tx)).size(14.0));
            ui.label(
                egui::RichText::new(ConnectionStats::format_speed(stats.speed_tx))
                    .size(11.0)
                    .color(egui::Color32::GRAY),
            );
        });
    });

    ui.add_space(8.0);

    ui.horizontal(|ui| {
        ui.label("⏱️");
        ui.label(ConnectionStats::format_duration(stats.duration_secs));
    });
}

/// Authentication input section.
fn auth_section(ui: &mut egui::Ui, state: &mut AppState) {
    ui.vertical(|ui| {
        ui.set_max_width(280.0);

        // Username input with validation feedback
        let username_response = ui.add(
            egui::TextEdit::singleline(&mut state.username)
                .hint_text("Username")
                .desired_width(280.0),
        );

        // Show validation error if any
        if username_response.lost_focus() {
            if let Some(err) = validate_username(&state.username) {
                ui.label(
                    egui::RichText::new(err)
                        .size(11.0)
                        .color(egui::Color32::RED),
                );
            }
        }

        ui.add_space(8.0);

        // Password input with validation feedback
        let password_response = ui.add(
            egui::TextEdit::singleline(state.password_mut())
                .hint_text("Password")
                .password(true)
                .desired_width(280.0),
        );

        // Show validation error if any
        if password_response.lost_focus() {
            if let Some(err) = validate_password(state.password()) {
                ui.label(
                    egui::RichText::new(err)
                        .size(11.0)
                        .color(egui::Color32::RED),
                );
            }
        }
    });
}
