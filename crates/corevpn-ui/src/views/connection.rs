//! Connection View
//!
//! Main connection view with status, profile info, and connect/disconnect buttons.

use std::path::PathBuf;

use eframe::egui;

use crate::backend::VpnBackend;
use crate::state::{AppState, AppView};
use crate::types::{ConnectionStats, VpnConnectionStatus};

/// Build the main connection view.
pub fn connection_view(
    ui: &mut egui::Ui,
    state: &mut AppState,
    backend: &mut VpnBackend,
    pending_file: &mut Option<PathBuf>,
) {
    ui.add_space(20.0);

    ui.vertical_centered(|ui| {
        // Connection status card
        connection_card(ui, state, backend);

        ui.add_space(20.0);

        // Active profile display
        if let Some(profile) = state.active_profile_ref().cloned() {
            egui::Frame::new()
                .fill(ui.visuals().extreme_bg_color)
                .corner_radius(8.0)
                .inner_margin(12.0)
                .show(ui, |ui| {
                    ui.set_min_width(280.0);
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(&profile.name).size(14.0).strong());
                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                if ui.small_button("Change").clicked() {
                                    state.current_view = AppView::Profiles;
                                }
                            },
                        );
                    });
                    ui.label(
                        egui::RichText::new(format!(
                            "{} | {} | {}",
                            profile.server_addr, profile.protocol, profile.cipher
                        ))
                        .size(11.0)
                        .color(egui::Color32::GRAY),
                    );
                });
        } else {
            // No profile - prompt to import
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new("No VPN profile loaded")
                    .size(14.0)
                    .color(egui::Color32::GRAY),
            );
            ui.add_space(12.0);
            if ui
                .add(
                    egui::Button::new(egui::RichText::new("Import .ovpn File").size(14.0))
                        .min_size(egui::vec2(200.0, 36.0)),
                )
                .clicked()
            {
                open_file_dialog(pending_file);
            }
        }

        // Last error display
        if let Some(ref error) = state.connection.last_error {
            ui.add_space(12.0);
            egui::Frame::new()
                .fill(egui::Color32::from_rgba_premultiplied(80, 20, 20, 200))
                .corner_radius(6.0)
                .inner_margin(10.0)
                .show(ui, |ui| {
                    ui.set_max_width(320.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            egui::RichText::new(error)
                                .size(12.0)
                                .color(egui::Color32::from_rgb(255, 180, 180)),
                        );
                    });
                });
        }
    });
}

/// Build the connection status card.
fn connection_card(ui: &mut egui::Ui, state: &mut AppState, backend: &mut VpnBackend) {
    let status = state.connection.status;

    egui::Frame::new()
        .fill(ui.visuals().extreme_bg_color)
        .corner_radius(12.0)
        .inner_margin(24.0)
        .show(ui, |ui| {
            ui.set_min_width(300.0);

            ui.vertical_centered(|ui| {
                // Large status icon
                let icon = match status {
                    VpnConnectionStatus::Disconnected => "Disconnected",
                    VpnConnectionStatus::Connecting | VpnConnectionStatus::Authenticating => {
                        "Connecting..."
                    }
                    VpnConnectionStatus::Connected => "Protected",
                    VpnConnectionStatus::Disconnecting | VpnConnectionStatus::Reconnecting => {
                        "Disconnecting..."
                    }
                    VpnConnectionStatus::Error => "Connection Error",
                };

                // Status circle
                let circle_color = status.color();
                let circle_size = 64.0;
                let (response, painter) =
                    ui.allocate_painter(egui::vec2(circle_size, circle_size), egui::Sense::hover());
                let center = response.rect.center();
                painter.circle_filled(center, circle_size / 2.0, circle_color.gamma_multiply(0.2));
                painter.circle_stroke(
                    center,
                    circle_size / 2.0,
                    egui::Stroke::new(3.0, circle_color),
                );
                // Inner dot
                if status.is_connected() {
                    painter.circle_filled(center, 8.0, circle_color);
                }

                ui.add_space(12.0);

                // Status text
                ui.label(
                    egui::RichText::new(icon)
                        .size(18.0)
                        .color(status.color())
                        .strong(),
                );

                // Connection statistics (when connected)
                if status.is_connected() {
                    state.connection.update_duration();
                    ui.add_space(16.0);
                    connection_stats(ui, &state.connection.stats);
                }

                ui.add_space(16.0);

                // Action button
                let has_profile = state.active_profile.is_some();

                match status {
                    VpnConnectionStatus::Disconnected | VpnConnectionStatus::Error => {
                        let btn = egui::Button::new(
                            egui::RichText::new("Connect")
                                .size(16.0)
                                .color(egui::Color32::WHITE),
                        )
                        .fill(egui::Color32::from_rgb(46, 160, 67))
                        .min_size(egui::vec2(180.0, 44.0));

                        if ui.add_enabled(has_profile, btn).clicked() {
                            // Find the active profile's config path
                            let config_path = state
                                .active_profile
                                .as_ref()
                                .and_then(|name| {
                                    state
                                        .profiles
                                        .iter()
                                        .find(|p| &p.name == name)
                                        .and_then(|p| p.config_path.clone())
                                });

                            if let Some(path) = config_path {
                                state.start_connecting();
                                backend.connect(path);
                            } else {
                                state
                                    .set_error("Profile has no config file path");
                            }
                        }
                    }
                    VpnConnectionStatus::Connected => {
                        if ui
                            .add(
                                egui::Button::new(
                                    egui::RichText::new("Disconnect")
                                        .size(16.0)
                                        .color(egui::Color32::WHITE),
                                )
                                .fill(egui::Color32::from_rgb(200, 60, 60))
                                .min_size(egui::vec2(180.0, 44.0)),
                            )
                            .clicked()
                        {
                            state.start_disconnecting();
                            backend.disconnect();
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
            ui.label(
                egui::RichText::new("Download")
                    .size(11.0)
                    .color(egui::Color32::GRAY),
            );
            ui.label(
                egui::RichText::new(ConnectionStats::format_bytes(stats.bytes_rx)).size(14.0),
            );
        });

        ui.add_space(40.0);

        ui.vertical(|ui| {
            ui.label(
                egui::RichText::new("Upload")
                    .size(11.0)
                    .color(egui::Color32::GRAY),
            );
            ui.label(
                egui::RichText::new(ConnectionStats::format_bytes(stats.bytes_tx)).size(14.0),
            );
        });
    });

    ui.add_space(8.0);
    ui.label(
        egui::RichText::new(ConnectionStats::format_duration(stats.duration_secs))
            .size(14.0)
            .color(egui::Color32::GRAY),
    );
}

/// Open a native file dialog for .ovpn import.
fn open_file_dialog(pending_file: &mut Option<PathBuf>) {
    if let Some(path) = rfd::FileDialog::new()
        .add_filter("OpenVPN Config", &["ovpn", "conf"])
        .set_title("Import VPN Profile")
        .pick_file()
    {
        *pending_file = Some(path);
    }
}
