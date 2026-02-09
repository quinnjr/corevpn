//! Profiles View
//!
//! VPN profile management - import, select, and delete .ovpn profiles.

use std::path::PathBuf;

use eframe::egui;

use crate::state::{AppState, AppView};

/// Build the profiles view.
pub fn profiles_view(ui: &mut egui::Ui, state: &mut AppState, pending_file: &mut Option<PathBuf>) {
    ui.add_space(8.0);

    // Header with back button and import
    ui.horizontal(|ui| {
        if ui.button("< Back").clicked() {
            state.current_view = AppView::Connection;
        }
        ui.heading("VPN Profiles");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .add(
                    egui::Button::new(
                        egui::RichText::new("Import .ovpn")
                            .color(egui::Color32::WHITE),
                    )
                    .fill(egui::Color32::from_rgb(46, 160, 67)),
                )
                .clicked()
            {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("OpenVPN Config", &["ovpn", "conf"])
                    .set_title("Import VPN Profile")
                    .pick_file()
                {
                    *pending_file = Some(path);
                }
            }
        });
    });

    ui.add_space(16.0);

    if state.profiles.is_empty() {
        // Empty state
        ui.add_space(40.0);
        ui.vertical_centered(|ui| {
            ui.label(egui::RichText::new("No profiles yet").size(16.0));
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("Import an .ovpn file to get started")
                    .size(13.0)
                    .color(egui::Color32::GRAY),
            );
        });
    } else {
        // Profile list
        let active_profile = state.active_profile.clone();
        let profiles: Vec<_> = state.profiles.iter().cloned().collect();
        let mut to_delete: Option<String> = None;
        let mut to_activate: Option<String> = None;

        for profile in &profiles {
            let is_active = active_profile.as_ref() == Some(&profile.name);

            egui::Frame::new()
                .fill(if is_active {
                    ui.visuals().selection.bg_fill
                } else {
                    ui.visuals().extreme_bg_color
                })
                .corner_radius(8.0)
                .inner_margin(14.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new(&profile.name).size(14.0).strong());
                            ui.label(
                                egui::RichText::new(&profile.server_addr)
                                    .size(12.0)
                                    .color(egui::Color32::GRAY),
                            );
                            ui.label(
                                egui::RichText::new(format!(
                                    "{} | {}{}",
                                    profile.protocol,
                                    profile.cipher,
                                    if profile.has_tls_auth {
                                        " | tls-auth"
                                    } else {
                                        ""
                                    }
                                ))
                                .size(11.0)
                                .color(egui::Color32::GRAY),
                            );
                        });

                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                // Delete button
                                if !is_active {
                                    if ui
                                        .add(
                                            egui::Button::new(
                                                egui::RichText::new("X")
                                                    .size(12.0)
                                                    .color(egui::Color32::from_rgb(200, 100, 100)),
                                            )
                                            .frame(false),
                                        )
                                        .on_hover_text("Remove profile")
                                        .clicked()
                                    {
                                        to_delete = Some(profile.name.clone());
                                    }
                                }

                                // Activate/Active button
                                if is_active {
                                    ui.label(
                                        egui::RichText::new("Active")
                                            .size(12.0)
                                            .color(egui::Color32::from_rgb(100, 200, 100)),
                                    );
                                } else if ui.small_button("Use").clicked() {
                                    to_activate = Some(profile.name.clone());
                                }
                            },
                        );
                    });
                });

            ui.add_space(4.0);
        }

        // Apply deferred mutations
        if let Some(name) = to_delete {
            state.profiles.retain(|p| p.name != name);
        }
        if let Some(name) = to_activate {
            state.active_profile = Some(name);
        }
    }
}
