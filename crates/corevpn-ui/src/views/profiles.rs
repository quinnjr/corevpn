//! Profiles View
//!
//! VPN profile management.

use eframe::egui;

use crate::state::{AppState, AppView};

/// Build the profiles view.
pub fn profiles_view(ui: &mut egui::Ui, state: &mut AppState) {
    ui.add_space(8.0);

    // Header with back button
    ui.horizontal(|ui| {
        if ui.button("←").clicked() {
            state.current_view = AppView::Settings;
        }
        ui.heading("VPN Profiles");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .add(egui::Button::new("+ New").fill(egui::Color32::from_rgb(46, 160, 67)))
                .clicked()
            {
                // TODO: Open new profile dialog
            }
        });
    });

    ui.add_space(16.0);

    if state.profiles.is_empty() {
        // Empty state
        ui.add_space(40.0);
        ui.vertical_centered(|ui| {
            ui.label(egui::RichText::new("📋").size(48.0));
            ui.add_space(8.0);
            ui.label(egui::RichText::new("No profiles yet").size(16.0));
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("Import or create a VPN profile to get started")
                    .size(13.0)
                    .color(egui::Color32::GRAY),
            );
            ui.add_space(16.0);
            ui.horizontal(|ui| {
                if ui.button("Import .ovpn").clicked() {
                    // TODO: Open file dialog
                }
                if ui
                    .add(egui::Button::new("Create Profile").fill(egui::Color32::from_rgb(46, 160, 67)))
                    .clicked()
                {
                    // TODO: Open create profile dialog
                }
            });
        });
    } else {
        // Profile list
        let active_profile = state.active_profile.clone();
        let profiles: Vec<_> = state.profiles.iter().cloned().collect();

        for profile in &profiles {
            let is_active = active_profile.as_ref() == Some(&profile.name);

            egui::Frame::new()
                .fill(if is_active {
                    ui.visuals().selection.bg_fill
                } else {
                    ui.visuals().extreme_bg_color
                })
                .corner_radius(8.0)
                .inner_margin(16.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new(&profile.name).size(14.0).strong());
                            ui.label(
                                egui::RichText::new(profile.server.location())
                                    .size(12.0)
                                    .color(egui::Color32::GRAY),
                            );
                            ui.label(
                                egui::RichText::new(profile.auth_method.label())
                                    .size(11.0)
                                    .color(egui::Color32::GRAY),
                            );
                        });

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let button_text = if is_active { "Active" } else { "Activate" };
                            let button = if is_active {
                                egui::Button::new(button_text)
                                    .fill(egui::Color32::from_rgb(46, 160, 67))
                            } else {
                                egui::Button::new(button_text)
                            };

                            if ui.add(button).clicked() && !is_active {
                                state.active_profile = Some(profile.name.clone());
                            }
                        });
                    });
                });

            ui.add_space(8.0);
        }
    }
}
