//! Settings View
//!
//! Application settings and preferences.

use eframe::egui;

use crate::state::{AppState, AppView};
use crate::types::AuthMethod;

/// Build the settings view.
pub fn settings_view(ui: &mut egui::Ui, state: &mut AppState) {
    ui.add_space(8.0);

    // Header with back button
    ui.horizontal(|ui| {
        if ui.button("←").clicked() {
            state.current_view = AppView::Connection;
        }
        ui.heading("Settings");
    });

    ui.add_space(16.0);

    // Authentication Section
    ui.label(egui::RichText::new("Authentication").size(14.0).strong());
    ui.add_space(8.0);

    egui::Frame::new()
        .fill(ui.visuals().extreme_bg_color)
        .corner_radius(8.0)
        .inner_margin(16.0)
        .show(ui, |ui| {
            // OAuth2/SSO toggle
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label("OAuth2/SSO");
                    ui.label(
                        egui::RichText::new("Sign in with your organization")
                            .size(11.0)
                            .color(egui::Color32::GRAY),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let mut oauth_enabled = state.auth_method == AuthMethod::OAuth2;
                    if ui.add(egui::Checkbox::without_text(&mut oauth_enabled)).changed() {
                        if oauth_enabled {
                            state.auth_method = AuthMethod::OAuth2;
                        }
                    }
                });
            });

            ui.separator();

            // Username/Password toggle
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label("Username/Password");
                    ui.label(
                        egui::RichText::new("Traditional credentials")
                            .size(11.0)
                            .color(egui::Color32::GRAY),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let mut password_enabled = state.auth_method == AuthMethod::UsernamePassword;
                    if ui
                        .add(egui::Checkbox::without_text(&mut password_enabled))
                        .changed()
                    {
                        if password_enabled {
                            state.auth_method = AuthMethod::UsernamePassword;
                        }
                    }
                });
            });

            ui.separator();

            // Remember credentials toggle
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label("Remember Credentials");
                    ui.label(
                        egui::RichText::new("Save login information")
                            .size(11.0)
                            .color(egui::Color32::GRAY),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_enabled(
                        state.auth_method == AuthMethod::UsernamePassword,
                        egui::Checkbox::without_text(&mut state.remember_credentials),
                    );
                });
            });
        });

    ui.add_space(20.0);

    // Connection Section
    ui.label(egui::RichText::new("Connection").size(14.0).strong());
    ui.add_space(8.0);

    egui::Frame::new()
        .fill(ui.visuals().extreme_bg_color)
        .corner_radius(8.0)
        .inner_margin(16.0)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label("Auto-Connect");
                    ui.label(
                        egui::RichText::new("Connect when app starts")
                            .size(11.0)
                            .color(egui::Color32::GRAY),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.checkbox(&mut state.auto_connect, "");
                });
            });
        });

    ui.add_space(20.0);

    // Notifications Section
    ui.label(egui::RichText::new("Notifications").size(14.0).strong());
    ui.add_space(8.0);

    egui::Frame::new()
        .fill(ui.visuals().extreme_bg_color)
        .corner_radius(8.0)
        .inner_margin(16.0)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label("Show Notifications");
                    ui.label(
                        egui::RichText::new("Connection status alerts")
                            .size(11.0)
                            .color(egui::Color32::GRAY),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.checkbox(&mut state.show_notifications, "");
                });
            });
        });

    ui.add_space(20.0);

    // Additional navigation
    ui.horizontal(|ui| {
        if ui.button("📋 Profiles").clicked() {
            state.current_view = AppView::Profiles;
        }
        if ui.button("📜 Logs").clicked() {
            state.current_view = AppView::Logs;
        }
        if ui.button("ℹ️ About").clicked() {
            state.current_view = AppView::About;
        }
    });
}
