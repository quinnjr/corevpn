//! Settings View
//!
//! Application settings and preferences.

use eframe::egui;

use crate::state::{AppState, AppView};

/// Build the settings view.
pub fn settings_view(ui: &mut egui::Ui, state: &mut AppState) {
    ui.add_space(8.0);

    // Header with back button
    ui.horizontal(|ui| {
        if ui.button("< Back").clicked() {
            state.current_view = AppView::Connection;
        }
        ui.heading("Settings");
    });

    ui.add_space(16.0);

    // Connection Section
    ui.label(egui::RichText::new("Connection").size(14.0).strong());
    ui.add_space(8.0);

    egui::Frame::new()
        .fill(ui.visuals().extreme_bg_color)
        .corner_radius(8.0)
        .inner_margin(16.0)
        .show(ui, |ui| {
            setting_row(
                ui,
                "Auto-Connect",
                "Connect when app starts",
                &mut state.auto_connect,
            );

            ui.separator();

            setting_row(
                ui,
                "Remember Credentials",
                "Save login information",
                &mut state.remember_credentials,
            );
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
            setting_row(
                ui,
                "Show Notifications",
                "Connection status alerts",
                &mut state.show_notifications,
            );
        });

    ui.add_space(20.0);

    // Navigation links
    ui.horizontal(|ui| {
        if ui.button("Connection Logs").clicked() {
            state.current_view = AppView::Logs;
        }
        if ui.button("About").clicked() {
            state.current_view = AppView::About;
        }
    });
}

/// A single settings row with a toggle.
fn setting_row(ui: &mut egui::Ui, title: &str, description: &str, value: &mut bool) {
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(title);
            ui.label(
                egui::RichText::new(description)
                    .size(11.0)
                    .color(egui::Color32::GRAY),
            );
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.checkbox(value, "");
        });
    });
}
