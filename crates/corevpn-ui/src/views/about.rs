//! About View
//!
//! Application information and help.

use eframe::egui;

use crate::state::{AppState, AppView};

/// Build the about view.
pub fn about_view(ui: &mut egui::Ui, state: &mut AppState) {
    ui.add_space(8.0);

    // Header with back button
    ui.horizontal(|ui| {
        if ui.button("< Back").clicked() {
            state.current_view = AppView::Settings;
        }
        ui.heading("About CoreVPN");
    });

    ui.add_space(24.0);

    ui.vertical_centered(|ui| {
        ui.label(egui::RichText::new("CoreVPN").size(24.0).strong());
        ui.label(
            egui::RichText::new(format!("Version {}", env!("CARGO_PKG_VERSION")))
                .size(13.0)
                .color(egui::Color32::GRAY),
        );

        ui.add_space(24.0);

        egui::Frame::new()
            .fill(ui.visuals().extreme_bg_color)
            .corner_radius(8.0)
            .inner_margin(20.0)
            .show(ui, |ui| {
                ui.set_max_width(320.0);

                ui.label("A modern, secure VPN client built with Rust.");

                ui.add_space(12.0);
                ui.separator();
                ui.add_space(12.0);

                ui.label(egui::RichText::new("Features:").strong());
                ui.add_space(8.0);

                let features = [
                    "Import .ovpn profiles",
                    "OpenVPN-compatible protocol",
                    "TLS 1.3 with tls-auth support",
                    "OAuth2/SSO authentication",
                    "Secure, audited Rust cryptography",
                ];

                for feature in features {
                    ui.label(format!("  - {}", feature));
                }
            });

        ui.add_space(20.0);

        if ui
            .hyperlink_to(
                "GitHub Repository",
                "https://github.com/pegasusheavy/corevpn",
            )
            .clicked()
        {}

        ui.add_space(24.0);

        ui.label(
            egui::RichText::new("Copyright 2025 Pegasus Heavy Industries LLC")
                .size(12.0)
                .color(egui::Color32::GRAY),
        );
        ui.label(
            egui::RichText::new("pegasusheavyindustries@gmail.com")
                .size(11.0)
                .color(egui::Color32::GRAY),
        );
    });
}
