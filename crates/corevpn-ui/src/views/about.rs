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
        if ui.button("←").clicked() {
            state.current_view = AppView::Settings;
        }
        ui.heading("About CoreVPN");
    });

    ui.add_space(24.0);

    ui.vertical_centered(|ui| {
        // Logo/Icon
        ui.label(egui::RichText::new("🛡️").size(64.0));
        ui.add_space(8.0);
        ui.label(egui::RichText::new("CoreVPN").size(24.0).strong());
        ui.label(egui::RichText::new("Version 0.1.0").size(13.0).color(egui::Color32::GRAY));

        ui.add_space(24.0);

        // Description
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
                    "• OAuth2/SAML SSO authentication",
                    "• Modern, clean interface",
                    "• Secure, audited cryptography",
                    "• Cross-platform support",
                ];

                for feature in features {
                    ui.label(feature);
                }
            });

        ui.add_space(20.0);

        // Links
        if ui.button("📖 Documentation").clicked() {
            // TODO: Open documentation URL
        }
        ui.add_space(4.0);
        if ui.button("🐛 Report Issue").clicked() {
            // TODO: Open issue tracker URL
        }

        ui.add_space(24.0);

        // Copyright
        ui.label(
            egui::RichText::new("© 2024 Pegasus Heavy Industries")
                .size(12.0)
                .color(egui::Color32::GRAY),
        );
    });
}
