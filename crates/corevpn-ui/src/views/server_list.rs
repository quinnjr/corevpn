//! Server List View
//!
//! Displays available VPN servers for selection.

use eframe::egui;

use crate::state::{AppState, AppView};
use crate::types::VpnServer;

/// Build the server list view.
pub fn server_list_view(ui: &mut egui::Ui, state: &mut AppState) {
    ui.add_space(8.0);

    // Header with back button
    ui.horizontal(|ui| {
        if ui.button("←").clicked() {
            state.current_view = AppView::Connection;
        }
        ui.heading("Select Server");
    });

    ui.add_space(12.0);

    // Search bar
    ui.horizontal(|ui| {
        ui.label("🔍");
        ui.add(
            egui::TextEdit::singleline(&mut state.server_search)
                .hint_text("Search servers...")
                .desired_width(ui.available_width() - 30.0),
        );
    });

    ui.add_space(12.0);

    ui.separator();

    // Server list
    let filtered_servers: Vec<_> = state.filtered_servers().into_iter().cloned().collect();
    let selected_id = state.selected_server_id.clone();

    for server in &filtered_servers {
        let is_selected = selected_id.as_ref() == Some(&server.id);

        if server_row(ui, server, is_selected) {
            state.select_server(&server.id);
            state.current_view = AppView::Connection;
        }

        ui.separator();
    }

    if filtered_servers.is_empty() {
        ui.add_space(20.0);
        ui.vertical_centered(|ui| {
            ui.label(egui::RichText::new("No servers found").color(egui::Color32::GRAY));
        });
    }
}

/// Display a single server row.
fn server_row(ui: &mut egui::Ui, server: &VpnServer, is_selected: bool) -> bool {
    let response = ui.horizontal(|ui| {
        ui.set_min_height(50.0);

        // Country flag
        ui.label(egui::RichText::new(server.flag()).size(24.0));

        ui.add_space(8.0);

        // Server info
        ui.vertical(|ui| {
            ui.label(egui::RichText::new(&server.name).size(14.0));
            ui.label(
                egui::RichText::new(server.location())
                    .size(12.0)
                    .color(egui::Color32::GRAY),
            );
        });

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            // Selection indicator
            if is_selected {
                ui.label(egui::RichText::new("✓").color(egui::Color32::from_rgb(100, 180, 255)));
            }

            // SSO badge
            if server.sso_enabled {
                ui.label("🔐");
            }

            // Latency
            if let Some(latency) = server.latency {
                let color = if latency > 150 {
                    egui::Color32::RED
                } else if latency > 75 {
                    egui::Color32::YELLOW
                } else {
                    egui::Color32::GREEN
                };
                ui.label(egui::RichText::new(format!("{}ms", latency)).size(11.0).color(color));
            }

            // Load
            if let Some(load) = server.load {
                let color = if load > 80 {
                    egui::Color32::RED
                } else if load > 50 {
                    egui::Color32::YELLOW
                } else {
                    egui::Color32::GREEN
                };
                ui.label(egui::RichText::new(format!("{}%", load)).size(11.0).color(color));
            }
        });
    });

    response.response.interact(egui::Sense::click()).clicked()
}
