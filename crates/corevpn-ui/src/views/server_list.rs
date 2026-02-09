//! Server List View
//!
//! Placeholder - profiles view replaces direct server selection.

use eframe::egui;

use crate::state::{AppState, AppView};

/// Build the server list view (redirects to profiles).
pub fn server_list_view(ui: &mut egui::Ui, state: &mut AppState) {
    ui.add_space(8.0);
    ui.vertical_centered(|ui| {
        ui.label("Server selection is managed through VPN profiles.");
        ui.add_space(8.0);
        if ui.button("Go to Profiles").clicked() {
            state.current_view = AppView::Profiles;
        }
    });
}
