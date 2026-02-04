//! Logs View
//!
//! Connection logs display.

use eframe::egui;

use crate::state::{AppState, AppView, LogLevel};

/// Build the logs view.
pub fn logs_view(ui: &mut egui::Ui, state: &mut AppState) {
    ui.add_space(8.0);

    // Header with back button
    ui.horizontal(|ui| {
        if ui.button("←").clicked() {
            state.current_view = AppView::Settings;
        }
        ui.heading("Connection Logs");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("Clear").clicked() {
                state.clear_logs();
            }
        });
    });

    ui.add_space(12.0);

    // Log content area
    egui::Frame::new()
        .fill(ui.visuals().extreme_bg_color)
        .corner_radius(8.0)
        .inner_margin(12.0)
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .max_height(400.0)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    if state.logs.is_empty() {
                        ui.label(
                            egui::RichText::new("No logs yet")
                                .color(egui::Color32::GRAY)
                                .italics(),
                        );
                    } else {
                        for entry in &state.logs {
                            ui.horizontal(|ui| {
                                // Timestamp
                                ui.label(
                                    egui::RichText::new(entry.timestamp.format("%H:%M:%S").to_string())
                                        .size(11.0)
                                        .color(egui::Color32::GRAY)
                                        .monospace(),
                                );

                                // Level
                                ui.label(
                                    egui::RichText::new(format!("[{}]", entry.level.as_str()))
                                        .size(11.0)
                                        .color(entry.level.color())
                                        .monospace(),
                                );

                                // Message
                                ui.label(
                                    egui::RichText::new(&entry.message)
                                        .size(12.0)
                                        .monospace(),
                                );
                            });
                        }
                    }
                });
        });

    ui.add_space(12.0);

    // Log level legend
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("●").color(LogLevel::Debug.color()));
        ui.label(egui::RichText::new("Debug").size(11.0));
        ui.add_space(8.0);
        ui.label(egui::RichText::new("●").color(LogLevel::Info.color()));
        ui.label(egui::RichText::new("Info").size(11.0));
        ui.add_space(8.0);
        ui.label(egui::RichText::new("●").color(LogLevel::Warn.color()));
        ui.label(egui::RichText::new("Warn").size(11.0));
        ui.add_space(8.0);
        ui.label(egui::RichText::new("●").color(LogLevel::Error.color()));
        ui.label(egui::RichText::new("Error").size(11.0));
    });
}
