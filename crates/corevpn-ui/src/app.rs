//! Main Application Logic
//!
//! Contains the core application struct and UI building logic using egui.

use eframe::egui;

use crate::state::{AppState, AppView};
use crate::views;

/// CoreVPN Desktop Application.
pub struct CoreVpnApp {
    /// Application state
    pub state: AppState,
}

impl CoreVpnApp {
    /// Create a new CoreVPN application instance.
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            state: AppState::new(),
        }
    }

    /// Create with existing state (for testing).
    pub fn with_state(state: AppState) -> Self {
        Self { state }
    }
}

impl eframe::App for CoreVpnApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Configure the visual style
        configure_style(ctx);

        // Top panel with header
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.add_space(16.0);
                ui.heading("🛡️ CoreVPN");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_space(16.0);
                    // Status indicator
                    let status = self.state.connection.status;
                    ui.label(egui::RichText::new(status.icon()).size(16.0));
                    ui.label(
                        egui::RichText::new(status.as_str())
                            .color(status.color())
                            .size(14.0),
                    );
                });
            });
            ui.add_space(8.0);
        });

        // Bottom panel with navigation
        egui::TopBottomPanel::bottom("navigation").show(ctx, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let current_view = self.state.current_view;

                ui.with_layout(egui::Layout::centered_and_justified(egui::Direction::LeftToRight), |ui| {
                    ui.spacing_mut().item_spacing.x = 40.0;

                    if nav_button(ui, "🏠", "Home", current_view == AppView::Connection) {
                        self.state.current_view = AppView::Connection;
                    }
                    if nav_button(ui, "📡", "Servers", current_view == AppView::ServerList) {
                        self.state.current_view = AppView::ServerList;
                    }
                    if nav_button(ui, "⚙️", "Settings", current_view == AppView::Settings) {
                        self.state.current_view = AppView::Settings;
                    }
                });
            });
            ui.add_space(8.0);
        });

        // Central panel with main content
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                match self.state.current_view {
                    AppView::Connection => views::connection_view(ui, &mut self.state),
                    AppView::ServerList => views::server_list_view(ui, &mut self.state),
                    AppView::Settings => views::settings_view(ui, &mut self.state),
                    AppView::Profiles => views::profiles_view(ui, &mut self.state),
                    AppView::Logs => views::logs_view(ui, &mut self.state),
                    AppView::About => views::about_view(ui, &mut self.state),
                }
            });
        });

        // Request repaint for animations when in transitional states
        if self.state.connection.status.is_transitioning() {
            ctx.request_repaint();
        }
    }
}

/// Configure the egui visual style for a modern VPN client look.
fn configure_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();

    // Spacing
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);

    ctx.set_style(style);
}

/// Create a navigation button.
fn nav_button(ui: &mut egui::Ui, icon: &str, label: &str, active: bool) -> bool {
    let response = ui.vertical_centered(|ui| {
        let button = if active {
            egui::Button::new(
                egui::RichText::new(icon)
                    .size(20.0)
                    .color(egui::Color32::from_rgb(100, 180, 255)),
            )
        } else {
            egui::Button::new(egui::RichText::new(icon).size(20.0))
        };

        let response = ui.add(button.frame(false));

        ui.label(
            egui::RichText::new(label)
                .size(11.0)
                .color(if active {
                    egui::Color32::from_rgb(100, 180, 255)
                } else {
                    egui::Color32::GRAY
                }),
        );

        response.clicked()
    });

    response.inner
}
