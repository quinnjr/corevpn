//! CoreVPN Desktop Application Entry Point
//!
//! This is the main entry point for the CoreVPN desktop application.

use eframe::egui;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use corevpn_ui::CoreVpnApp;

fn main() -> eframe::Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "corevpn_ui=info,eframe=warn,egui=warn".into()),
        )
        .init();

    tracing::info!("Starting CoreVPN Desktop Client");

    // Configure the native window
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([420.0, 680.0])
            .with_min_inner_size([380.0, 500.0])
            .with_title("CoreVPN"),
        ..Default::default()
    };

    // Run the application
    eframe::run_native(
        "CoreVPN",
        options,
        Box::new(|cc| Ok(Box::new(CoreVpnApp::new(cc)))),
    )
}
