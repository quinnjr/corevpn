//! CoreVPN Server
//!
//! A secure, OpenVPN-compatible VPN server with OAuth2 support.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::{error, info, warn};

pub mod audit;
mod connection_log;
mod server;
mod setup;
mod webui;

use corevpn_config::ServerConfig;

#[derive(Parser)]
#[command(name = "corevpn-server")]
#[command(about = "CoreVPN - Secure OpenVPN-compatible server with OAuth2")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize and configure a new VPN server (interactive wizard)
    Setup {
        /// Data directory
        #[arg(short, long, default_value = "/var/lib/corevpn")]
        data_dir: PathBuf,

        /// Run web-based setup instead of CLI
        #[arg(long)]
        web: bool,
    },

    /// Start the VPN server
    Run {
        /// Configuration file path
        #[arg(short, long, default_value = "/etc/corevpn/config.toml")]
        config: PathBuf,

        /// Ghost mode: disable ALL connection logging (overrides config)
        /// No connection data will be stored, tracked, or persisted.
        /// Useful for privacy-focused deployments.
        #[arg(long)]
        ghost: bool,
    },

    /// Generate a client configuration
    Client {
        /// Configuration file path
        #[arg(short, long, default_value = "/etc/corevpn/config.toml")]
        config: PathBuf,

        /// Username/email for the client
        #[arg(short, long)]
        user: String,

        /// Output file (default: `<user>.ovpn`)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Show server status
    Status {
        /// Configuration file path
        #[arg(short, long, default_value = "/etc/corevpn/config.toml")]
        config: PathBuf,
    },

    /// Diagnose and fix common issues
    Doctor {
        /// Configuration file path
        #[arg(short, long, default_value = "/etc/corevpn/config.toml")]
        config: PathBuf,
    },

    /// Start the admin web interface
    ///
    /// Requires COREVPN_ADMIN_PASSWORD environment variable to be set.
    /// Username is always "admin".
    Web {
        /// Configuration file path
        #[arg(short, long, default_value = "/etc/corevpn/config.toml")]
        config: PathBuf,

        /// Web UI listen address
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        listen: SocketAddr,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install the ring crypto provider for rustls before any TLS operations
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = Cli::parse();

    match cli.command {
        Commands::Setup { data_dir, web } => {
            if web {
                setup::run_web_setup(&data_dir).await?;
            } else {
                setup::run_interactive_setup(&data_dir).await?;
            }
        }
        Commands::Run { config, ghost } => {
            let mut server_config = ServerConfig::load(&config)
                .with_context(|| format!("Failed to load config from {:?}", config))?;

            // Ghost mode: override config to disable all logging
            if ghost {
                server_config.logging.connection_mode = corevpn_config::ConnectionLogMode::None;
                warn!("🔒 Ghost mode enabled - NO connection logging");
            }

            setup_logging(&server_config);
            info!("Starting CoreVPN server...");

            server::run_server(server_config).await?;
        }
        Commands::Client {
            config,
            user,
            output,
        } => {
            let server_config = ServerConfig::load(&config)
                .with_context(|| format!("Failed to load config from {:?}", config))?;

            generate_client_config(&server_config, &user, output.as_deref())?;
        }
        Commands::Status { config } => {
            let server_config = ServerConfig::load(&config)
                .with_context(|| format!("Failed to load config from {:?}", config))?;

            show_status(&server_config).await?;
        }
        Commands::Doctor { config } => {
            let config_result = ServerConfig::load(&config);
            run_doctor(&config, config_result).await?;
        }
        Commands::Web { config, listen } => {
            let server_config = ServerConfig::load(&config)
                .with_context(|| format!("Failed to load config from {:?}", config))?;

            setup_logging(&server_config);
            run_web_ui(server_config, listen).await?;
        }
    }

    Ok(())
}

fn setup_logging(config: &ServerConfig) {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.logging.level));

    let subscriber = tracing_subscriber::registry().with(filter);

    if config.logging.format == "json" {
        subscriber.with(fmt::layer().json()).init();
    } else {
        subscriber.with(fmt::layer().pretty()).init();
    }
}

fn generate_client_config(
    config: &ServerConfig,
    username: &str,
    output: Option<&std::path::Path>,
) -> Result<()> {
    use corevpn_config::generator::ConfigGenerator;
    use corevpn_crypto::CertificateAuthority;

    println!("Generating client configuration for: {}", username);

    // Load CA
    let ca_cert =
        std::fs::read_to_string(config.ca_cert_path()).context("Failed to read CA certificate")?;
    let ca_key = std::fs::read_to_string(config.ca_key_path()).context("Failed to read CA key")?;

    let ca = CertificateAuthority::from_pem(&ca_cert, &ca_key).context("Failed to load CA")?;

    // Load tls-auth key if exists
    let ta_key = std::fs::read_to_string(config.ta_key_path()).ok();

    // Generate config
    let generator = ConfigGenerator::new(config.clone(), ca, ta_key);
    let generated = generator
        .generate_client_config(username, Some(username))
        .context("Failed to generate client config")?;

    // Write output
    let output_path = output
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(generated.filename()));

    std::fs::write(&output_path, &generated.ovpn_content).context("Failed to write config file")?;

    println!("Client configuration saved to: {:?}", output_path);
    println!("\nTo connect:");
    println!("  1. Copy this file to your device");
    println!("  2. Import into your OpenVPN client");
    println!("  3. Connect!");

    Ok(())
}

async fn show_status(config: &ServerConfig) -> Result<()> {
    println!("CoreVPN Server Status");
    println!("=====================");
    println!();
    println!("Configuration:");
    println!("  Public Host: {}", config.server.public_host);
    println!("  Listen Address: {}", config.server.listen_addr);
    println!("  Protocol: {}", config.server.protocol);
    println!("  Max Clients: {}", config.server.max_clients);
    println!();
    println!("Network:");
    println!("  Subnet: {}", config.network.subnet);
    println!("  DNS: {:?}", config.network.dns);
    println!("  Full Tunnel: {}", config.network.redirect_gateway);
    println!();
    println!("Security:");
    println!("  Cipher: {}", config.security.cipher);
    println!("  TLS Version: {}", config.security.tls_min_version);
    println!("  TLS Auth: {}", config.security.tls_auth);
    println!("  PFS: {}", config.security.pfs);
    println!();

    if let Some(oauth) = &config.oauth {
        println!("OAuth2:");
        println!("  Enabled: {}", oauth.enabled);
        println!("  Provider: {}", oauth.provider);
        if !oauth.allowed_domains.is_empty() {
            println!("  Allowed Domains: {:?}", oauth.allowed_domains);
        }
    }

    // Check if server is running (simplified check)
    println!();
    println!("Status: Configuration OK");

    Ok(())
}

async fn run_web_ui(config: ServerConfig, listen: SocketAddr) -> Result<()> {
    use corevpn_core::SessionManager;

    info!("Starting CoreVPN Web UI...");

    // Check if admin password is configured
    if !webui::is_auth_configured() {
        error!(
            "Admin password not configured! Set {} environment variable.",
            webui::ADMIN_PASSWORD_ENV
        );
        error!(
            "Example: export {}=\"your-secure-password\"",
            webui::ADMIN_PASSWORD_ENV
        );
        anyhow::bail!(
            "Admin password required. Set {} environment variable.",
            webui::ADMIN_PASSWORD_ENV
        );
    }

    info!("Dashboard: http://{}", listen);
    info!("Username: {}", webui::ADMIN_USERNAME);
    info!("Password: (from {} env var)", webui::ADMIN_PASSWORD_ENV);

    // Create session manager for the web UI
    let session_manager = SessionManager::new(
        config.server.max_clients as usize,
        chrono::Duration::hours(24),
    );

    // Create web UI state
    let state = webui::WebUiState::new(config, session_manager);

    // Create router
    let app = webui::create_router(state);

    // Start server
    let listener = tokio::net::TcpListener::bind(listen).await?;
    info!("Web UI listening on {}", listen);

    axum::serve(listener, app).await?;

    Ok(())
}

async fn run_doctor(
    _config_path: &std::path::Path,
    config_result: Result<ServerConfig, corevpn_config::ConfigError>,
) -> Result<()> {
    use console::{Emoji, style};

    static CHECK: Emoji<'_, '_> = Emoji("✅ ", "[OK] ");
    static CROSS: Emoji<'_, '_> = Emoji("❌ ", "[FAIL] ");
    static WARN: Emoji<'_, '_> = Emoji("⚠️  ", "[WARN] ");

    println!("CoreVPN Doctor");
    println!("==============");
    println!();

    let mut issues = Vec::new();

    // Check config file
    print!("Checking configuration file... ");
    match &config_result {
        Ok(_) => println!("{} Configuration valid", CHECK),
        Err(e) => {
            println!("{} {}", CROSS, e);
            issues.push(format!("Fix configuration: {}", e));
        }
    }

    // Check data directory
    if let Ok(config) = &config_result {
        let data_dir = config.data_dir();

        print!("Checking data directory... ");
        if data_dir.exists() {
            println!("{} {:?} exists", CHECK, data_dir);
        } else {
            println!("{} {:?} not found", CROSS, data_dir);
            issues.push(format!("Create data directory: mkdir -p {:?}", data_dir));
        }

        // Check certificates
        print!("Checking CA certificate... ");
        if config.ca_cert_path().exists() {
            println!("{} Found", CHECK);
        } else {
            println!("{} Not found", CROSS);
            issues.push("Run 'corevpn-server setup' to initialize PKI".to_string());
        }

        print!("Checking server certificate... ");
        if config.server_cert_path().exists() {
            println!("{} Found", CHECK);
        } else {
            println!("{} Not found", CROSS);
            issues.push("Server certificate missing".to_string());
        }

        print!("Checking TLS auth key... ");
        if config.ta_key_path().exists() {
            println!("{} Found", CHECK);
        } else if config.security.tls_auth {
            println!("{} Not found (tls_auth enabled)", WARN);
            issues.push("TLS auth key missing but tls_auth is enabled".to_string());
        } else {
            println!("{} Not required", CHECK);
        }

        // Check network
        print!("Checking network configuration... ");
        if config.network.subnet.parse::<ipnet::Ipv4Net>().is_ok() {
            println!("{} Subnet valid", CHECK);
        } else {
            println!("{} Invalid subnet: {}", CROSS, config.network.subnet);
            issues.push("Fix subnet in configuration".to_string());
        }

        // Check port availability
        print!("Checking port {}... ", config.server.listen_addr.port());
        match std::net::UdpSocket::bind(config.server.listen_addr) {
            Ok(_) => println!("{} Available", CHECK),
            Err(e) => {
                println!("{} {}", WARN, e);
                issues.push(format!(
                    "Port {} may be in use or require root",
                    config.server.listen_addr.port()
                ));
            }
        }
    }

    println!();

    if issues.is_empty() {
        println!("{} All checks passed!", style("SUCCESS").green().bold());
    } else {
        println!(
            "{} Found {} issue(s):",
            style("ISSUES").yellow().bold(),
            issues.len()
        );
        for (i, issue) in issues.iter().enumerate() {
            println!("  {}. {}", i + 1, issue);
        }
    }

    Ok(())
}
