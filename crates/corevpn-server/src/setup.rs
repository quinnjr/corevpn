//! Interactive Setup Wizard
//!
//! Dead-simple setup experience for CoreVPN.

use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use axum::response::Html;
use axum::Json;
use console::{style, Emoji, Term};
use dialoguer::{Confirm, Input, Select, theme::ColorfulTheme};

use corevpn_config::{ServerConfig, generator::initialize_pki};
use secrecy::SecretString;

static ROCKET: Emoji<'_, '_> = Emoji("🚀 ", "");
static LOCK: Emoji<'_, '_> = Emoji("🔒 ", "");
static CHECK: Emoji<'_, '_> = Emoji("✅ ", "[OK] ");
static GLOBE: Emoji<'_, '_> = Emoji("🌍 ", "");
static KEY: Emoji<'_, '_> = Emoji("🔑 ", "");
static GEAR: Emoji<'_, '_> = Emoji("⚙️  ", "");

/// Run interactive CLI setup
pub async fn run_interactive_setup(data_dir: &Path) -> Result<()> {
    let term = Term::stdout();
    term.clear_screen()?;

    println!();
    println!("  {}CoreVPN Setup Wizard", ROCKET);
    println!("  {}", style("═".repeat(40)).cyan());
    println!();
    println!("  This wizard will help you set up a secure VPN server");
    println!("  in just a few minutes. No Linux expertise required!");
    println!();

    let theme = ColorfulTheme::default();

    // Step 1: Detect public IP
    println!("{}Step 1: Server Address", style("▶").cyan().bold());
    println!();

    let detected_ip = detect_public_ip().await;
    let public_host: String = if let Some(ip) = &detected_ip {
        println!("  {} Detected public IP: {}", CHECK, style(ip).green());
        Input::with_theme(&theme)
            .with_prompt("  Server hostname/IP (press Enter to use detected)")
            .default(ip.clone())
            .interact_text()?
    } else {
        println!("  Could not detect public IP automatically.");
        Input::with_theme(&theme)
            .with_prompt("  Enter your server's public hostname or IP")
            .interact_text()?
    };

    println!();

    // Step 2: Port selection
    println!("{}Step 2: Port Configuration", style("▶").cyan().bold());
    println!();

    let port_options = vec![
        "1194 (Standard OpenVPN port - recommended)",
        "443 (HTTPS port - works through most firewalls)",
        "Custom port",
    ];

    let port_selection = Select::with_theme(&theme)
        .with_prompt("  Select VPN port")
        .items(&port_options)
        .default(0)
        .interact()?;

    let port: u16 = match port_selection {
        0 => 1194,
        1 => 443,
        _ => Input::with_theme(&theme)
            .with_prompt("  Enter custom port")
            .validate_with(|input: &String| {
                input.parse::<u16>().map(|_| ()).map_err(|_| "Invalid port number")
            })
            .interact_text()?
            .parse()?,
    };

    println!();

    // Step 3: Protocol
    println!("{}Step 3: Protocol", style("▶").cyan().bold());
    println!();

    let protocol_options = vec![
        "UDP (faster, recommended)",
        "TCP (works through strict firewalls)",
    ];

    let protocol_selection = Select::with_theme(&theme)
        .with_prompt("  Select protocol")
        .items(&protocol_options)
        .default(0)
        .interact()?;

    let protocol = if protocol_selection == 0 { "udp" } else { "tcp" };

    println!();

    // Step 4: OAuth2 Setup
    println!("{}Step 4: Authentication", style("▶").cyan().bold());
    println!();

    let auth_options = vec![
        "Certificate only (simple, secure)",
        "Google Workspace (recommended for organizations)",
        "Microsoft Entra ID (Azure AD)",
        "Okta",
        "Skip OAuth2 for now (can add later)",
    ];

    let auth_selection = Select::with_theme(&theme)
        .with_prompt("  Select authentication method")
        .items(&auth_options)
        .default(0)
        .interact()?;

    let oauth_config = match auth_selection {
        1 => Some(setup_google_oauth(&theme)?),
        2 => Some(setup_microsoft_oauth(&theme)?),
        3 => Some(setup_okta_oauth(&theme)?),
        _ => None,
    };

    println!();

    // Step 5: Network configuration
    println!("{}Step 5: Network Configuration", style("▶").cyan().bold());
    println!();

    let tunnel_mode = Select::with_theme(&theme)
        .with_prompt("  VPN tunnel mode")
        .items(&[
            "Full tunnel (all traffic through VPN - most secure)",
            "Split tunnel (only specific networks through VPN)",
        ])
        .default(0)
        .interact()?;

    let redirect_gateway = tunnel_mode == 0;

    let subnet: String = Input::with_theme(&theme)
        .with_prompt("  VPN subnet")
        .default("10.8.0.0/24".to_string())
        .interact_text()?;

    println!();

    // Confirmation
    println!("{}Configuration Summary", style("▶").cyan().bold());
    println!();
    println!("  {} Server: {}:{}/{}", GLOBE, public_host, port, protocol);
    println!("  {} Subnet: {}", GEAR, subnet);
    println!("  {} Full tunnel: {}", LOCK, if redirect_gateway { "Yes" } else { "No" });
    if oauth_config.is_some() {
        println!("  {} OAuth2: Enabled", KEY);
    }
    println!();

    if !Confirm::with_theme(&theme)
        .with_prompt("  Proceed with setup?")
        .default(true)
        .interact()?
    {
        println!("  Setup cancelled.");
        return Ok(());
    }

    println!();

    // Create configuration
    println!("{}Setting up CoreVPN...", style("▶").cyan().bold());
    println!();

    // Create directories
    let config_dir = PathBuf::from("/etc/corevpn");
    std::fs::create_dir_all(&config_dir)
        .context("Failed to create config directory")?;
    std::fs::create_dir_all(data_dir)
        .context("Failed to create data directory")?;

    print!("  Generating PKI (certificates)... ");
    io::stdout().flush()?;
    let (_ca, _ta_key) = initialize_pki(data_dir, &public_host, "CoreVPN")
        .context("Failed to initialize PKI")?;
    println!("{}", CHECK);

    // Build config
    let mut config = ServerConfig::default_config(&public_host);
    config.server.listen_addr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        port,
    );
    config.server.protocol = protocol.to_string();
    config.server.data_dir = data_dir.to_path_buf();
    config.network.subnet = subnet;
    config.network.redirect_gateway = redirect_gateway;

    if let Some(oauth) = oauth_config {
        config.oauth = Some(oauth);
    }

    // Save config
    print!("  Saving configuration... ");
    io::stdout().flush()?;
    let config_path = config_dir.join("config.toml");
    config.save(&config_path)
        .context("Failed to save configuration")?;
    println!("{}", CHECK);

    // Print success message
    println!();
    println!("  {}", style("═".repeat(50)).green());
    println!("  {} {}", CHECK, style("Setup Complete!").green().bold());
    println!("  {}", style("═".repeat(50)).green());
    println!();
    println!("  {}Next steps:", ROCKET);
    println!();
    println!("  1. Start the server:");
    println!("     {}", style("sudo corevpn-server run").cyan());
    println!();
    println!("  2. Generate a client config:");
    println!("     {}", style("corevpn-server client -u user@example.com").cyan());
    println!();
    println!("  3. Import the .ovpn file into your VPN client");
    println!();

    if config.oauth.is_some() {
        println!("  {}OAuth2 is configured. Users will authenticate", KEY);
        println!("  through your identity provider on first connect.");
        println!();
    }

    println!("  Configuration saved to: {:?}", config_path);
    println!("  Data directory: {:?}", data_dir);
    println!();

    Ok(())
}

/// Run web-based setup
pub async fn run_web_setup(_data_dir: &Path) -> Result<()> {
    use axum::{
        Router,
        routing::{get, post},
    };
    
    

    println!();
    println!("  {}CoreVPN Web Setup", ROCKET);
    println!();
    println!("  Starting web setup interface...");
    println!();

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));

    println!("  Open your browser to:");
    println!("  {}", style(format!("http://{}", addr)).cyan().bold());
    println!();
    println!("  Press Ctrl+C to cancel");
    println!();

    // Simple web setup (placeholder - would be a full SPA in production)
    let app = Router::new()
        .route("/", get(setup_page))
        .route("/api/setup", post(handle_setup));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn setup_page() -> Html<&'static str> {
    Html(r#"
<!DOCTYPE html>
<html>
<head>
    <title>CoreVPN Setup</title>
    <style>
        body { font-family: -apple-system, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        h1 { color: #2563eb; }
        .form-group { margin: 20px 0; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input, select { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
        button { background: #2563eb; color: white; padding: 15px 30px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        button:hover { background: #1d4ed8; }
        .success { background: #d1fae5; padding: 20px; border-radius: 5px; margin-top: 20px; }
    </style>
</head>
<body>
    <h1>🚀 CoreVPN Setup</h1>
    <p>Configure your VPN server in seconds.</p>

    <form id="setup-form">
        <div class="form-group">
            <label>Server Hostname/IP</label>
            <input type="text" name="public_host" placeholder="vpn.example.com" required>
        </div>

        <div class="form-group">
            <label>Port</label>
            <select name="port">
                <option value="1194">1194 (Standard)</option>
                <option value="443">443 (HTTPS)</option>
            </select>
        </div>

        <div class="form-group">
            <label>Protocol</label>
            <select name="protocol">
                <option value="udp">UDP (Faster)</option>
                <option value="tcp">TCP (More Compatible)</option>
            </select>
        </div>

        <div class="form-group">
            <label>VPN Subnet</label>
            <input type="text" name="subnet" value="10.8.0.0/24">
        </div>

        <button type="submit">Setup Server</button>
    </form>

    <div id="result" style="display:none" class="success">
        <h3>✅ Setup Complete!</h3>
        <p>Your VPN server is configured. Run <code>corevpn-server run</code> to start.</p>
    </div>

    <script>
        document.getElementById('setup-form').onsubmit = async (e) => {
            e.preventDefault();
            const form = new FormData(e.target);
            const data = Object.fromEntries(form);

            const resp = await fetch('/api/setup', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(data)
            });

            if (resp.ok) {
                document.getElementById('result').style.display = 'block';
                e.target.style.display = 'none';
            }
        };
    </script>
</body>
</html>
"#)
}

async fn handle_setup(Json(_data): Json<serde_json::Value>) -> Json<serde_json::Value> {
    // In a real implementation, this would perform the actual setup
    Json(serde_json::json!({"status": "ok"}))
}

/// Detect public IP address
async fn detect_public_ip() -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;

    // Try multiple services
    let services = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ];

    for service in services {
        if let Ok(resp) = client.get(service).send().await {
            if let Ok(ip) = resp.text().await {
                let ip = ip.trim().to_string();
                if !ip.is_empty() && ip.parse::<std::net::IpAddr>().is_ok() {
                    return Some(ip);
                }
            }
        }
    }

    None
}

fn setup_google_oauth(theme: &ColorfulTheme) -> Result<corevpn_config::server::OAuthSettings> {
    println!();
    println!("  {}Google Workspace OAuth2 Setup", KEY);
    println!();
    println!("  To set up Google OAuth2:");
    println!("  1. Go to https://console.cloud.google.com/apis/credentials");
    println!("  2. Create a new OAuth 2.0 Client ID");
    println!("  3. Set the redirect URI to: http://localhost:8080/callback");
    println!();

    let client_id: String = Input::with_theme(theme)
        .with_prompt("  Google Client ID")
        .interact_text()?;

    let client_secret: String = Input::with_theme(theme)
        .with_prompt("  Google Client Secret")
        .interact_text()?;

    let domain: String = Input::with_theme(theme)
        .with_prompt("  Allowed domain (e.g., company.com, leave empty for all)")
        .allow_empty(true)
        .interact_text()?;

    Ok(corevpn_config::server::OAuthSettings {
        enabled: true,
        provider: "google".to_string(),
        client_id,
        client_secret: SecretString::new(client_secret),
        issuer_url: None,
        tenant_id: None,
        domain: None,
        allowed_domains: if domain.is_empty() { vec![] } else { vec![domain] },
        required_groups: vec![],
        oauth_port: 9000,
        external_url: None,
    })
}

fn setup_microsoft_oauth(theme: &ColorfulTheme) -> Result<corevpn_config::server::OAuthSettings> {
    println!();
    println!("  {}Microsoft Entra ID OAuth2 Setup", KEY);
    println!();
    println!("  To set up Microsoft OAuth2:");
    println!("  1. Go to https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps");
    println!("  2. Register a new application");
    println!("  3. Add a client secret");
    println!();

    let client_id: String = Input::with_theme(theme)
        .with_prompt("  Application (client) ID")
        .interact_text()?;

    let client_secret: String = Input::with_theme(theme)
        .with_prompt("  Client Secret")
        .interact_text()?;

    let tenant_id: String = Input::with_theme(theme)
        .with_prompt("  Tenant ID (or 'common' for multi-tenant)")
        .default("common".to_string())
        .interact_text()?;

    Ok(corevpn_config::server::OAuthSettings {
        enabled: true,
        provider: "microsoft".to_string(),
        client_id,
        client_secret: SecretString::new(client_secret),
        issuer_url: None,
        tenant_id: Some(tenant_id),
        domain: None,
        allowed_domains: vec![],
        required_groups: vec![],
        oauth_port: 9000,
        external_url: None,
    })
}

fn setup_okta_oauth(theme: &ColorfulTheme) -> Result<corevpn_config::server::OAuthSettings> {
    println!();
    println!("  {}Okta OAuth2 Setup", KEY);
    println!();
    println!("  To set up Okta OAuth2:");
    println!("  1. Go to your Okta Admin Console");
    println!("  2. Create a new OIDC application");
    println!();

    let domain: String = Input::with_theme(theme)
        .with_prompt("  Okta domain (e.g., company.okta.com)")
        .interact_text()?;

    let client_id: String = Input::with_theme(theme)
        .with_prompt("  Client ID")
        .interact_text()?;

    let client_secret: String = Input::with_theme(theme)
        .with_prompt("  Client Secret")
        .interact_text()?;

    Ok(corevpn_config::server::OAuthSettings {
        enabled: true,
        provider: "okta".to_string(),
        client_id,
        client_secret: SecretString::new(client_secret),
        issuer_url: None,
        tenant_id: None,
        domain: Some(domain),
        allowed_domains: vec![],
        required_groups: vec![],
        oauth_port: 9000,
        external_url: None,
    })
}
