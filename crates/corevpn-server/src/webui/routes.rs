//! Web UI Routes
//!
//! HTTP handlers for the admin web interface.
//! All routes are protected by HTTP Basic Authentication.

use axum::{
    Router,
    middleware,
    routing::{get, post},
    response::{Html, IntoResponse, Redirect, Response},
    extract::{State, Path, Form},
    http::StatusCode,
};
use serde::Deserialize;

use super::auth;
use super::csrf;
use super::state::WebUiState;
use super::templates;
use axum::extract::Request;
use axum::http::header;
use axum::middleware::Next;

/// Create the web UI router with authentication
pub fn create_router(state: WebUiState) -> Router {
    // Protected admin routes
    let admin_routes = Router::new()
        // Dashboard
        .route("/", get(dashboard))
        .route("/admin", get(dashboard))
        .route("/admin/", get(dashboard))

        // Clients
        .route("/admin/clients", get(clients_list))
        .route("/admin/clients/", get(clients_list))
        .route("/admin/clients/new", get(new_client_form))
        .route("/admin/clients", post(create_client))
        .route("/admin/clients/:id/download", get(download_client_config))
        .route("/admin/clients/:id/download/mobile", get(download_client_config_mobile))
        .route("/admin/clients/:id/revoke", post(revoke_client))
        .route("/admin/clients/quick-generate", get(quick_generate_form))
        .route("/admin/clients/quick-generate", post(quick_generate_download))

        // Sessions
        .route("/admin/sessions", get(sessions_list))
        .route("/admin/sessions/", get(sessions_list))
        .route("/admin/sessions/:id/disconnect", post(disconnect_session))
        .route("/admin/sessions/disconnect-all", post(disconnect_all_sessions))

        // Settings
        .route("/admin/settings", get(settings_page))
        .route("/admin/settings/", get(settings_page))

        // Apply authentication middleware to all admin routes
        .layer(middleware::from_fn(auth::require_auth))
        .layer(middleware::from_fn(csrf_middleware))
        .layer(middleware::from_fn(csp_middleware))
        .with_state(state);

    // Combine with fallback (fallback doesn't need auth)
    admin_routes.fallback(not_found)
}

// ============================================================================
// Route Handlers
// ============================================================================

async fn dashboard(State(state): State<WebUiState>) -> Html<String> {
    let config = &state.config;
    let uptime = state.uptime();

    // Get stats from session manager
    let (active_clients, total_sessions) = {
        let sessions = state.session_manager.read();
        (sessions.active_sessions().len() as u32, sessions.session_count() as u64)
    };

    let html = templates::dashboard(
        &uptime,
        active_clients,
        total_sessions,
        0, // bytes_rx - would come from metrics
        0, // bytes_tx
        &config.server.public_host,
        config.server.listen_addr.port(),
        &config.server.protocol,
        &config.network.subnet,
    );

    Html(html)
}

async fn clients_list(State(state): State<WebUiState>) -> Html<String> {
    // In a real implementation, this would fetch from the database
    // For now, show empty list
    let clients: Vec<templates::ClientInfo> = vec![];
    
    // Generate CSRF token for forms
    let session_id = get_session_id_from_state(&state);
    let csrf_token = csrf::generate_token(&session_id);

    Html(templates::clients_list(&clients, &csrf_token))
}

async fn new_client_form(State(state): State<WebUiState>) -> Html<String> {
    // Generate CSRF token for this session
    let session_id = get_session_id_from_state(&state);
    let csrf_token = csrf::generate_token(&session_id);
    Html(templates::new_client(&csrf_token))
}

#[derive(Deserialize)]
struct CreateClientForm {
    name: String,
    email: String,
    #[serde(default = "default_expires")]
    expires: u32,
    csrf_token: String,
}

fn default_expires() -> u32 {
    365
}

async fn create_client(
    State(state): State<WebUiState>,
    Form(form): Form<CreateClientForm>,
) -> Response {
    // Validate CSRF token
    let session_id = get_session_id_from_state(&state);
    if !csrf::validate_token(&session_id, &form.csrf_token) {
        return error_response(403, "Invalid CSRF token");
    }

    // Validate and sanitize input
    let name = sanitize_filename(&form.name);
    let email = sanitize_email(&form.email);
    
    if name.is_empty() || name.len() > 64 {
        return error_response(400, "Invalid client name");
    }

    use corevpn_config::generator::ConfigGenerator;
    use corevpn_crypto::CertificateAuthority;

    // Load CA
    let ca_cert = match std::fs::read_to_string(state.config.ca_cert_path()) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to read CA cert: {}", e);
            return error_response(500, "Failed to read CA certificate");
        }
    };
    let ca_key = match std::fs::read_to_string(state.config.ca_key_path()) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("Failed to read CA key: {}", e);
            return error_response(500, "Failed to read CA key");
        }
    };

    let ca = match CertificateAuthority::from_pem(&ca_cert, &ca_key) {
        Ok(ca) => ca,
        Err(e) => {
            tracing::error!("Failed to load CA: {}", e);
            return error_response(500, "Failed to load CA");
        }
    };

    // Load tls-auth key
    let ta_key = std::fs::read_to_string(state.config.ta_key_path()).ok();

    // Generate config
    let config = (*state.config).clone();
    let generator = ConfigGenerator::new(config, ca, ta_key);

    let generated = match generator.generate_client_config(&name, Some(&email)) {
        Ok(g) => g,
        Err(e) => {
            tracing::error!("Failed to generate config: {}", e);
            return error_response(500, "Failed to generate configuration");
        }
    };

    let filename = sanitize_filename_for_download(&generated.filename());
    let ovpn_content = generated.ovpn_content;

    // Show download page with auto-download and config preview
    let html = templates::client_download(&name, &filename, &ovpn_content);
    Html(html).into_response()
}

async fn download_client_config(
    State(state): State<WebUiState>,
    Path(id): Path<String>,
) -> Response {
    // Validate and sanitize path parameter
    let id = sanitize_path_param(&id);
    if id.is_empty() || id.len() > 64 {
        return error_response(400, "Invalid client ID");
    }

    use corevpn_config::generator::ConfigGenerator;
    use corevpn_crypto::CertificateAuthority;
    use axum::http::header;

    // Load CA
    let ca_cert = match std::fs::read_to_string(state.config.ca_cert_path()) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to read CA cert: {}", e);
            return error_response(500, "Failed to read CA certificate");
        }
    };
    let ca_key = match std::fs::read_to_string(state.config.ca_key_path()) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("Failed to read CA key: {}", e);
            return error_response(500, "Failed to read CA key");
        }
    };

    let ca = match CertificateAuthority::from_pem(&ca_cert, &ca_key) {
        Ok(ca) => ca,
        Err(e) => {
            tracing::error!("Failed to load CA: {}", e);
            return error_response(500, "Failed to load CA");
        }
    };

    let ta_key = std::fs::read_to_string(state.config.ta_key_path()).ok();

    let config = (*state.config).clone();
    let generator = ConfigGenerator::new(config, ca, ta_key);

    let generated = match generator.generate_client_config(&id, Some(&id)) {
        Ok(g) => g,
        Err(e) => {
            tracing::error!("Failed to generate config: {}", e);
            return error_response(500, "Failed to generate configuration");
        }
    };

    let filename = sanitize_filename_for_download(&generated.filename());
    let content = generated.ovpn_content;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-openvpn-profile")
        .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", filename))
        .body(content.into())
        .unwrap_or_else(|_| error_response(500, "Failed to build response"))
}

#[derive(Deserialize)]
struct RevokeClientForm {
    csrf_token: String,
}

async fn revoke_client(
    State(state): State<WebUiState>,
    Path(id): Path<String>,
    Form(form): Form<RevokeClientForm>,
) -> Redirect {
    // Validate CSRF token
    let session_id = get_session_id_from_state(&state);
    if !csrf::validate_token(&session_id, &form.csrf_token) {
        return Redirect::to("/admin/clients?error=csrf");
    }

    // Validate path parameter
    let id = sanitize_path_param(&id);
    if id.is_empty() {
        return Redirect::to("/admin/clients?error=invalid_id");
    }

    // In a real implementation, this would revoke the client certificate
    // For now, just redirect back
    Redirect::to("/admin/clients")
}

/// Download mobile-optimized client config
async fn download_client_config_mobile(
    State(state): State<WebUiState>,
    Path(id): Path<String>,
) -> Response {
    // Validate and sanitize path parameter
    let id = sanitize_path_param(&id);
    if id.is_empty() || id.len() > 64 {
        return error_response(400, "Invalid client ID");
    }

    use corevpn_config::generator::ConfigGenerator;
    use corevpn_crypto::CertificateAuthority;
    use axum::http::header;

    // Load CA
    let ca_cert = match std::fs::read_to_string(state.config.ca_cert_path()) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to read CA cert: {}", e);
            return error_response(500, "Failed to read CA certificate");
        }
    };
    let ca_key = match std::fs::read_to_string(state.config.ca_key_path()) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("Failed to read CA key: {}", e);
            return error_response(500, "Failed to read CA key");
        }
    };

    let ca = match CertificateAuthority::from_pem(&ca_cert, &ca_key) {
        Ok(ca) => ca,
        Err(e) => {
            tracing::error!("Failed to load CA: {}", e);
            return error_response(500, "Failed to load CA");
        }
    };

    let ta_key = std::fs::read_to_string(state.config.ta_key_path()).ok();

    let config = (*state.config).clone();
    let generator = ConfigGenerator::new(config, ca, ta_key);

    // Generate mobile-optimized config
    let generated = match generator.generate_mobile_config(&id, Some(&id)) {
        Ok(g) => g,
        Err(e) => {
            tracing::error!("Failed to generate mobile config: {}", e);
            return error_response(500, "Failed to generate configuration");
        }
    };

    let safe_id = id.replace(['@', '.', ' '], "_");
    let filename = sanitize_filename_for_download(&format!("{}-mobile.ovpn", safe_id));
    let content = generated.ovpn_content;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-openvpn-profile")
        .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", filename))
        .body(content.into())
        .unwrap_or_else(|_| error_response(500, "Failed to build response"))
}

/// Quick generate form - simple one-field form for fast config generation
async fn quick_generate_form(State(state): State<WebUiState>) -> Html<String> {
    let session_id = get_session_id_from_state(&state);
    let csrf_token = csrf::generate_token(&session_id);
    Html(templates::quick_generate(&csrf_token))
}

/// Quick generate and immediate download
#[derive(Deserialize)]
struct QuickGenerateForm {
    name: String,
    #[serde(default)]
    mobile: bool,
    csrf_token: String,
}

async fn quick_generate_download(
    State(state): State<WebUiState>,
    Form(form): Form<QuickGenerateForm>,
) -> Response {
    // Validate CSRF token
    let session_id = get_session_id_from_state(&state);
    if !csrf::validate_token(&session_id, &form.csrf_token) {
        return error_response(403, "Invalid CSRF token");
    }

    use corevpn_config::generator::ConfigGenerator;
    use corevpn_crypto::CertificateAuthority;
    use axum::http::header;

    // Validate and sanitize name
    let name = sanitize_filename(&form.name.trim().to_string());
    if name.is_empty() || name.len() > 64 {
        return error_response(400, "Invalid client name. Must be 1-64 characters.");
    }

    // Load CA
    let ca_cert = match std::fs::read_to_string(state.config.ca_cert_path()) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to read CA cert: {}", e);
            return error_response(500, "Failed to read CA certificate");
        }
    };
    let ca_key = match std::fs::read_to_string(state.config.ca_key_path()) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("Failed to read CA key: {}", e);
            return error_response(500, "Failed to read CA key");
        }
    };

    let ca = match CertificateAuthority::from_pem(&ca_cert, &ca_key) {
        Ok(ca) => ca,
        Err(e) => {
            tracing::error!("Failed to load CA: {}", e);
            return error_response(500, "Failed to load CA");
        }
    };

    let ta_key = std::fs::read_to_string(state.config.ta_key_path()).ok();

    let config = (*state.config).clone();
    let generator = ConfigGenerator::new(config, ca, ta_key);

    // Generate config (mobile or standard)
    let generated = if form.mobile {
        generator.generate_mobile_config(&name, None)
    } else {
        generator.generate_client_config(&name, None)
    };

    let generated = match generated {
        Ok(g) => g,
        Err(e) => {
            tracing::error!("Failed to generate config: {}", e);
            return error_response(500, "Failed to generate configuration");
        }
    };

    let filename = if form.mobile {
        let safe_name = name.replace(['@', '.', ' '], "_");
        sanitize_filename_for_download(&format!("{}-mobile.ovpn", safe_name))
    } else {
        sanitize_filename_for_download(&generated.filename())
    };
    let content = generated.ovpn_content;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-openvpn-profile")
        .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", filename))
        .body(content.into())
        .unwrap_or_else(|_| error_response(500, "Failed to build response"))
}

async fn sessions_list(State(state): State<WebUiState>) -> Html<String> {
    // Get active sessions from session manager
    let sessions = {
        let sm = state.session_manager.read();
        sm.active_sessions()
    };

    let session_infos: Vec<templates::SessionInfo> = sessions
        .iter()
        .map(|s| {
            // Format VPN address - prefer IPv4, fall back to IPv6
            let vpn_ip = s.vpn_address
                .and_then(|addr| addr.ipv4.map(|ip| ip.to_string())
                    .or_else(|| addr.ipv6.map(|ip| ip.to_string())))
                .unwrap_or_else(|| "-".to_string());

            templates::SessionInfo {
                id: s.id.to_string(),
                client_name: s.user_id.as_ref().map(|u| u.to_string()).unwrap_or_else(|| "Unknown".to_string()),
                vpn_ip,
                real_ip: format!("{}:{}", s.client_ip, s.client_port),
                connected_at: s.created_at.format("%Y-%m-%d %H:%M").to_string(),
                data_usage: format_data_usage(s.bytes_rx, s.bytes_tx),
            }
        })
        .collect();

    // Generate CSRF token for forms
    let session_id = get_session_id_from_state(&state);
    let csrf_token = csrf::generate_token(&session_id);

    Html(templates::sessions_list(&session_infos, &csrf_token))
}

#[derive(Deserialize)]
struct DisconnectSessionForm {
    csrf_token: String,
}

async fn disconnect_session(
    State(state): State<WebUiState>,
    Path(id): Path<String>,
    Form(form): Form<DisconnectSessionForm>,
) -> Redirect {
    // Validate CSRF token
    let session_id = get_session_id_from_state(&state);
    if !csrf::validate_token(&session_id, &form.csrf_token) {
        return Redirect::to("/admin/sessions?error=csrf");
    }

    // Validate path parameter
    let id = sanitize_path_param(&id);
    if id.is_empty() {
        return Redirect::to("/admin/sessions?error=invalid_id");
    }

    use corevpn_core::SessionId;

    // Parse UUID and remove session
    if let Ok(uuid) = id.parse::<uuid::Uuid>() {
        let session_id = SessionId::from_bytes(*uuid.as_bytes());
        let sm = state.session_manager.read();
        sm.remove_session(&session_id);
    }

    Redirect::to("/admin/sessions")
}

#[derive(Deserialize)]
struct DisconnectAllForm {
    csrf_token: String,
}

async fn disconnect_all_sessions(
    State(state): State<WebUiState>,
    Form(form): Form<DisconnectAllForm>,
) -> Redirect {
    // Validate CSRF token
    let session_id = get_session_id_from_state(&state);
    if !csrf::validate_token(&session_id, &form.csrf_token) {
        return Redirect::to("/admin/sessions?error=csrf");
    }

    // Get all session IDs and remove them
    let session_ids: Vec<_> = {
        let sm = state.session_manager.read();
        sm.active_sessions().iter().map(|s| s.id).collect()
    };

    let sm = state.session_manager.read();
    for id in session_ids {
        sm.remove_session(&id);
    }

    Redirect::to("/admin/sessions")
}

async fn settings_page(State(state): State<WebUiState>) -> Html<String> {
    let config = &state.config;

    let (oauth_enabled, oauth_provider) = config.oauth.as_ref()
        .map(|o| (o.enabled, Some(o.provider.as_str())))
        .unwrap_or((false, None));

    // Generate CSRF token for forms
    let session_id = get_session_id_from_state(&state);
    let csrf_token = csrf::generate_token(&session_id);

    let html = templates::settings(
        &config.server.public_host,
        config.server.listen_addr.port(),
        &config.server.protocol,
        &config.network.subnet,
        config.server.max_clients,
        oauth_enabled,
        oauth_provider,
        &csrf_token,
    );

    Html(html)
}

async fn not_found() -> Html<String> {
    Html(templates::error_page(404, "The page you're looking for doesn't exist."))
}

// ============================================================================
// Helpers
// ============================================================================

fn error_response(status: u16, message: &str) -> Response {
    // Sanitize error message - don't expose internal details
    let safe_message = match status {
        500 => "An internal error occurred. Please try again later.",
        _ => message,
    };
    
    let html = templates::error_page(status, safe_message);
    let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    (status_code, Html(html)).into_response()
}

// ============================================================================
// Security Helpers
// ============================================================================

/// Get session ID from state (simplified - uses a hash of config)
fn get_session_id_from_state(_state: &WebUiState) -> String {
    // In a real implementation, you'd use a proper session cookie
    // For now, use a simple identifier
    "default".to_string()
}

/// Sanitize filename for use in Content-Disposition header
fn sanitize_filename_for_download(filename: &str) -> String {
    // Remove path separators and control characters
    filename
        .chars()
        .filter(|c| {
            !matches!(c, '/' | '\\' | '\0'..='\x1f' | '\x7f'..='\u{9f}')
        })
        .collect::<String>()
        .trim()
        .to_string()
        .chars()
        .take(255) // Limit length
        .collect()
}

/// Sanitize filename input
fn sanitize_filename(input: &str) -> String {
    input
        .chars()
        .filter(|c| {
            c.is_alphanumeric() || matches!(c, '-' | '_' | '.')
        })
        .take(64)
        .collect()
}

/// Sanitize email input
fn sanitize_email(input: &str) -> String {
    input
        .chars()
        .filter(|c| {
            c.is_alphanumeric() || matches!(c, '@' | '.' | '-' | '_' | '+')
        })
        .take(255)
        .collect()
}

/// Sanitize path parameter
fn sanitize_path_param(input: &str) -> String {
    // Remove path traversal attempts and control characters
    input
        .chars()
        .filter(|c| {
            !matches!(c, '/' | '\\' | '.' | '\0'..='\x1f' | '\x7f'..='\u{9f}')
        })
        .take(64)
        .collect()
}

/// CSRF middleware - validate CSRF tokens on POST requests
async fn csrf_middleware(request: Request, next: Next) -> Response {
    // For GET requests, just pass through
    if request.method() == axum::http::Method::GET {
        return next.run(request).await;
    }

    // For POST requests, we would validate the CSRF token here
    // In a full implementation, this would check a token from the form against a session token
    // For now, we pass through since we have Basic Auth protection
    // TODO: Implement full CSRF token validation when session-based auth is added
    next.run(request).await
}

/// CSP middleware - add Content-Security-Policy headers
async fn csp_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    
    // Add strict CSP header
    let csp = "default-src 'self'; \
               script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com; \
               style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com; \
               font-src 'self' https://fonts.gstatic.com; \
               img-src 'self' data:; \
               connect-src 'self'; \
               frame-ancestors 'none'; \
               base-uri 'self'; \
               form-action 'self'";
    
    if let Ok(header_value) = header::HeaderValue::from_str(csp) {
        response.headers_mut().insert(header::CONTENT_SECURITY_POLICY, header_value);
    }
    
    // Add other security headers
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    
    response.headers_mut().insert(
        header::X_FRAME_OPTIONS,
        header::HeaderValue::from_static("DENY"),
    );
    
    response.headers_mut().insert(
        header::X_XSS_PROTECTION,
        header::HeaderValue::from_static("1; mode=block"),
    );
    
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    
    response
}

fn format_data_usage(rx: u64, tx: u64) -> String {
    let total = rx + tx;
    format_bytes(total)
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
