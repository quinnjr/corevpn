//! HTTP Basic Authentication for Admin UI
//!
//! Protects the admin interface with HTTP Basic Auth.
//! Password is set via the `COREVPN_ADMIN_PASSWORD` environment variable.

use axum::{
    body::Body,
    http::{Request, Response, StatusCode, header},
    middleware::Next,
};
use base64::Engine;

/// Environment variable name for admin password
pub const ADMIN_PASSWORD_ENV: &str = "COREVPN_ADMIN_PASSWORD";

/// Default admin username
pub const ADMIN_USERNAME: &str = "admin";

/// Check if admin authentication is configured
pub fn is_auth_configured() -> bool {
    std::env::var(ADMIN_PASSWORD_ENV).is_ok()
}

/// Get the configured admin password
pub fn get_admin_password() -> Option<String> {
    std::env::var(ADMIN_PASSWORD_ENV).ok()
}

/// HTTP Basic Authentication middleware
///
/// Requires the `COREVPN_ADMIN_PASSWORD` environment variable to be set.
/// Username is always "admin".
pub async fn require_auth(request: Request<Body>, next: Next) -> Response<Body> {
    // Get expected password from environment
    let expected_password = match get_admin_password() {
        Some(p) if !p.is_empty() => p,
        _ => {
            // No password configured - return error
            return unauthorized_response(Some(
                "Admin password not configured. Set COREVPN_ADMIN_PASSWORD environment variable.",
            ));
        }
    };

    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    match auth_header {
        Some(auth) if auth.starts_with("Basic ") => {
            // Decode base64 credentials
            let encoded = &auth[6..];
            let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded) {
                Ok(d) => d,
                Err(_) => return unauthorized_response(None),
            };

            let credentials = match String::from_utf8(decoded) {
                Ok(c) => c,
                Err(_) => return unauthorized_response(None),
            };

            // Parse username:password
            let mut parts = credentials.splitn(2, ':');
            let username = parts.next().unwrap_or("");
            let password = parts.next().unwrap_or("");

            // Verify credentials (constant-time comparison for password)
            if username == ADMIN_USERNAME && constant_time_eq(password, &expected_password) {
                // Authentication successful
                next.run(request).await
            } else {
                unauthorized_response(None)
            }
        }
        _ => {
            // No or invalid Authorization header
            unauthorized_response(None)
        }
    }
}

/// Generate 401 Unauthorized response with WWW-Authenticate header
fn unauthorized_response(message: Option<&str>) -> Response<Body> {
    let body = message.unwrap_or("Unauthorized. Please provide valid credentials.");

    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(
            header::WWW_AUTHENTICATE,
            "Basic realm=\"CoreVPN Admin\", charset=\"UTF-8\"",
        )
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Constant-time string comparison to prevent timing attacks
fn constant_time_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;

    if a.len() != b.len() {
        return false;
    }

    a.as_bytes().ct_eq(b.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("password", "password"));
        assert!(!constant_time_eq("password", "wrong"));
        assert!(!constant_time_eq("short", "longer"));
    }
}
