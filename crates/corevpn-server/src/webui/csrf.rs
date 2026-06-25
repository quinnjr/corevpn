//! CSRF Protection
//!
//! Generates and validates CSRF tokens for POST requests.

use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
use rand::Rng;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// CSRF token store with expiration
struct CsrfStore {
    tokens: HashMap<String, (String, Instant)>,
}

impl CsrfStore {
    fn generate_token(&mut self, session_id: &str) -> String {
        // Generate random token
        let token: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        // Store with expiration (1 hour)
        self.tokens.insert(
            session_id.to_string(),
            (token.clone(), Instant::now() + Duration::from_secs(3600)),
        );

        // Cleanup expired tokens
        self.cleanup_expired();

        token
    }

    fn validate_token(&mut self, session_id: &str, token: &str) -> bool {
        self.cleanup_expired();

        if let Some((stored_token, _)) = self.tokens.get(session_id) {
            // Constant-time comparison
            use subtle::ConstantTimeEq;
            stored_token.as_bytes().ct_eq(token.as_bytes()).into()
        } else {
            false
        }
    }

    fn cleanup_expired(&mut self) {
        let now = Instant::now();
        self.tokens.retain(|_, (_, expires_at)| *expires_at > now);
    }
}

/// Global CSRF store
static CSRF_STORE: LazyLock<Mutex<CsrfStore>> = LazyLock::new(|| {
    Mutex::new(CsrfStore {
        tokens: HashMap::new(),
    })
});

/// Generate a CSRF token for a session
pub fn generate_token(session_id: &str) -> String {
    CSRF_STORE.lock().unwrap().generate_token(session_id)
}

/// Validate a CSRF token
pub fn validate_token(session_id: &str, token: &str) -> bool {
    CSRF_STORE.lock().unwrap().validate_token(session_id, token)
}

/// Get or create a session ID from request
/// Uses a simple hash of the Authorization header as session identifier
#[allow(dead_code)] // Used by csrf_middleware, which is not yet mounted.
fn get_session_id(request: &Request) -> String {
    // Use Authorization header as session identifier
    // In a real implementation, you'd use a proper session cookie
    if let Some(auth_header) = request.headers().get("authorization") {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        auth_header.hash(&mut hasher);
        format!("session_{:x}", hasher.finish())
    } else {
        // Fallback: use a default session
        "default".to_string()
    }
}

/// CSRF middleware for POST requests
#[allow(dead_code)] // Retained for future mounting on the web UI router.
pub async fn csrf_middleware(request: Request, next: Next) -> Response {
    // Only check CSRF on POST requests
    if request.method() == axum::http::Method::POST {
        let session_id = get_session_id(&request);

        // Extract CSRF token from form or header
        let token = request
            .headers()
            .get("x-csrf-token")
            .and_then(|h| h.to_str().ok())
            .or_else(|| {
                // Try to get from query string as fallback
                request.uri().query().and_then(|q| {
                    q.split('&').find_map(|pair| {
                        let mut parts = pair.split('=');
                        if parts.next() == Some("csrf_token") {
                            parts.next()
                        } else {
                            None
                        }
                    })
                })
            });

        if let Some(token) = token {
            if !validate_token(&session_id, token) {
                return Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(axum::body::Body::from("Invalid CSRF token"))
                    .unwrap();
            }
        } else {
            // No token provided
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(axum::body::Body::from("CSRF token required"))
                .unwrap();
        }
    }

    next.run(request).await
}
