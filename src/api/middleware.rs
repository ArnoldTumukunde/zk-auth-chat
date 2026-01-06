use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::api::state::AppState;
use crate::db::SessionRepository;
use crate::error::AppError;

/// Authentication middleware - validates session tokens
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Extract Authorization header
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::Auth("Missing Authorization header".to_string()))?;

    // Extract token from "Bearer <token>"
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Auth("Invalid Authorization format".to_string()))?;

    // Validate session
    let session = SessionRepository::get_by_token(&state.db, token)
        .await?
        .ok_or_else(|| AppError::Auth("Invalid or expired session".to_string()))?;

    // Store user_id in request extensions
    request.extensions_mut().insert(session.user_id);

    Ok(next.run(request).await)
}

/// Simple in-memory rate limiter
/// Tracks requests per IP address and enforces limits
#[derive(Clone)]
pub struct RateLimiter {
    // IP -> (count, window_start)
    state: Arc<Mutex<HashMap<IpAddr, (u32, Instant)>>>,
    max_requests: u32,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window: Duration::from_secs(window_secs),
        }
    }

    pub async fn check(&self, ip: IpAddr) -> bool {
        let mut state = self.state.lock().await;
        let now = Instant::now();

        let entry = state.entry(ip).or_insert((0, now));
        
        // Reset if window expired
        if now.duration_since(entry.1) > self.window {
            *entry = (1, now);
            return true;
        }

        // Check if under limit
        if entry.0 < self.max_requests {
            entry.0 += 1;
            true
        } else {
            false
        }
    }

    /// Periodic cleanup of old entries
    pub async fn cleanup(&self) {
        let mut state = self.state.lock().await;
        let now = Instant::now();
        state.retain(|_, (_, time)| now.duration_since(*time) <= self.window * 2);
    }
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    limiter: Arc<RateLimiter>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Extract IP address from connection info
    let ip = request
        .extensions()
        .get::<std::net::SocketAddr>()
        .map(|addr| addr.ip())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));

    if !limiter.check(ip).await {
        return Err(AppError::Auth("Rate limit exceeded - too many requests".to_string()));
    }

    Ok(next.run(request).await)
}
