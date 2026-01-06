pub mod auth;
pub mod chat;
pub mod state;
pub mod middleware;

pub use state::AppState;
pub use middleware::RateLimiter;

use axum::{
    Router,
    routing::{get, post},
    middleware as axum_middleware,
};
use tower_http::{
    cors::CorsLayer,
    trace::TraceLayer,
    timeout::TimeoutLayer,
};
use std::sync::Arc;
use std::time::Duration;
use serde::Serialize;

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
}

pub fn create_router(state: AppState, rate_limiter: Arc<RateLimiter>) -> Router {
    Router::new()
        // Health check
        .route("/api/health", get(health))
        
        // Authentication endpoints
        .route("/api/auth/register", post(auth::register))
        .route("/api/auth/login", post(auth::login))
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/auth/me", get(auth::me))
        
        // Chat endpoints
        .route("/api/chat/send", post(chat::send_message))
        .route("/api/chat/messages", get(chat::get_messages))
        
        // Add rate limiting middleware
        .layer(axum_middleware::from_fn(move |req, next| {
            let limiter = rate_limiter.clone();
            middleware::rate_limit_middleware(limiter, req, next)
        }))
        // Add request timeout
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn health() -> axum::Json<HealthResponse> {
    axum::Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}
