use std::sync::Arc;
use std::time::Duration;
use sqlx::sqlite::SqlitePoolOptions;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use zk_auth_chat::{
    api::{create_router, AppState, RateLimiter},
    config::Config,
    crypto::proof::ProofSystem,
    db::SessionRepository,
    error::AppError,
};

#[tokio::main]
async fn main() -> Result<(), AppError> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,zk_auth_chat=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("🚀 Starting ZK-Auth Chat server v{}...", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config = Arc::new(Config::from_env()?);
    tracing::info!("✅ Configuration loaded");

    // Setup database with proper connection pooling
    let db = SqlitePoolOptions::new()
        .max_connections(config.db_max_connections)
        .min_connections(config.db_min_connections)
        .acquire_timeout(Duration::from_secs(30))
        .idle_timeout(Duration::from_secs(600))
        .max_lifetime(Duration::from_secs(1800))
        .connect(&config.database_url)
        .await?;

    tracing::info!("✅ Database connected: {}", config.database_url);

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .map_err(|e| AppError::Internal(format!("Migration failed: {}", e)))?;

    tracing::info!("✅ Database migrations completed");

    // Setup ZK proof system (one-time trusted setup or load cached keys)
    let proof_system = ProofSystem::setup(&config.zk_keys_dir)?;
    tracing::info!("✅ ZK proof system initialized");

    // Create rate limiter (100 requests per minute per IP)
    let rate_limiter = Arc::new(RateLimiter::new(100, 60));
    tracing::info!("✅ Rate limiter configured (100 req/min per IP)");

    // Create shared application state
    let state = AppState {
        db: db.clone(),
        vk: Arc::new(proof_system.verifying_key),
        config: config.clone(),
    };

    // Spawn background task for session cleanup
    {
        let db_clone = db.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Every hour
            loop {
                interval.tick().await;
                match SessionRepository::cleanup_expired(&db_clone).await {
                    Ok(_) => tracing::debug!("🧹 Expired sessions cleaned up"),
                    Err(e) => tracing::error!("❌ Session cleanup failed: {}", e),
                }
            }
        });
        tracing::info!("✅ Session cleanup task started (runs hourly)");
    }

    // Spawn background task for rate limiter cleanup
    {
        let limiter = rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // Every 5 minutes
            loop {
                interval.tick().await;
                limiter.cleanup().await;
                tracing::debug!("🧹 Rate limiter cache cleaned up");
            }
        });
        tracing::info!("✅ Rate limiter cleanup task started");
    }

    // Build router
    let app = create_router(state, rate_limiter);

    // Bind and serve
    let addr = config.server_address();
    tracing::info!("🌐 Server listening on http://{}", addr);
    tracing::info!("🏥 Health check: http://{}/api/health", addr);
    tracing::info!("");
    tracing::info!("📚 API Endpoints:");
    tracing::info!("  POST /api/auth/register - Register new user");
    tracing::info!("  POST /api/auth/login    - Login with ZK proof");
    tracing::info!("  POST /api/auth/logout   - Logout (requires auth)");
    tracing::info!("  GET  /api/auth/me       - Get user info (requires auth)");
    tracing::info!("  POST /api/chat/send     - Send message (requires auth)");
    tracing::info!("  GET  /api/chat/messages - Get messages (requires auth)");
    tracing::info!("");
    
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to bind to {}: {}", addr, e)))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| AppError::Internal(format!("Server error: {}", e)))?;

    Ok(())
}