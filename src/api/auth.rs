use axum::{
    extract::State,
    Json,
};
use serde::{Deserialize, Serialize};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use crate::api::state::AppState;
use crate::crypto::{generate_salt, hash_password, verify_proof};
use crate::db::{UserRepository, SessionRepository};
use crate::error::AppError;

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub user_id: String,
    pub public_key: String, // Base64 encoded
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub zk_proof: String, // Base64 encoded proof
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub session_token: String,
    pub expires_at: i64,
}

#[derive(Debug, Serialize)]
pub struct UserInfoResponse {
    pub user_id: String,
    pub username: String,
    pub public_key: String,
}

/// Validate and sanitize username
fn validate_username(username: &str) -> Result<String, AppError> {
    let trimmed = username.trim();
    
    if trimmed.len() < 3 || trimmed.len() > 32 {
        return Err(AppError::Auth("Username must be 3-32 characters".to_string()));
    }
    
    if !trimmed.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err(AppError::Auth("Username must be alphanumeric, underscore, or hyphen".to_string()));
    }
    
    // Convert to lowercase for consistency
    Ok(trimmed.to_lowercase())
}

/// POST /api/auth/register
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, AppError> {
    // Validate and sanitize username
    let username = validate_username(&req.username)?;

    // Validate password
    if req.password.len() < 12 {
        return Err(AppError::Auth("Password must be at least 12 characters".to_string()));
    }

    // Check if username exists
    if UserRepository::get_by_username(&state.db, &username).await?.is_some() {
        return Err(AppError::Auth("Username already exists".to_string()));
    }

    // Generate salt and hash password
    let salt = generate_salt();
    let password_hash = hash_password(&req.password, &salt)?;

    // Generate Ed25519 keypair for message signing
    let keypair = SigningKey::generate(&mut OsRng);
    let public_key = keypair.verifying_key().to_bytes();

    // Create user
    let user = UserRepository::create(
        &state.db,
        username,
        &password_hash,
        &salt,
        &public_key,
    ).await?;

    Ok(Json(RegisterResponse {
        user_id: user.id,
        public_key: base64_simd::STANDARD.encode_to_string(&public_key),
    }))
}

/// POST /api/auth/login
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    // Sanitize username
    let username = validate_username(&req.username)?;

    // Get user by username
    let user = UserRepository::get_by_username(&state.db, &username)
        .await?
        .ok_or_else(|| AppError::Auth("Invalid credentials".to_string()))?;

    // Decode proof
    let proof_bytes = base64_simd::STANDARD
        .decode_to_vec(&req.zk_proof)
        .map_err(|e| AppError::Auth(format!("Invalid proof format: {}", e)))?;

    // Verify ZK proof
    let password_hash: [u8; 32] = user.password_hash
        .try_into()
        .map_err(|_| AppError::Internal("Invalid stored hash".to_string()))?;

    let valid = verify_proof(&proof_bytes, password_hash, &state.vk)?;
    
    if !valid {
        return Err(AppError::Auth("Invalid credentials".to_string()));
    }

    // Create session
    let session = SessionRepository::create(
        &state.db,
        user.id,
        state.config.session_expiry_hours,
    ).await?;

    Ok(Json(LoginResponse {
        session_token: session.token,
        expires_at: session.expires_at,
    }))
}

/// POST /api/auth/logout (requires auth)
pub async fn logout(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let auth_header = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::Auth("Missing Authorization header".to_string()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Auth("Invalid Authorization format".to_string()))?;

    SessionRepository::delete(&state.db, token).await?;

    Ok(Json(serde_json::json!({"success": true})))
}

/// GET /api/auth/me (requires auth via middleware)
pub async fn me(
    State(state): State<AppState>,
    axum::Extension(user_id): axum::Extension<String>,
) -> Result<Json<UserInfoResponse>, AppError> {
    let user = UserRepository::get_by_id(&state.db, &user_id)
        .await?
        .ok_or_else(|| AppError::Internal("User not found".to_string()))?;

    Ok(Json(UserInfoResponse {
        user_id: user.id,
        username: user.username,
        public_key: base64_simd::STANDARD.encode_to_string(&user.public_key),
    }))
}
