use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::api::state::AppState;
use crate::db::{MessageRepository, UserRepository};
use crate::error::AppError;

#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    pub content: String,
    pub signature: String, // Base64 encoded Ed25519 signature
}

#[derive(Debug, Serialize)]
pub struct SendMessageResponse {
    pub message_id: String,
    pub created_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct GetMessagesQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    pub before: Option<i64>, // Cursor for pagination
}

fn default_limit() -> i64 {
    50
}

/// POST /api/chat/send (requires auth)
pub async fn send_message(
    State(state): State<AppState>,
    axum::Extension(user_id): axum::Extension<String>,
    Json(req): Json<SendMessageRequest>,
) -> Result<Json<SendMessageResponse>, AppError> {
    // Validate content length
    if req.content.is_empty() || req.content.len() > 4096 {
        return Err(AppError::Auth("Message must be 1-4096 characters".to_string()));
    }

    // Decode signature
    let signature_bytes = base64_simd::STANDARD
        .decode_to_vec(&req.signature)
        .map_err(|e| AppError::Auth(format!("Invalid signature format: {}", e)))?;
    
    if signature_bytes.len() != 64 {
        return Err(AppError::Auth("Invalid signature length".to_string()));
    }

    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&signature_bytes);
    let signature = Signature::from_bytes(&sig_array);

    // Get user's public key from database
    let user = UserRepository::get_by_id(&state.db, &user_id).await?
        .ok_or_else(|| AppError::Internal("User not found".to_string()))?;
    
    if user.public_key.len() != 32 {
        return Err(AppError::Internal("Invalid public key length".to_string()));
    }

    let mut pk_array = [0u8; 32];
    pk_array.copy_from_slice(&user.public_key);
    
    let verifying_key = VerifyingKey::from_bytes(&pk_array)
        .map_err(|e| AppError::Crypto(format!("Invalid verifying key: {}", e)))?;

    // Verify signature against message content
    verifying_key.verify(req.content.as_bytes(), &signature)
        .map_err(|_| AppError::Auth("Invalid message signature - message authentication failed".to_string()))?;

    // Store message with verified signature
    let message = MessageRepository::create(
        &state.db,
        user_id,
        req.content,
        &signature_bytes,
    ).await?;

    Ok(Json(SendMessageResponse {
        message_id: message.id,
        created_at: message.created_at,
    }))
}

/// GET /api/chat/messages (requires auth)
pub async fn get_messages(
    State(state): State<AppState>,
    Query(query): Query<GetMessagesQuery>,
) -> Result<Json<Vec<crate::db::models::Message>>, AppError> {
    let limit = query.limit.min(100).max(1); // Cap at 100

    let messages = if let Some(before) = query.before {
        MessageRepository::get_before(&state.db, before, limit).await?
    } else {
        MessageRepository::get_recent(&state.db, limit).await?
    };

    Ok(Json(messages))
}
