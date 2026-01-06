use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: Vec<u8>,
    #[serde(skip_serializing)]
    pub password_salt: Vec<u8>,
    pub public_key: Vec<u8>,
    pub created_at: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub token: String,
    pub expires_at: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub user_id: String,
    pub username: String, // Joined from users table
    pub content: String,
    pub signature: Vec<u8>,
    pub created_at: i64,
}
