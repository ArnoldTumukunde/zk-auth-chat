use sqlx::{Pool, Sqlite};
use uuid::Uuid;
use crate::db::models::User;
use crate::error::AppError;

pub struct UserRepository;

impl UserRepository {
    pub async fn create(
        pool: &Pool<Sqlite>,
        username: String,
        password_hash: &[u8; 32],
        password_salt: &[u8; 32],
        public_key: &[u8],
    ) -> Result<User, AppError> {
        let id = Uuid::new_v4().to_string();
        let created_at = chrono::Utc::now().timestamp();

        let user = sqlx::query_as::<_, User>(
            r#"
INSERT INTO users (id, username, password_hash, password_salt, public_key, created_at)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING *
            "#,
        )
        .bind(&id)
        .bind(&username)
        .bind(password_hash.as_slice())
        .bind(password_salt.as_slice())
        .bind(public_key)
        .bind(created_at)
        .fetch_one(pool)
        .await?;

        Ok(user)
    }

    pub async fn get_by_username(
        pool: &Pool<Sqlite>,
        username: &str,
    ) -> Result<Option<User>, AppError> {
        let user = sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE username = ?"
        )
        .bind(username)
        .fetch_optional(pool)
        .await?;

        Ok(user)
    }

    pub async fn get_by_id(
        pool: &Pool<Sqlite>,
        id: &str,
    ) -> Result<Option<User>, AppError> {
        let user = sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(user)
    }
}
