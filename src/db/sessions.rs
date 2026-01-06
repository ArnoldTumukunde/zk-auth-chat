use sqlx::{Pool, Sqlite};
use uuid::Uuid;
use crate::db::models::Session;
use crate::error::AppError;

pub struct SessionRepository;

impl SessionRepository {
    pub async fn create(
        pool: &Pool<Sqlite>,
        user_id: String,
        expiry_hours: i64,
    ) -> Result<Session, AppError> {
        let id = Uuid::new_v4().to_string();
        let token = Uuid::new_v4().to_string();
        let created_at = chrono::Utc::now().timestamp();
        let expires_at = created_at + (expiry_hours * 3600);

        let session = sqlx::query_as::<_, Session>(
            r#"
INSERT INTO sessions (id, user_id, token, expires_at, created_at)
VALUES (?, ?, ?, ?, ?)
RETURNING *
            "#,
        )
        .bind(&id)
        .bind(&user_id)
        .bind(&token)
        .bind(expires_at)
        .bind(created_at)
        .fetch_one(pool)
        .await?;

        Ok(session)
    }

    pub async fn get_by_token(
        pool: &Pool<Sqlite>,
        token: &str,
    ) -> Result<Option<Session>, AppError> {
        let now = chrono::Utc::now().timestamp();
        
        let session = sqlx::query_as::<_, Session>(
            "SELECT * FROM sessions WHERE token = ? AND expires_at > ?"
        )
        .bind(token)
        .bind(now)
        .fetch_optional(pool)
        .await?;

        Ok(session)
    }

    pub async fn delete(
        pool: &Pool<Sqlite>,
        token: &str,
    ) -> Result<(), AppError> {
        sqlx::query("DELETE FROM sessions WHERE token = ?")
            .bind(token)
            .execute(pool)
            .await?;

        Ok(())
    }

    pub async fn cleanup_expired(pool: &Pool<Sqlite>) -> Result<(), AppError> {
        let now = chrono::Utc::now().timestamp();
        
        sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
            .bind(now)
            .execute(pool)
            .await?;

        Ok(())
    }
}
