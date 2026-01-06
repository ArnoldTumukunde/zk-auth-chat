use sqlx::{Pool, Sqlite};
use uuid::Uuid;
use crate::db::models::Message;
use crate::error::AppError;

pub struct MessageRepository;

impl MessageRepository {
    pub async fn create(
        pool: &Pool<Sqlite>,
        user_id: String,
        content: String,
        signature: &[u8],
    ) -> Result<Message, AppError> {
        let id = Uuid::new_v4().to_string();
        let created_at = chrono::Utc::now().timestamp();

        sqlx::query(
            r#"
INSERT INTO messages (id, user_id, content, signature, created_at)
VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(&user_id)
        .bind(&content)
        .bind(signature)
        .bind(created_at)
        .execute(pool)
        .await?;

        // Fetch with username joined
        let message = Self::get_by_id(pool, &id).await?
            .ok_or_else(|| AppError::Internal("Failed to fetch created message".to_string()))?;

        Ok(message)
    }

    pub async fn get_by_id(
        pool: &Pool<Sqlite>,
        id: &str,
    ) -> Result<Option<Message>, AppError> {
        let message = sqlx::query_as::<_, Message>(
            r#"
SELECT m.id, m.user_id, u.username, m.content, m.signature, m.created_at
FROM messages m
JOIN users u ON m.user_id = u.id
WHERE m.id = ?
            "#
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(message)
    }

    pub async fn get_recent(
        pool: &Pool<Sqlite>,
        limit: i64,
    ) -> Result<Vec<Message>, AppError> {
        let messages = sqlx::query_as::<_, Message>(
            r#"
SELECT m.id, m.user_id, u.username, m.content, m.signature, m.created_at
FROM messages m
JOIN users u ON m.user_id = u.id
ORDER BY m.created_at DESC
LIMIT ?
            "#
        )
        .bind(limit)
        .fetch_all(pool)
        .await?;

        Ok(messages)
    }

    pub async fn get_before(
        pool: &Pool<Sqlite>,
        before: i64,
        limit: i64,
    ) -> Result<Vec<Message>, AppError> {
        let messages = sqlx::query_as::<_, Message>(
            r#"
SELECT m.id, m.user_id, u.username, m.content, m.signature, m.created_at
FROM messages m
JOIN users u ON m.user_id = u.id
WHERE m.created_at < ?
ORDER BY m.created_at DESC
LIMIT ?
            "#
        )
        .bind(before)
        .bind(limit)
        .fetch_all(pool)
        .await?;

        Ok(messages)
    }

    pub async fn get_since(
        pool: &Pool<Sqlite>,
        timestamp: i64,
    ) -> Result<Vec<Message>, AppError> {
        let messages = sqlx::query_as::<_, Message>(
            r#"
SELECT m.id, m.user_id, u.username, m.content, m.signature, m.created_at
FROM messages m
JOIN users u ON m.user_id = u.id
WHERE m.created_at > ?
ORDER BY m.created_at ASC
            "#
        )
        .bind(timestamp)
        .fetch_all(pool)
        .await?;

        Ok(messages)
    }
}
