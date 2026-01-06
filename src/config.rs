use crate::error::AppError;

#[derive(Clone)]
pub struct Config {
    pub server_host: String,
    pub server_port: u16,
    pub database_url: String,
    pub session_expiry_hours: i64,
    pub zk_keys_dir: String,
    pub db_max_connections: u32,
    pub db_min_connections: u32,
    pub request_timeout_secs: u64,
}

impl Config {
    pub fn from_env() -> Result<Self, AppError> {
        dotenvy::dotenv().ok(); // Load .env file if present

        Ok(Config {
            server_host: std::env::var("SERVER_HOST")
                .unwrap_or_else(|_| "127.0.0.1".to_string()),
            server_port: std::env::var("SERVER_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .map_err(|e| AppError::Config(format!("Invalid SERVER_PORT: {}", e)))?,
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite://zk_auth_chat.db".to_string()),
            session_expiry_hours: std::env::var("SESSION_EXPIRY_HOURS")
                .unwrap_or_else(|_| "24".to_string())
                .parse()
                .map_err(|e| AppError::Config(format!("Invalid SESSION_EXPIRY_HOURS: {}", e)))?,
            zk_keys_dir: std::env::var("ZK_KEYS_DIR")
                .unwrap_or_else(|_| "./keys".to_string()),
            db_max_connections: std::env::var("DB_MAX_CONNECTIONS")
                .unwrap_or_else(|_| "20".to_string())
                .parse()
                .map_err(|e| AppError::Config(format!("Invalid DB_MAX_CONNECTIONS: {}", e)))?,
            db_min_connections: std::env::var("DB_MIN_CONNECTIONS")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .map_err(|e| AppError::Config(format!("Invalid DB_MIN_CONNECTIONS: {}", e)))?,
            request_timeout_secs: std::env::var("REQUEST_TIMEOUT_SECS")
                .unwrap_or_else(|_| "30".to_string())
                .parse()
                .map_err(|e| AppError::Config(format!("Invalid REQUEST_TIMEOUT_SECS: {}", e)))?,
        })
    }

    pub fn server_address(&self) -> String {
        format!("{}:{}", self.server_host, self.server_port)
    }
}
