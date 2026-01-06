use argon2::Argon2;
use crate::error::AppError;
use rand::Rng;

/// Generate a cryptographically secure random salt
pub fn generate_salt() -> [u8; 32] {
    rand::thread_rng().gen()
}

/// Hash a password with Argon2id using the provided salt
pub fn hash_password(password: &str, salt: &[u8]) -> Result<[u8; 32], AppError> {
    let argon2 = Argon2::default();
    let mut hash = [0u8; 32];
    
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut hash)
        .map_err(|e| AppError::Crypto(format!("Password hashing failed: {}", e)))?;
    
    Ok(hash)
}

/// Verify a password against a stored hash and salt
pub fn verify_password(password: &str, stored_hash: &[u8; 32], salt: &[u8]) -> Result<bool, AppError> {
    let computed_hash = hash_password(password, salt)?;
    Ok(computed_hash == *stored_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_verify() {
        let password = "test_password_123";
        let salt = generate_salt();
        
        let hash = hash_password(password, &salt).unwrap();
        assert!(verify_password(password, &hash, &salt).unwrap());
        assert!(!verify_password("wrong_password", &hash, &salt).unwrap());
    }
}
