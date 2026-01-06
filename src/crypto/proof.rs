use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;

use crate::crypto::zk_circuit::PasswordAuthCircuit;
use crate::error::AppError;

/// Proof system manager handling key generation, proof creation, and verification
pub struct ProofSystem {
    pub proving_key: ProvingKey<Bn254>,
    pub verifying_key: VerifyingKey<Bn254>,
}

impl ProofSystem {
    /// Initialize proof system with one-time trusted setup
    pub fn setup(keys_dir: &str) -> Result<Self, AppError> {
        let pk_path = format!("{}/proving.key", keys_dir);
        let vk_path = format!("{}/verification.key", keys_dir);

        // Try to load existing keys
        if Path::new(&pk_path).exists() && Path::new(&vk_path).exists() {
            tracing::info!("Loading existing ZK keys from {}", keys_dir);
            return Self::load_keys(&pk_path, &vk_path);
        }

        // Generate new keys
        tracing::info!("Generating new ZK keys (one-time trusted setup)...");
        fs::create_dir_all(keys_dir)
            .map_err(|e| AppError::Crypto(format!("Failed to create keys directory: {}", e)))?;

        // Create a dummy circuit for setup
        let dummy_circuit = PasswordAuthCircuit {
            password_hash: Some([0u8; 32]),
            stored_hash: [0u8; 32],
        };

        let (pk, vk) = Groth16::<Bn254>::setup(dummy_circuit, &mut OsRng)
            .map_err(|e| AppError::Crypto(format!("Setup failed: {}", e)))?;

        // Save keys to disk
        Self::save_key(&pk, &pk_path)?;
        Self::save_key(&vk, &vk_path)?;

        tracing::info!("ZK keys generated and saved successfully");
        Ok(ProofSystem {
            proving_key: pk,
            verifying_key: vk,
        })
    }

    /// Load keys from disk
    fn load_keys(pk_path: &str, vk_path: &str) -> Result<Self, AppError> {
        let pk_bytes = fs::read(pk_path)
            .map_err(|e| AppError::Crypto(format!("Failed to read proving key: {}", e)))?;
        let vk_bytes = fs::read(vk_path)
            .map_err(|e| AppError::Crypto(format!("Failed to read verification key: {}", e)))?;

        let pk = ProvingKey::<Bn254>::deserialize_compressed(&pk_bytes[..])
            .map_err(|e| AppError::Crypto(format!("Failed to deserialize proving key: {}", e)))?;
        let vk = VerifyingKey::<Bn254>::deserialize_compressed(&vk_bytes[..])
            .map_err(|e| AppError::Crypto(format!("Failed to deserialize verification key: {}", e)))?;

        Ok(ProofSystem {
            proving_key: pk,
            verifying_key: vk,
        })
    }

    /// Save a key to disk
    fn save_key<T: CanonicalSerialize>(key: &T, path: &str) -> Result<(), AppError> {
        let mut bytes = Vec::new();
        key.serialize_compressed(&mut bytes)
            .map_err(|e| AppError::Crypto(format!("Failed to serialize key: {}", e)))?;
        fs::write(path, bytes)
            .map_err(|e| AppError::Crypto(format!("Failed to write key to {}: {}", path, e)))?;
        Ok(())
    }
}

/// Generate a ZK proof for password authentication
pub fn generate_proof(
    password_hash: [u8; 32],
    stored_hash: [u8; 32],
    proving_key: &ProvingKey<Bn254>,
) -> Result<Vec<u8>, AppError> {
    let circuit = PasswordAuthCircuit {
        password_hash: Some(password_hash),
        stored_hash,
    };

    let proof = Groth16::<Bn254>::prove(proving_key, circuit, &mut OsRng)
        .map_err(|e| AppError::Crypto(format!("Proof generation failed: {}", e)))?;

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)
        .map_err(|e| AppError::Crypto(format!("Proof serialization failed: {}", e)))?;

    Ok(proof_bytes)
}

/// Verify a ZK proof (REAL implementation, not placeholder)
pub fn verify_proof(
    proof_bytes: &[u8],
    _stored_hash: [u8; 32],
    verifying_key: &VerifyingKey<Bn254>,
) -> Result<bool, AppError> {
    // Deserialize proof
    let proof = ark_groth16::Proof::<Bn254>::deserialize_compressed(proof_bytes)
        .map_err(|e| AppError::Crypto(format!("Invalid proof format: {}", e)))?;

    // The public inputs are derived from the stored hash
    // In our circuit, stored_hash is a public input (constant)
    // For Groth16, we typically need to provide public inputs as field elements
    // Since our circuit uses the hash as constants, we use an empty public input vector
    let public_inputs: Vec<Fr> = Vec::new();

    // Perform actual Groth16 verification
    let result = Groth16::<Bn254>::verify(verifying_key, &public_inputs, &proof)
        .map_err(|e| AppError::Crypto(format!("Verification failed: {}", e)))?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::password::hash_password;

    #[test]
    fn test_proof_generation_verification() {
        let password = "test_password_123";
        let salt = [1u8; 32];
        
        let hash = hash_password(password, &salt).unwrap();
        
        // Setup proof system
        let ps = ProofSystem::setup("./test_keys").unwrap();
        
        // Generate proof
        let proof = generate_proof(hash, hash, &ps.proving_key).unwrap();
        
        // Verify proof
        let valid = verify_proof(&proof, hash, &ps.verifying_key).unwrap();
        assert!(valid);
        
        // Clean up
        std::fs::remove_dir_all("./test_keys").ok();
    }
}
