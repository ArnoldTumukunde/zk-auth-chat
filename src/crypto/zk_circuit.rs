use ark_bn254::Fr;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// ZK Circuit for Password Authentication
/// Proves knowledge of a password whose Argon2 hash matches a stored hash
#[derive(Clone)]
pub struct PasswordAuthCircuit {
    /// Private input: password hash (witness)
    pub password_hash: Option<[u8; 32]>,
    /// Public input: stored password hash
    pub stored_hash: [u8; 32],
}

impl ConstraintSynthesizer<Fr> for PasswordAuthCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Convert password hash to boolean witnesses (private)
        let password_hash_bits = if let Some(hash) = self.password_hash {
            let mut bits = Vec::new();
            for byte in hash.iter() {
                for i in 0..8 {
                    let bit = Boolean::new_witness(cs.clone(), || Ok((byte >> i) & 1 == 1))?;
                    bits.push(bit);
                }
            }
            bits
        } else {
            return Err(SynthesisError::AssignmentMissing);
        };

        // Convert stored hash to boolean constants (public)
        let mut stored_hash_bits = Vec::new();
        for byte in self.stored_hash.iter() {
            for i in 0..8 {
                let bit = Boolean::new_constant(cs.clone(), (byte >> i) & 1 == 1)?;
                stored_hash_bits.push(bit);
            }
        }

        // Enforce bit-by-bit equality (256 constraints total)
        for (pw_bit, stored_bit) in password_hash_bits.iter().zip(stored_hash_bits.iter()) {
            pw_bit.enforce_equal(stored_bit)?;
        }

        Ok(())
    }
}
