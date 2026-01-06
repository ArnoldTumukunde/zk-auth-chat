pub mod password;
pub mod zk_circuit;
pub mod proof;

pub use password::{generate_salt, hash_password, verify_password};
pub use zk_circuit::PasswordAuthCircuit;
pub use proof::{ProofSystem, generate_proof, verify_proof};
