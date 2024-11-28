use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use argon2::{self, Config};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::error::Error;

// ZK Circuit for Password Authentication
struct PasswordAuthCircuit {
    password_hash: Option<[u8; 32]>,
    stored_hash: [u8; 32],
}

impl ConstraintSynthesizer<Fr> for PasswordAuthCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Convert hashes to bits for circuit comparison
        let password_hash_bits = self.password_hash
            .map(|hash| hash.iter().flat_map(|&byte| 
                (0..8).map(move |i| UInt8::new_witness(cs.clone(), || Ok((byte >> i) & 1 == 1)).unwrap())
            ).collect::<Vec<_>>());

        let stored_hash_bits = self.stored_hash.iter().flat_map(|&byte| 
            (0..8).map(move |i| UInt8::new_constant(cs.clone(), (byte >> i) & 1 == 1).unwrap())
        ).collect::<Vec<_>>();

        // Ensure hashes match bit by bit
        for (pw_bit, stored_bit) in password_hash_bits.unwrap().iter().zip(stored_hash_bits.iter()) {
            pw_bit.enforce_equal(stored_bit)?;
        }

        Ok(())
    }
}

struct ZKAuthChat {
    keypair: Keypair,
    username: String,
    password_hash: [u8; 32],
}

impl ZKAuthChat {
    fn new(username: String, password: String) -> Self {
        let salt = b"zk-chat-salt";
        let config = Config::default();
        let password_hash = argon2::hash_raw(password.as_bytes(), salt, &config)
            .expect("Failed to hash password")
            .try_into()
            .expect("Incorrect hash length");

        let keypair = Keypair::generate(&mut OsRng);

        ZKAuthChat {
            keypair,
            username,
            password_hash,
        }
    }

    fn generate_zk_proof(&self, input_password: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let salt = b"zk-chat-salt";
        let config = Config::default();
        let input_hash = argon2::hash_raw(
            input_password.as_bytes(), 
            salt, 
            &config
        )?.try_into()?;

        let circuit = PasswordAuthCircuit {
            password_hash: Some(input_hash),
            stored_hash: self.password_hash,
        };

        let (pk, _vk) = Groth16::<Bn254>::setup(circuit.clone(), &mut OsRng)?;
        let proof = Groth16::<Bn254>::prove(&pk, circuit)?;

        Ok(proof.to_vec())
    }

    async fn authenticate(&self, server_addr: &str, password: &str) -> Result<(), Box<dyn Error>> {
        let mut stream = TcpStream::connect(server_addr).await?;
        
        let zk_proof = self.generate_zk_proof(password)?;
        
        // Send authentication request
        let auth_req = serde_json::to_vec(&AuthRequest {
            username: self.username.clone(),
            zk_proof,
            public_key: self.keypair.public.to_bytes().to_vec(),
        })?;

        stream.write_all(&auth_req).await?;
        
        // Wait for authentication response
        let mut buffer = [0; 1024];
        let n = stream.read(&mut buffer).await?;
        let response: AuthResponse = serde_json::from_slice(&buffer[..n])?;

        if response.authenticated {
            println!("Successfully authenticated");
            Ok(())
        } else {
            Err("Authentication failed".into())
        }
    }

    async fn start_server(&self, bind_addr: &str) -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind(bind_addr).await?;
        println!("Authentication server listening on {}", bind_addr);

        loop {
            let (mut socket, _) = listener.accept().await?;
            
            let mut buffer = [0; 1024];
            let n = socket.read(&mut buffer).await?;
            let auth_req: AuthRequest = serde_json::from_slice(&buffer[..n])?;

            // Verify ZK proof
            let authenticated = self.verify_zk_proof(&auth_req.zk_proof);

            let response = AuthResponse {
                authenticated,
                message: if authenticated { "Welcome!" } else { "Authentication failed" }.to_string(),
            };

            socket.write_all(&serde_json::to_vec(&response)?).await?;
        }
    }

    fn verify_zk_proof(&self, proof: &[u8]) -> bool {
        // Placeholder for actual ZK proof verification
        // In a real implementation, you'd use Groth16::verify()
        !proof.is_empty()
    }
}

#[derive(Serialize, Deserialize)]
struct AuthRequest {
    username: String,
    zk_proof: Vec<u8>,
    public_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct AuthResponse {
    authenticated: bool,
    message: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Example usage
    let server = ZKAuthChat::new(
        "server_user".to_string(), 
        "secure_password".to_string()
    );

    // Run server in one thread
    tokio::spawn(async move {
        server.start_server("127.0.0.1:8080").await.unwrap();
    });

    // Client authentication
    let client = ZKAuthChat::new(
        "client_user".to_string(), 
        "secure_password".to_string()
    );

    client.authenticate("127.0.0.1:8080", "secure_password").await?;

    Ok(())
}