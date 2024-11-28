# ZK-Auth Chat

## Overview
A zero-knowledge proof authentication chat application built in Rust, demonstrating secure user authentication without revealing credentials.
This is not a production ready application, it's for learning purposes only.

## Features
- Zero-knowledge proof authentication
- Secure password hashing with Argon2
- Ed25519 key management
- Async networking with Tokio

## Prerequisites
- Rust (latest stable version)
- Cargo package manager

## Dependencies
- tokio
- ark-bn254
- ark-groth16
- ed25519-dalek
- argon2
- serde

## Installation
1. Clone the repository:
```bash
git clone https://github.com/yourusername/zk-auth-chat.git
cd zk-auth-chat
```

2. Build the project:
```bash
cargo build --release
```

## Running the Application
### Server Mode
```bash
cargo run -- server 8080
```

### Client Mode
```bash
cargo run -- client 8080
```

## Configuration
- Modify authentication parameters in `main()` function
- Adjust ZK circuit logic in `PasswordAuthCircuit`

## Security Considerations
- Uses Argon2 for password hashing
- Implements zero-knowledge proof authentication
- Protects credential exposure

## Current Limitations
- Proof verification needs enhancement
- Requires more robust error handling
- No persistent authentication state