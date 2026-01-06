# ZK-Auth Chat

Zero-knowledge proof authenticated chat application built in Rust.

## Features

### Security  
✅ **Zero-Knowledge Authentication** - Groth16 zkSNARKs with BN254 curve  
✅ **Message Signing** - Ed25519 cryptographic signature verification  
✅ **Secure Password Hashing** - Argon2id with per-user salts  
✅ **Rate Limiting** - 100 requests/min per IP  
✅ **Input Validation** - Username sanitization, 12-char min password  
✅ **Session Management** - Automated cleanup, configurable expiry  

### Performance  
✅ **Database Pooling** - Configurable connections with timeouts  
✅ **Request Timeouts** - 30s limit prevents hanging  
✅ **Cursor Pagination** - Efficient message history retrieval  

### Infrastructure
✅ **REST API** - Axum framework with JSON endpoints  
✅ **Database Persistence** - SQLite with automated migrations  
✅ **Structured Logging** - Tracing with configurable levels  
✅ **Health Monitoring** - JSON health endpoint with version  

## Quick Start

### Prerequisites
- Rust (latest stable)
- Cargo package manager

### Installation
```bash
git clone https://github.com/ArnoldTumukunde/zk-auth-chat.git
cd zk-auth-chat
cargo build --release
```

### Running
```bash
# Start server
DATABASE_URL="sqlite:zk_auth_chat.db?mode=rwc" cargo run --release

# Server will start on http://127.0.0.1:8080
```

## API Endpoints

### Authentication
- `POST /api/auth/register` - Create new user
- `POST /api/auth/login` - Authenticate with ZK proof
- `POST /api/auth/logout` - Invalidate session
- `GET /api/auth/me` - Get current user info

### Chat
- `POST /api/chat/send` - Post message with signature (requires auth)
- `GET /api/chat/messages?limit=50&before=<timestamp>` - Fetch history (requires auth)

### Health
- `GET /api/health` - Server health check

## Example Usage

### Register User
```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"SecurePassword123"}'
```

Response:
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "public_key": "base64_encoded_ed25519_public_key"
}
```

### Send Message (requires signature verification)
```bash
curl -X POST http://localhost:8080/api/chat/send \
  -H "Authorization: Bearer <session_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "content":"Hello, world!",
    "signature":"<base64_ed25519_signature_of_content>"
  }'
```

**Note**: Messages must include valid Ed25519 signatures matching the user's public key.

## Configuration

Environment variables:
```env
# Server
SERVER_HOST=127.0.0.1
SERVER_PORT=8080

# Database
DATABASE_URL=sqlite:zk_auth_chat.db?mode=rwc
DB_MAX_CONNECTIONS=20
DB_MIN_CONNECTIONS=5

# Security
SESSION_EXPIRY_HOURS=24
REQUEST_TIMEOUT_SECS=30

# ZK Keys
ZK_KEYS_DIR=./keys

# Logging
RUST_LOG=info,zk_auth_chat=debug
```

## Architecture

```
src/
├── main.rs              # Entry point, background tasks
├── lib.rs               # Module exports
├── config.rs            # Environment configuration
├── error.rs             # Error types
├── crypto/              # Cryptography
│   ├── password.rs      # Argon2 hashing
│   ├── zk_circuit.rs    # ZK circuit
│   └── proof.rs         # Proof generation/verification
├── db/                  # Database layer
│   ├── models.rs        # Data models
│   ├── users.rs         # User repository
│   ├── sessions.rs      # Session repository
│   └── messages.rs      # Message repository
└── api/                 # REST API
    ├── mod.rs           # Router setup
    ├── state.rs         # App state
    ├── middleware.rs    # Auth + rate limiting
    ├── auth.rs          # Auth endpoints
    └── chat.rs          # Chat endpoints
```

## Security Features

- **Message Forgery Prevention** - Ed25519 signature verification
- **DoS Protection** - Rate limiting (100 req/min per IP)
- **Password Security** - Argon2id + unique per-user salts
- **ZK Proof Verification** - Real Groth16::verify()
- **SQL Injection Prevention** - Parameterized queries
- **Session Security** - Token-based with auto-cleanup
- **Input Validation** - Whitelist + sanitization
- **Request Timeouts** - 30-second limit

## Development

```bash
# Run in development mode
cargo run

# Run tests
cargo test

# Format code
cargo fmt

# Lint
cargo clippy
```

## Testing

```bash
# Run test script
./test.sh

# Manual health check
curl http://localhost:8080/api/health
```

## Dependencies

**Core**: tokio, axum, sqlx, ark-* (ZK proofs)  
**Cryptography**: argon2, ed25519-dalek, rand  
**Utilities**: serde, tracing, uuid, chrono  

## License

MIT License

## Contributing

Contributions welcome! Please open an issue or PR.

---

**Security Note**: For production, use HTTPS (TLS) via reverse proxy like nginx.