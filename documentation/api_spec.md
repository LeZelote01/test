# QuantumGate API Specification

## Overview
QuantumGate provides a comprehensive REST API for post-quantum cryptography, AI-powered threat detection, and blockchain integration.

## Base URL
```
https://api.quantumgate.com/api
```

## Authentication
All API endpoints require JWT authentication. Include the token in the Authorization header:
```
Authorization: Bearer <jwt_token>
```

## Endpoints

### Authentication
- `POST /auth/register` - Register new user
- `POST /auth/login` - User login
- `POST /auth/refresh` - Refresh JWT token
- `POST /auth/logout` - User logout

### Encryption
- `POST /encryption/generate-keys` - Generate quantum-safe key pair
- `POST /encryption/encrypt` - Encrypt data using hybrid encryption
- `POST /encryption/decrypt` - Decrypt data
- `GET /encryption/algorithms` - List available encryption algorithms

### AI Threat Detection
- `POST /ai/analyze-threat` - Analyze potential quantum threats
- `GET /ai/threat-history` - Get threat detection history
- `POST /ai/train-model` - Train threat detection model

### Blockchain Integration
- `POST /blockchain/deploy-contract` - Deploy quantum-safe smart contract
- `POST /blockchain/sign-transaction` - Sign transaction with quantum-safe signature
- `GET /blockchain/transaction-history` - Get transaction history

### Dashboard
- `GET /dashboard/stats` - Get dashboard statistics
- `GET /dashboard/user-activity` - Get user activity data
- `GET /dashboard/threat-alerts` - Get active threat alerts

### Bug Bounty
- `POST /bug-bounty/submit` - Submit bug report
- `GET /bug-bounty/bounties` - List active bounties
- `GET /bug-bounty/rewards` - Get user rewards

## Error Handling
All endpoints return consistent error responses:
```json
{
  "error": "error_code",
  "message": "Human readable error message",
  "details": "Additional error details"
}
```

## Rate Limiting
- 100 requests per minute per IP address
- 1000 requests per hour per authenticated user