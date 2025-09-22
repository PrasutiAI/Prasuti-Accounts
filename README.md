# Prasuti.AI Identity Management Service (IDM)

A production-ready, independent Identity & Access Management microservice built with Node.js, TypeScript, and Express. This service provides comprehensive authentication, authorization, multi-factor authentication, and audit capabilities for the Prasuti.AI ecosystem.

## 🚀 Features

### Core Authentication
- **User Registration & Email Verification** - Secure user onboarding with email validation
- **JWT Authentication** - RS256-signed JWT tokens with automatic key rotation
- **Password Management** - Secure password hashing, reset, and policy enforcement
- **Session Management** - Refresh token support with proper revocation

### Security Features
- **Multi-Factor Authentication (MFA)** - TOTP-based MFA with backup codes
- **Role-Based Access Control (RBAC)** - Granular permission system
- **Attribute-Based Access Control (ABAC)** - Policy-driven authorization
- **Machine-to-Machine Authentication** - Client credentials flow for API clients
- **Audit Logging** - Comprehensive security event tracking

### Advanced Capabilities
- **OAuth2 Token Endpoints** - Standards-compliant token issuance
- **Social Login Connectors** - Google OAuth integration (extensible)
- **Key Rotation** - Automated JWT signing key rotation
- **Rate Limiting** - Brute force protection and API rate limiting
- **Service Discovery** - Consul integration for microservices architecture

### Operational Features
- **Health Checks** - Kubernetes-ready health and readiness probes
- **Metrics Export** - Prometheus-compatible metrics endpoint
- **Structured Logging** - JSON-structured audit and application logs
- **Docker Support** - Multi-stage builds and container optimization
- **Kubernetes Ready** - Complete K8s manifests and deployment guides

## 📋 Prerequisites

- **Node.js** 18+ and npm
- **PostgreSQL** 13+ database
- **Redis** (optional, for session storage)
- **Docker** and Docker Compose (for containerized setup)

## 🚀 Quick Start

### 1. Environment Setup

```bash
# Clone the repository
git clone https://github.com/prasuti-ai/idm-service.git
cd idm-service

# Install dependencies
npm install

# Copy environment template
cp .env.example .env

# Edit .env file with your database URL and other settings
# At minimum, set DATABASE_URL to your PostgreSQL connection string
```

### 2. Database Setup

```bash
# Run the complete database setup (migrations, roles, JWT keys)
npm run setup

# Or run individual steps:
npm run db:push                    # Push schema changes
tsx scripts/init-default-roles.ts  # Initialize default roles
tsx scripts/setup-encryption-key.ts # Setup encryption key
```

### 3. Create Admin User

```bash
# Interactive admin creation
tsx scripts/create-admin.ts

# Or with parameters
tsx scripts/create-admin.ts admin@example.com password123 "Admin User"
```

### 4. Start the Application

```bash
# Development mode
npm run dev

# Production mode
npm run build
npm start
```

The application will be available at `http://localhost:5000`

### 5. Verify Installation

- Frontend: `http://localhost:5000`
- Health Check: `http://localhost:5000/health`
- API Documentation: `http://localhost:5000/api/openapi.json`
- JWKS Endpoint: `http://localhost:5000/.well-known/jwks.json`

## 🔧 Environment Variables

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgres://user:pass@localhost:5432/idm` |

### JWT Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_ISSUER` | JWT token issuer | `https://idm.prasuti.ai` |
| `JWT_AUD` | JWT token audience | `prasuti-services` |
| `JWT_ACCESS_TTL` | Access token expiry | `15m` |
| `JWT_REFRESH_TTL` | Refresh token expiry | `30d` |

### Security Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `ENCRYPTION_MASTER_KEY` | Master key for data encryption (32+ chars) | `change-me-in-production` |
| `SESSION_SECRET` | Express session secret | Generated randomly |
| `MFA_ISSUER` | MFA app display name | `Prasuti.AI Hub` |

### Optional Services

| Variable | Description | Default |
|----------|-------------|---------|
| `REDIS_URL` | Redis connection for session storage | None (uses memory) |
| `CONSUL_ADDR` | Consul service discovery | `http://consul:8500` |
| `PROMETHEUS_ENABLED` | Enable Prometheus metrics | `false` |

### Email Configuration (SMTP)

| Variable | Description |
|----------|-------------|
| `EMAIL_SMTP_HOST` | SMTP server hostname |
| `EMAIL_SMTP_PORT` | SMTP server port (587, 465, 25) |
| `EMAIL_SMTP_USER` | SMTP username |
| `EMAIL_SMTP_PASSWORD` | SMTP password |

### Application Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_ENV` | Environment mode | `development` |
| `PORT` | Server port | `5000` |

## 🗄️ Database Migrations

### Setup Database Schema

```bash
# Push schema changes to database
npm run db:push

# Force push (use with caution, may cause data loss)
npm run db:push -- --force
```

### Complete Database Setup

```bash
# Run complete setup (recommended for new installations)
npm run setup

# Setup with options
tsx scripts/setup-database.ts --force --verbose
```

The setup script will:
1. Verify `DATABASE_URL` is configured
2. Setup encryption keys
3. Push database schema changes
4. Test database connection
5. Initialize default roles
6. Generate initial JWT signing keys

### Manual Migration Steps

```bash
# 1. Generate migration files (when schema changes)
npm run db:generate

# 2. Apply migrations to database
npm run db:migrate

# 3. View database schema
npm run db:studio
```

## 👥 User and Role Management

### Creating Admin User

```bash
# Interactive creation (recommended)
tsx scripts/create-admin.ts

# Non-interactive with parameters
tsx scripts/create-admin.ts admin@company.com SecurePass123! "Admin Name"

# With options
tsx scripts/create-admin.ts --force  # Overwrite existing admin
```

### Default Roles and Permissions

The system creates four default roles:

#### Admin Role
- **Permissions**: `*` (all permissions)
- **Description**: Full system access
- **Can**: Manage all users, roles, clients, system settings

#### Developer Role
- **Permissions**: 
  - `dashboard:read`
  - `users:read`, `users:update`
  - `roles:read`
  - `clients:*` (all client operations)
  - `api-keys:*` (all API key operations)
  - `audit:read`
  - `settings:read`, `settings:update`
  - `profile:*` (all profile operations)

#### User Role
- **Permissions**:
  - `dashboard:read`
  - `profile:*`
  - `settings:read`
- **Description**: Regular users with basic access

#### Guest Role
- **Permissions**:
  - `dashboard:read`
- **Description**: Limited access for guest users

### Creating Additional Roles

```bash
# Initialize/update default roles
tsx scripts/init-default-roles.ts

# Create custom roles via API
curl -X POST http://localhost:5000/api/roles \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "name": "moderator",
    "description": "Content moderation role",
    "permissions": ["users:read", "audit:read", "content:moderate"]
  }'
```

### User Management Operations

```bash
# View all users (admin only)
curl -H "Authorization: Bearer JWT_TOKEN" \
  http://localhost:5000/api/users

# Create new user (admin/developer)
curl -X POST http://localhost:5000/api/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer JWT_TOKEN" \
  -d '{
    "email": "user@example.com",
    "name": "User Name",
    "password": "SecurePassword123!",
    "role": "user"
  }'

# Update user role (admin only)
curl -X PATCH http://localhost:5000/api/users/USER_ID \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer JWT_TOKEN" \
  -d '{"role": "developer"}'
```

## 🔑 JWT Key Rotation

### Manual Key Rotation

```bash
# Rotate keys immediately
tsx scripts/rotate-keys.ts

# Rotate with options
tsx scripts/rotate-keys.ts --force           # Force rotation even if not expired
tsx scripts/rotate-keys.ts --dry-run         # Preview rotation without changes
tsx scripts/rotate-keys.ts --expiry-days 180 # Set custom expiry (default: 90 days)
```

### Key Rotation Process

1. **Generate New Key Pair**: Creates RSA-2048 key pair
2. **Encrypt Private Key**: Uses AES-256-GCM encryption
3. **Store in Database**: Saves to `jwks_keys` table
4. **Deactivate Old Keys**: Marks previous keys as inactive
5. **Update Active Key**: New key becomes the signing key
6. **Audit Logging**: Records rotation event

### Automatic Key Rotation

Keys are automatically rotated when:
- Current active key expires
- `jwtService.getActiveSigningKey()` is called with expired key
- Key is within 7 days of expiration (configurable)

### Key Management Commands

```bash
# View current keys
tsx -e "
import { storage } from './server/storage.js';
const keys = await storage.getAllJwksKeys();
console.table(keys.map(k => ({
  kid: k.kid,
  active: k.isActive,
  expires: k.expiresAt,
  algorithm: k.algorithm
})));
"

# Check active signing key
curl http://localhost:5000/.well-known/jwks.json

# Force key rotation for security incident
tsx scripts/rotate-keys.ts --force --expiry-days 30
```

### Key Security Best Practices

1. **Regular Rotation**: Rotate keys every 90 days (default)
2. **Secure Storage**: Private keys are encrypted at rest
3. **Key Backup**: Export public keys for external verification
4. **Incident Response**: Immediate rotation on security breaches
5. **Monitoring**: Track key usage via audit logs
