# Identity Management System - 4C Architecture Model Documentation

## Table of Contents
1. [Context Diagram](#context-diagram)
2. [Container Diagram](#container-diagram)  
3. [Component Diagram](#component-diagram)
4. [Code Diagram](#code-diagram)
5. [Technology Stack](#technology-stack)
6. [Database Design](#database-design)
7. [Deployment Architecture](#deployment-architecture)
8. [Operations & Commands](#operations--commands)

---

## Context Diagram

### System Purpose
**Prasuti.AI Identity Management Service (IDM)** - A production-ready Identity & Access Management microservice that provides comprehensive authentication, authorization, and user management capabilities for the Prasuti.AI ecosystem.

### External Dependencies & Integrations

#### **Primary Systems**
- **Prasuti.AI Services** - Main consumers of authentication/authorization services
- **External OAuth Providers** - Google OAuth2 for social authentication
- **Email Service Providers** - SMTP services for verification emails and notifications
- **Monitoring Systems** - Prometheus/Grafana for observability
- **Certificate Authorities** - Let's Encrypt for TLS certificates

#### **Infrastructure Dependencies**
- **PostgreSQL Database** - Primary data store (Neon serverless)
- **Redis Cache** - Session storage and caching layer
- **Consul** - Service discovery and configuration management
- **Kubernetes** - Container orchestration platform
- **Load Balancers** - AWS Network Load Balancer (NLB)

#### **Security Dependencies**
- **Certificate Manager** - Automated TLS certificate management
- **Encryption Services** - AES-256-GCM for data at rest
- **JWT Key Storage** - Persistent volume for cryptographic keys

---

## Container Diagram

### High-Level Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│                 │    │                 │    │                 │
│  React Frontend │◄──►│ Express Backend │◄──►│  PostgreSQL DB  │
│   (Port 5000)   │    │   (Port 5000)   │    │   (Port 5432)   │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         ▲                        ▲                        
         │                        ▼                        
         │              ┌─────────────────┐               
         │              │                 │               
         └──────────────│   Redis Cache   │               
                        │   (Port 6379)   │               
                        │                 │               
                        └─────────────────┘               
```

### Container Details

#### **Frontend Container (React SPA)**
- **Technology**: React 18 + TypeScript + Vite
- **Port**: 5000 (served by Express in production)
- **Responsibilities**:
  - User interface for authentication flows
  - Admin dashboard for user/role management
  - Client-side routing and state management
  - JWT token handling and refresh logic

#### **Backend Container (Express API)**
- **Technology**: Node.js + Express + TypeScript
- **Port**: 5000 (unified port for API and static files)
- **Responsibilities**:
  - RESTful API endpoints
  - JWT authentication and authorization
  - MFA implementation
  - Audit logging
  - OAuth2 flows

#### **Database Container (PostgreSQL)**
- **Technology**: PostgreSQL 15 with Neon serverless driver
- **Port**: 5432
- **Responsibilities**:
  - User data persistence
  - Role and permission management
  - Audit trail storage
  - JWT key rotation history

#### **Cache Container (Redis)**
- **Technology**: Redis 7
- **Port**: 6379
- **Responsibilities**:
  - Session storage
  - Rate limiting counters
  - Temporary token storage

---

## Component Diagram

### Backend Components

#### **Authentication Components**
```
auth.middleware.ts      - JWT validation and route protection
auth.service.ts         - Core authentication business logic
google-oauth.service.ts - Google OAuth2 integration
mfa.service.ts         - Multi-factor authentication logic
jwt.service.ts         - JWT token management and key rotation
```

#### **User Management Components**
```
user.service.ts        - User CRUD operations and business logic
audit.service.ts       - Audit logging and compliance tracking
email.service.ts       - Email notifications and verification
```

#### **Security Components**
```
security.middleware.ts - Rate limiting, security headers, sanitization
crypto.ts             - Encryption utilities (AES-256-GCM)
domain-validation.ts  - Redirect URL validation
validation.ts         - Request validation schemas
```

#### **Storage Components**
```
storage.ts            - Database abstraction layer
db.ts                 - Database connection and configuration
schema.ts             - Drizzle ORM schema definitions
```

### Frontend Components

#### **Authentication Components**
```
AuthProvider          - Authentication context and state management
ProtectedRoute        - Route-level access control
LoginForm            - User authentication interface
RegisterForm         - User registration interface
MFA                  - Multi-factor authentication UI
```

#### **Admin Components**
```
Dashboard            - Overview and metrics display
Users               - User management interface
Roles               - Role and permission management
ApiKeys             - API key management
Audit               - Audit log viewer
Settings            - System configuration
```

#### **Shared Components**
```
ThemeProvider       - Dark/light mode management
PermissionProvider  - Permission-based UI rendering
QueryClient         - TanStack Query configuration
UI Components       - Radix UI + shadcn/ui design system
```

---

## Code Diagram

### Directory Structure
```
├── client/                 # React Frontend
│   ├── src/
│   │   ├── components/    # Reusable UI components
│   │   ├── hooks/         # Custom React hooks
│   │   ├── lib/           # Utility libraries
│   │   ├── pages/         # Route components
│   │   └── types/         # TypeScript type definitions
│   └── index.css          # Global styles and CSS variables
├── server/                 # Express Backend
│   ├── config/            # Configuration files
│   ├── middleware/        # Express middleware
│   ├── services/          # Business logic services
│   ├── utils/             # Utility functions
│   ├── index.ts           # Application entry point
│   ├── routes.ts          # API route definitions
│   ├── storage.ts         # Database abstraction
│   └── db.ts              # Database connection
├── shared/                 # Shared code
│   └── schema.ts          # Database schema and Zod validations
├── k8s/                   # Kubernetes manifests
├── scripts/               # Database setup scripts
└── tests/                 # Test files
```

### Key Implementation Patterns

#### **Authentication Flow**
1. **Login Request** → `auth.service.ts` validates credentials
2. **JWT Generation** → `jwt.service.ts` creates signed tokens
3. **Token Validation** → `auth.middleware.ts` verifies requests
4. **Permission Check** → Role-based access control enforcement
5. **Audit Logging** → `audit.service.ts` tracks all actions

#### **Database Schema Design**
```typescript
// Primary entities with relationships
users ──┐
        ├─► roles ──► permissions
        ├─► userSessions
        ├─► auditLogs
        └─► userTokens

// Security entities
jwtKeys ──► keyRotation history
allowedDomains ──► redirect validation
clients ──► OAuth2 client management
```

---

## Technology Stack

### **Backend Technologies**
| Category | Technology | Version | Purpose |
|----------|------------|---------|---------|
| Runtime | Node.js | Latest | JavaScript runtime |
| Framework | Express.js | 4.21.2 | Web application framework |
| Language | TypeScript | 5.6.3 | Type-safe development |
| ORM | Drizzle | 0.39.1 | Type-safe database operations |
| Database | PostgreSQL | 15+ | Primary data store |
| Cache | Redis | 7+ | Session storage and caching |
| Authentication | JWT | RS256 | Asymmetric token signing |
| Encryption | bcrypt | 6.0.0 | Password hashing |
| MFA | Speakeasy | 2.0.0 | TOTP implementation |
| Security | Helmet | 8.1.0 | Security headers |
| Validation | Zod | 3.24.2 | Runtime type validation |

### **Frontend Technologies**
| Category | Technology | Version | Purpose |
|----------|------------|---------|---------|
| Framework | React | 18.3.1 | UI library |
| Language | TypeScript | 5.6.3 | Type-safe development |
| Build Tool | Vite | 5.4.20 | Development and build tooling |
| UI Library | Radix UI | Various | Accessible component primitives |
| Design System | shadcn/ui | Latest | Pre-built components |
| Styling | Tailwind CSS | 3.4.17 | Utility-first CSS framework |
| State Management | TanStack Query | 5.60.5 | Server state management |
| Routing | Wouter | 3.3.5 | Lightweight routing |
| Forms | React Hook Form | 7.55.0 | Form state management |
| Icons | Lucide React | 0.453.0 | Icon library |

### **DevOps & Deployment**
| Category | Technology | Version | Purpose |
|----------|------------|---------|---------|
| Containerization | Docker | Latest | Application packaging |
| Orchestration | Kubernetes | 1.28+ | Container orchestration |
| Service Mesh | - | - | Not implemented |
| Load Balancer | AWS NLB | Latest | Traffic distribution |
| Certificate | Let's Encrypt | Latest | TLS certificates |
| Monitoring | Prometheus | Latest | Metrics collection |
| Visualization | Grafana | Latest | Metrics dashboard |
| Service Discovery | Consul | 1.16 | Service registry |

---

## Database Design

### **Core Tables Schema**

#### Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE,
    phone_number TEXT,
    name TEXT NOT NULL,
    password_hash TEXT, -- Optional for OAuth users
    role_id UUID NOT NULL REFERENCES roles(id),
    is_email_verified BOOLEAN NOT NULL DEFAULT false,
    is_active BOOLEAN NOT NULL DEFAULT true,
    mfa_secret_encrypted TEXT, -- AES-256-GCM encrypted
    google_id TEXT, -- Google OAuth user ID
    profile_picture TEXT,
    last_login TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);
```

#### Roles & Permissions
```sql
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    permissions TEXT[] NOT NULL DEFAULT ARRAY[]::text[],
    is_active BOOLEAN NOT NULL DEFAULT true
);
```

#### Security Tables
```sql
-- JWT Key Management
CREATE TABLE jwt_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    private_key_encrypted TEXT NOT NULL, -- AES-256-GCM encrypted
    algorithm TEXT NOT NULL DEFAULT 'RS256',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    expires_at TIMESTAMP
);

-- Audit Logging
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    action audit_action NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);
```

### **Indexes for Performance**
```sql
-- User lookup optimizations
CREATE INDEX users_email_idx ON users(email);
CREATE INDEX users_active_idx ON users(is_active);
CREATE INDEX users_role_idx ON users(role_id);

-- Audit log optimizations
CREATE INDEX audit_logs_user_id_idx ON audit_logs(user_id);
CREATE INDEX audit_logs_action_idx ON audit_logs(action);
CREATE INDEX audit_logs_created_at_idx ON audit_logs(created_at DESC);
```

---

## Deployment Architecture

### **Kubernetes Production Deployment**

#### **Deployment Configuration**
```yaml
# Located in k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: idm-service
  namespace: prasuti-ai
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    spec:
      containers:
      - name: idm-service
        image: prasuti/idm-service:latest
        ports:
        - containerPort: 5000
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

#### **Service Configuration**
```yaml
# External Load Balancer
apiVersion: v1
kind: Service
metadata:
  name: idm-service
spec:
  type: LoadBalancer
  ports:
  - port: 80
    targetPort: 5000
  - port: 443
    targetPort: 5000

# Internal Cluster Service
apiVersion: v1
kind: Service
metadata:
  name: idm-service-internal
spec:
  type: ClusterIP
  ports:
  - port: 5000
    targetPort: 5000
```

#### **Ingress Configuration**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: idm-service-ingress
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/rate-limit: "100"
spec:
  tls:
  - hosts:
    - idm.prasuti.ai
    secretName: idm-tls-secret
  rules:
  - host: idm.prasuti.ai
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: idm-service-internal
            port:
              number: 5000
```

### **Docker Compose Development**

#### **Multi-Service Stack**
```yaml
# Located in docker-compose.yml
version: '3.8'
services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: idm
      POSTGRES_USER: idm_user
      POSTGRES_PASSWORD: idm_password_dev
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --appendonly yes --requirepass redis_password_dev

  idm-service:
    build: .
    ports:
      - "5000:5000"
    environment:
      NODE_ENV: development
      DATABASE_URL: postgres://idm_user:idm_password_dev@postgres:5432/idm
      JWT_ISSUER: https://idm.prasuti.ai
    depends_on:
      - postgres
      - redis

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3001:3000"
    environment:
      GF_SECURITY_ADMIN_PASSWORD: admin_password_dev
```

### **Security Configuration**

#### **Network Policies**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: idm-service-netpol
spec:
  podSelector:
    matchLabels:
      app: idm-service
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: nginx-ingress
    ports:
    - protocol: TCP
      port: 5000
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgres
    ports:
    - protocol: TCP
      port: 5432
```

#### **Pod Security Context**
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
    - ALL
```

---

## Operations & Commands

### **Development Commands**

#### **Project Setup**
```bash
# Clone and setup
git clone <repository-url>
cd idm-service

# Install dependencies
npm install

# Setup environment variables
cp .env.example .env
# Edit .env with your configuration

# Start development environment
docker-compose up -d postgres redis  # Start dependencies
npm run dev                          # Start development server
```

#### **Database Operations**
```bash
# Push schema changes to database
npm run db:push

# Force push (with data loss warning)
npm run db:push --force

# Setup initial database with roles and admin user
npm run setup-database

# Create admin user
npm run create-admin

# Initialize default roles
npm run init-default-roles

# Initialize allowed domains
npm run init-default-domains
```

#### **Development Workflow**
```bash
# Start development server
npm run dev                    # Runs on port 5000

# Type checking
npm run check                  # TypeScript compilation check

# Run tests
npm test                      # Jest test suite
npm run test:auth             # Authentication tests
npm run test:jwt              # JWT service tests
npm run test:user             # User service tests
```

### **Production Commands**

#### **Build and Deploy**
```bash
# Build for production
npm run build                 # Creates dist/ directory

# Start production server
npm start                     # Runs built application

# Docker build
docker build -t prasuti/idm-service:latest .

# Kubernetes deployment
kubectl apply -f k8s/         # Deploy all manifests
kubectl rollout restart deployment/idm-service  # Rolling update
```

#### **Maintenance Operations**
```bash
# Key rotation
npm run rotate-keys           # Rotate JWT signing keys

# Health checks
curl http://localhost:5000/health   # Basic health check
curl http://localhost:5000/ready    # Readiness check
curl http://localhost:5000/metrics  # Prometheus metrics
```

#### **Monitoring Commands**
```bash
# View application logs
kubectl logs -f deployment/idm-service

# Port forward for local access
kubectl port-forward service/idm-service 5000:5000

# Check pod status
kubectl get pods -l app=idm-service

# Scale deployment
kubectl scale deployment idm-service --replicas=5
```

### **Environment Variables**

#### **Required Configuration**
```bash
# Database
DATABASE_URL=postgres://user:password@host:port/database

# JWT Configuration
JWT_ISSUER=https://idm.prasuti.ai
JWT_AUD=prasuti-services
JWT_ACCESS_TTL=15m
JWT_REFRESH_TTL=30d

# Security
ENCRYPTION_MASTER_KEY=32-character-encryption-key
SESSION_SECRET=secure-session-secret

# Optional Services
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=redis-password
CONSUL_ADDR=http://consul:8500

# Email Configuration
EMAIL_SMTP_HOST=smtp.example.com
EMAIL_SMTP_PORT=587
EMAIL_SMTP_USER=user@example.com
EMAIL_SMTP_PASSWORD=email-password

# MFA Configuration
MFA_ISSUER=Prasuti.AI Hub
```

### **API Endpoints**

#### **Authentication Endpoints**
```bash
POST /api/auth/login          # User login
POST /api/auth/register       # User registration
POST /api/auth/logout         # User logout
POST /api/auth/refresh        # Token refresh
POST /api/auth/verify-token   # Token verification
GET  /api/auth/me            # Current user info

# Password Management
POST /api/auth/forgot-password    # Password reset request
POST /api/auth/reset-password     # Password reset confirmation
POST /api/auth/change-password    # Change current password
```

#### **OAuth Endpoints**
```bash
GET  /api/oauth/authorize     # OAuth2 authorization
POST /api/oauth/token         # Token exchange
GET  /api/oauth/google        # Google OAuth redirect
GET  /api/oauth/google/callback  # Google OAuth callback
```

#### **User Management**
```bash
GET    /api/users             # List users (admin)
POST   /api/users             # Create user (admin)
GET    /api/users/:id         # Get user details
PUT    /api/users/:id         # Update user
DELETE /api/users/:id         # Delete user (admin)
```

#### **MFA Endpoints**
```bash
POST /api/mfa/setup           # Setup MFA
POST /api/mfa/verify          # Verify MFA token
POST /api/mfa/backup-codes    # Generate backup codes
DELETE /api/mfa/disable       # Disable MFA
```

#### **Admin Endpoints**
```bash
GET  /api/roles               # List roles
POST /api/roles               # Create role
PUT  /api/roles/:id           # Update role
GET  /api/audit               # Audit logs
GET  /api/metrics             # System metrics
```

This comprehensive documentation provides a complete 4C's architectural view of the Identity Management System, covering all levels from high-level context to implementation details, deployment configurations, and operational procedures.