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

## 🔧 Quick Start

### 1. Environment Setup

```bash
# Clone the repository
git clone https://github.com/prasuti-ai/idm-service.git
cd idm-service

# Install dependencies
npm install

# Copy environment template
cp .env.example .env
