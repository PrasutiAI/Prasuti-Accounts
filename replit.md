# Prasuti.AI Identity Management Service (IDM)

## Overview

This is a production-ready Identity & Access Management (IDM) microservice built as a full-stack application. The system provides comprehensive authentication, authorization, and user management capabilities for the Prasuti.AI ecosystem. It features a Node.js/TypeScript backend with Express serving RESTful APIs, and a React frontend with modern UI components for administration. The service implements JWT-based authentication with RS256 signing, role-based access control (RBAC), multi-factor authentication (MFA), OAuth2 endpoints, and comprehensive audit logging.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Full-Stack Monorepo Structure
The application uses a monorepo approach with three main directories:
- `client/` - React frontend with TypeScript and Tailwind CSS
- `server/` - Node.js/Express backend with TypeScript
- `shared/` - Common schemas and types shared between frontend and backend

### Frontend Architecture
- **Framework**: React 18 with TypeScript and Vite for development/build tooling
- **UI Library**: Radix UI components with shadcn/ui design system and Tailwind CSS
- **State Management**: TanStack Query for server state management and caching
- **Routing**: Wouter for client-side routing
- **Forms**: React Hook Form with Zod validation
- **Authentication**: Context-based auth provider with JWT token management

### Backend Architecture
- **Framework**: Express.js with TypeScript for type safety
- **Authentication**: JWT tokens with RS256 asymmetric signing and refresh token rotation
- **Authorization**: Role-based access control (RBAC) with middleware-based enforcement
- **Security Features**: MFA with TOTP, password hashing with bcrypt, rate limiting, audit logging
- **API Design**: RESTful endpoints with OpenAPI documentation

### Database Layer
- **ORM**: Drizzle ORM for type-safe database operations
- **Database**: PostgreSQL with Neon serverless driver
- **Migrations**: Drizzle Kit for schema migrations
- **Schema Design**: Comprehensive user management with roles, permissions, audit logs, JWT keys, and verification tokens

### Security Implementation
- **JWT Management**: RS256 key pairs with automated rotation capability
- **Encryption**: AES-256-GCM for sensitive data at rest (MFA secrets, keys)
- **Password Security**: bcrypt with 12 salt rounds
- **MFA Support**: TOTP-based authentication with backup codes using speakeasy
- **Audit Trail**: Comprehensive logging of all security events and user actions

### Service Architecture
- **Layered Design**: Clear separation between routes, services, storage, and utilities
- **Dependency Injection**: Service-based architecture with clean interfaces
- **Error Handling**: Centralized error handling with structured responses
- **Health Checks**: Kubernetes-ready health and readiness endpoints

## External Dependencies

### Core Infrastructure
- **Database**: PostgreSQL (via Neon serverless for development/cloud deployment)
- **Caching**: Redis (optional, configured for session storage)
- **Service Discovery**: Consul support for microservices registration

### Authentication & Security
- **JWT Library**: jsonwebtoken for token creation and verification
- **Crypto**: Node.js crypto module for key generation and encryption
- **Password Hashing**: bcrypt for secure password storage
- **MFA**: speakeasy for TOTP generation and QR code creation with qrcode library

### Frontend Dependencies
- **Component Library**: Radix UI primitives with shadcn/ui styling
- **Styling**: Tailwind CSS with CSS variables for theming
- **Data Fetching**: TanStack Query for API state management
- **Form Handling**: React Hook Form with Hookform resolvers for Zod integration
- **Icons**: Lucide React for consistent iconography

### Development & Testing
- **Build Tools**: Vite for frontend bundling, esbuild for backend compilation
- **Testing**: Jest and Supertest for unit and integration testing
- **Type Safety**: TypeScript with strict configuration across the stack
- **Validation**: Zod schemas shared between frontend and backend

### Deployment & Operations
- **Containerization**: Docker support with multi-stage builds
- **Orchestration**: Kubernetes manifests for production deployment
- **Monitoring**: Prometheus metrics endpoint for observability
- **Logging**: Structured JSON logging for audit and application events