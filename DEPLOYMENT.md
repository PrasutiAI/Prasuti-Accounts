# Deployment Configuration Guide

## Overview

This application has been optimized for fast deployment health checks by separating database setup from runtime startup.

## Key Changes

### 1. Production Startup Behavior

- **Development mode**: Runs full database setup on every restart (schema push, roles, JWT keys)
- **Production mode**: Skips database setup entirely - expects it to run during build phase

### 2. Health Check Endpoints

- **`/health`**: Immediate response, no database dependency (use for deployment health checks)
- **`/ready`**: Checks database connectivity (use for readiness probes)

### 3. Build Process

The application requires database setup during the build phase for production deployments.

#### Option A: Using the Build Script (Recommended)

Use the provided production build script:

```bash
bash scripts/production-build.sh
```

This script will:
1. Build the frontend and backend
2. Run database setup (schema push, roles, JWT keys)

#### Option B: Manual Build Configuration

Update your deployment configuration to run database setup during build:

**For Replit Deployments:**

In your deployment settings (`.replit` file or Publishing UI), configure:

```
Build command: sh -c "npm run build && tsx scripts/setup-database.ts"
Run command: npm run start
```

**For Other Platforms:**

Ensure your build command includes:
```bash
npm run build && tsx scripts/setup-database.ts
```

## Environment Variables

Required for production:
- `DATABASE_URL`: PostgreSQL connection string
- `ENCRYPTION_MASTER_KEY`: Encryption key for sensitive data (auto-generated during build)
- `NODE_ENV=production`: Ensures production optimizations

## Health Check Configuration

Configure your deployment platform to use:
- **Health check endpoint**: `/health`
- **Health check timeout**: 5 seconds (endpoint responds in <100ms)
- **Startup timeout**: 30 seconds (application starts in <10 seconds in production)

## Troubleshooting

### Deployment fails with "database setup failed"

**Cause**: Database setup is trying to run at startup in production mode

**Solution**: Ensure `NODE_ENV=production` is set and database setup runs during build

### Health checks timeout

**Cause**: Application not starting before health check timeout

**Solution**: 
1. Verify database setup runs during build, not startup
2. Check `/health` endpoint responds (should be <100ms)
3. Increase health check timeout to 10 seconds if needed

### Database not initialized

**Cause**: Database setup didn't run during build

**Solution**: Add `tsx scripts/setup-database.ts` to your build command
