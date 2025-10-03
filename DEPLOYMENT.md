# Deployment Configuration Guide

## Overview

This application is optimized for fast deployment health checks. The server starts **immediately** and responds to health checks within milliseconds, while database setup runs in the background (development) or during build (production).

## Key Changes

### 1. Server Startup Flow

The server now follows this optimized startup sequence:
1. **Register routes** (including health endpoints) 
2. **Start listening on port** (health checks succeed immediately)
3. **Background tasks** (database setup in development only)

### 2. Health Check Endpoints

- **`/` (root)**: Serves the frontend immediately (use for deployment health checks)
- **`/health`**: JSON health status, no database dependency
- **`/ready`**: Checks database connectivity (use for readiness probes after startup)

### 3. Production vs Development

- **Development mode**: 
  - Server starts immediately
  - Database setup runs in background (non-blocking)
  - Full database setup on every restart (schema push, roles, JWT keys)
  
- **Production mode**: 
  - Server starts immediately
  - Database setup skipped entirely (runs during build phase)
  - No blocking operations at startup

### 4. Build Process

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
Build command: bash scripts/production-build.sh
Run command: npm run start
```

Or manually:
```
Build command: sh -c "export NODE_ENV=production && npm run build && tsx scripts/setup-database.ts"
Run command: npm run start
```

**For Other Platforms:**

Ensure your build command sets NODE_ENV=production:
```bash
export NODE_ENV=production && npm run build && tsx scripts/setup-database.ts
```

## Environment Variables

Required for production:
- `DATABASE_URL`: PostgreSQL connection string
- `ENCRYPTION_MASTER_KEY`: Encryption key for sensitive data (auto-generated during build)
- `NODE_ENV=production`: Ensures production optimizations

## Health Check Configuration

Configure your deployment platform to use:
- **Health check endpoint**: `/` or `/health` (both respond in <100ms)
- **Health check timeout**: 5-10 seconds
- **Startup timeout**: 10-15 seconds (server starts in <3 seconds)
- **Initial delay**: 5 seconds (wait for server to initialize)

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
