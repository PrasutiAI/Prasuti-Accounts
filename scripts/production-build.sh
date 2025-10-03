#!/bin/bash

# Production build script that includes all necessary setup steps
set -e

echo "🏗️  Starting production build..."

# Set production environment for all steps
export NODE_ENV=production

# Step 1: Build the frontend and backend
echo "📦 Building frontend and backend..."
npm run build

# Step 2: Run database setup (schema push, roles, JWT keys)
echo "🗄️  Setting up database for production..."
tsx scripts/setup-database.ts

echo "✅ Production build completed successfully!"
