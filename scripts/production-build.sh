#!/bin/bash

# Production build script that includes all necessary setup steps
set -e

echo "🏗️  Starting production build..."

# Step 1: Build the frontend and backend
echo "📦 Building frontend and backend..."
npm run build

# Step 2: Run database setup (schema push, roles, JWT keys)
echo "🗄️  Setting up database..."
tsx scripts/setup-database.ts

echo "✅ Production build completed successfully!"
