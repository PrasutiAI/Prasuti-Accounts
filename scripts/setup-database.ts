#!/usr/bin/env tsx

import dotenv from 'dotenv';
import { execSync } from 'child_process';
import { existsSync, readFileSync } from 'fs';
import { resolve } from 'path';

// Load .env file, handling both missing and empty environment variables
const envPath = resolve(process.cwd(), '.env');
if (existsSync(envPath)) {
  // In development, always load .env; in production, only if DATABASE_URL is missing or empty
  const databaseUrlEmpty = !process.env.DATABASE_URL || process.env.DATABASE_URL.trim() === '';
  const shouldLoadEnv = process.env.NODE_ENV === 'development' || databaseUrlEmpty;
  
  if (shouldLoadEnv) {
    // If DATABASE_URL is empty but defined, we need to override it
    if (process.env.DATABASE_URL === '') {
      const envContent = readFileSync(envPath, 'utf8');
      const lines = envContent.split('\n');
      for (const line of lines) {
        const trimmedLine = line.trim();
        if (trimmedLine && !trimmedLine.startsWith('#') && trimmedLine.includes('=')) {
          const [key, ...valueParts] = trimmedLine.split('=');
          if (key === 'DATABASE_URL' && valueParts.length > 0) {
            process.env.DATABASE_URL = valueParts.join('=');
            console.log('🔧 Set DATABASE_URL from .env file (was empty)');
          }
        }
      }
    }
    
    dotenv.config({ path: envPath });
    console.log('🔧 Loaded environment variables from .env file');
  } else {
    console.log('🔧 Using existing environment variables (production mode with DATABASE_URL set)');
  }
} else {
  console.log('⚠️ No .env file found, using environment variables only');
}

interface SetupOptions {
  force?: boolean;
  verbose?: boolean;
}

async function checkDatabaseUrl(): Promise<boolean> {
  if (!process.env.DATABASE_URL) {
    console.error('❌ DATABASE_URL environment variable is not set');
    console.log('Make sure your database is provisioned and the environment variable is available');
    return false;
  }
  
  console.log('✅ DATABASE_URL is set');
  return true;
}

async function checkDatabaseConnection(): Promise<boolean> {
  try {
    // Import database connection to test it
    const { pool } = await import('../server/db');
    await pool.query('SELECT 1');
    console.log('✅ Database connection successful');
    return true;
  } catch (error) {
    console.error('❌ Database connection failed:', error instanceof Error ? error.message : String(error));
    return false;
  }
}

async function pushDatabaseSchema(options: SetupOptions): Promise<boolean> {
  try {
    console.log('🔄 Pushing database schema...');
    
    // In production, skip schema push as it should be done during deployment
    if (process.env.NODE_ENV === 'production') {
      console.log('⚠️ Skipping schema push in production (should be done during deployment)');
      return true;
    }
    
    // Call drizzle-kit directly to ensure --force flag is properly handled
    const pushCommand = options.force ? 'npx drizzle-kit push --force' : 'npx drizzle-kit push';
    execSync(pushCommand, { 
      stdio: options.verbose ? 'inherit' : 'pipe',
      cwd: process.cwd()
    });
    
    console.log('✅ Database schema pushed successfully');
    return true;
  } catch (error) {
    console.error('❌ Failed to push database schema:', error instanceof Error ? error.message : String(error));
    
    if (!options.force) {
      console.log('💡 Try running with --force flag to force push the schema');
    }
    return false;
  }
}

async function setupEncryptionKey(options: SetupOptions): Promise<boolean> {
  try {
    console.log('🔐 Setting up encryption key...');
    
    // Check if .env file exists and has ENCRYPTION_MASTER_KEY
    const envPath = resolve(process.cwd(), '.env');
    if (existsSync(envPath)) {
      const envContent = readFileSync(envPath, 'utf8');
      if (envContent.includes('ENCRYPTION_MASTER_KEY=') && !options.force) {
        console.log('✅ Encryption key already exists');
        return true;
      }
    }
    
    // Run the setup encryption key script
    const setupEncryptionKeyModule = await import('./setup-encryption-key');
    const encryptionKey = await setupEncryptionKeyModule.setupEncryptionKey({ force: options.force });
    
    // Ensure the key is set in the current process environment
    if (encryptionKey && !process.env.ENCRYPTION_MASTER_KEY) {
      process.env.ENCRYPTION_MASTER_KEY = encryptionKey;
    }
    
    console.log('✅ Encryption key setup completed');
    return true;
  } catch (error) {
    console.error('❌ Failed to setup encryption key:', error instanceof Error ? error.message : String(error));
    return false;
  }
}

async function initializeDefaultRoles(): Promise<boolean> {
  try {
    console.log('👥 Initializing default roles...');
    
    const initRolesModule = await import('./init-default-roles');
    await initRolesModule.initDefaultRoles();
    
    console.log('✅ Default roles initialized successfully');
    return true;
  } catch (error) {
    console.error('❌ Failed to initialize default roles:', error instanceof Error ? error.message : String(error));
    return false;
  }
}

async function initializeDefaultAllowedDomains(): Promise<boolean> {
  try {
    console.log('🌐 Initializing default allowed domains...');
    
    const initDomainsModule = await import('./init-default-domains');
    await initDomainsModule.initDefaultAllowedDomains();
    
    console.log('✅ Default allowed domains initialized successfully');
    return true;
  } catch (error) {
    console.error('❌ Failed to initialize default allowed domains:', error instanceof Error ? error.message : String(error));
    return false;
  }
}

async function initializeJwtKeys(): Promise<boolean> {
  try {
    console.log('🔑 Initializing JWT keys...');
    
    // Import and use JWT service to ensure keys exist
    const { jwtService } = await import('../server/services/jwt.service');
    const { storage } = await import('../server/storage');
    
    // Check if we have any active keys
    const activeKey = await storage.getActiveJwksKey();
    if (!activeKey) {
      console.log('🔄 No active JWT key found, rotating keys...');
      await jwtService.rotateKeys();
      console.log('✅ JWT keys initialized');
    } else {
      console.log('✅ JWT keys already exist');
    }
    
    return true;
  } catch (error) {
    console.error('❌ Failed to initialize JWT keys:', error instanceof Error ? error.message : String(error));
    return false;
  }
}

export async function setupDatabase(options: SetupOptions = {}): Promise<boolean> {
  console.log('🚀 Starting database setup...\n');

  // Step 1: Check DATABASE_URL
  if (!(await checkDatabaseUrl())) {
    return false;
  }

  // Step 2: Setup encryption key (needed before database operations)
  if (!(await setupEncryptionKey(options))) {
    return false;
  }

  // Step 3: Push database schema
  if (!(await pushDatabaseSchema(options))) {
    return false;
  }

  // Step 4: Check database connection
  if (!(await checkDatabaseConnection())) {
    return false;
  }

  // Step 5: Initialize default roles
  if (!(await initializeDefaultRoles())) {
    return false;
  }

  // Step 6: Initialize default allowed domains
  if (!(await initializeDefaultAllowedDomains())) {
    return false;
  }

  // Step 7: Initialize JWT keys
  if (!(await initializeJwtKeys())) {
    return false;
  }

  console.log('\n🎉 Database setup completed successfully!');
  console.log('✅ Your application is ready to start\n');
  
  return true;
}

// Parse command line arguments
const args = process.argv.slice(2);
const options: SetupOptions = {};

for (const arg of args) {
  switch (arg) {
    case '--force':
      options.force = true;
      break;
    case '--verbose':
    case '-v':
      options.verbose = true;
      break;
    case '--help':
      console.log('Database Setup Script');
      console.log('Usage: tsx scripts/setup-database.ts [options]');
      console.log('');
      console.log('Options:');
      console.log('  --force     Force push database schema and regenerate keys');
      console.log('  --verbose   Show verbose output from database operations');
      console.log('  --help      Show this help message');
      process.exit(0);
    default:
      console.error(`Unknown option: ${arg}`);
      console.log('Use --help for available options');
      process.exit(1);
  }
}

// Run the setup when executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  setupDatabase(options)
    .then((success) => {
      process.exit(success ? 0 : 1);
    })
    .catch((error) => {
      console.error('❌ Database setup failed:', error);
      process.exit(1);
    });
}