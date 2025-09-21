#!/usr/bin/env tsx

import { randomBytes } from 'crypto';
import { writeFileSync, existsSync, readFileSync } from 'fs';
import { resolve } from 'path';

interface SetupKeyOptions {
  force?: boolean;
  output?: boolean;
}

async function generateEncryptionKey(): Promise<string> {
  // Generate a cryptographically secure 256-bit (32 byte) key
  return randomBytes(32).toString('hex');
}

async function setupEncryptionKey(options: SetupKeyOptions = {}): Promise<void> {
  console.log('🔐 Setting up ENCRYPTION_MASTER_KEY for secure operation\n');

  // Check if .env file exists
  const envPath = resolve(process.cwd(), '.env');
  let envContent = '';
  
  if (existsSync(envPath)) {
    envContent = readFileSync(envPath, 'utf8');
    
    // Check if ENCRYPTION_MASTER_KEY already exists
    if (envContent.includes('ENCRYPTION_MASTER_KEY=') && !options.force) {
      console.log('✅ ENCRYPTION_MASTER_KEY already exists in .env file');
      console.log('Use --force flag to regenerate the key\n');
      return;
    }
  }

  // Generate new encryption key
  console.log('🔑 Generating new encryption key...');
  const newKey = await generateEncryptionKey();

  // Remove existing ENCRYPTION_MASTER_KEY line if it exists
  const lines = envContent.split('\n');
  const filteredLines = lines.filter(line => !line.startsWith('ENCRYPTION_MASTER_KEY='));

  // Add new ENCRYPTION_MASTER_KEY
  filteredLines.push(`ENCRYPTION_MASTER_KEY=${newKey}`);
  
  // Write to .env file
  const newContent = filteredLines.filter(line => line.trim()).join('\n') + '\n';
  writeFileSync(envPath, newContent);

  console.log('✅ ENCRYPTION_MASTER_KEY has been set in .env file');
  
  if (options.output) {
    console.log(`\n🔑 Generated key: ${newKey}`);
    console.log('⚠️  Keep this key secure and never commit it to version control!\n');
  } else {
    console.log('🔒 Key has been securely saved (not displayed for security)\n');
  }

  console.log('📋 Next steps:');
  console.log('1. Restart your application to use the new encryption key');
  console.log('2. Ensure .env is added to .gitignore');
  console.log('3. Set ENCRYPTION_MASTER_KEY in your production environment\n');
}

// Parse command line arguments
const args = process.argv.slice(2);
const options: SetupKeyOptions = {};

for (const arg of args) {
  switch (arg) {
    case '--force':
      options.force = true;
      break;
    case '--output':
    case '--show':
      options.output = true;
      break;
    case '--help':
      console.log('Setup ENCRYPTION_MASTER_KEY for secure authentication');
      console.log('Usage: npm run setup-key [options]');
      console.log('');
      console.log('Options:');
      console.log('  --force   Regenerate key even if it already exists');
      console.log('  --output  Display the generated key (security risk)');
      console.log('  --help    Show this help message');
      process.exit(0);
    default:
      console.error(`Unknown option: ${arg}`);
      console.log('Use --help for available options');
      process.exit(1);
  }
}

// Run the setup
setupEncryptionKey(options).catch((error) => {
  console.error('❌ Error setting up encryption key:', error);
  process.exit(1);
});