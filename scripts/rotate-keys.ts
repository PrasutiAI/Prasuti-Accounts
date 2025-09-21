#!/usr/bin/env tsx

/**
 * JWT Key Rotation Script
 * 
 * This script rotates JWT signing keys for the Identity Management System.
 * It creates new RSA key pairs and safely transitions from old to new keys.
 */

import { db } from '../server/db';
import { jwksKeys } from '@shared/schema';
import { cryptoUtils } from '../server/utils/crypto';
import { auditLogs } from '@shared/schema';
import { randomUUID } from 'crypto';
import readline from 'readline';

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

function prompt(question: string): Promise<string> {
  return new Promise((resolve) => {
    rl.question(question, resolve);
  });
}

interface RotateKeysOptions {
  force?: boolean;
  dryRun?: boolean;
  expiryDays?: number;
}

async function getCurrentKeys() {
  try {
    return await db.query.jwksKeys.findMany({
      orderBy: (keys, { desc }) => [desc(keys.createdAt)],
    });
  } catch (error) {
    console.error('Error fetching current keys:', error);
    throw error;
  }
}

async function createNewKeyPair(expiryDays: number = 90) {
  console.log('🔑 Generating new RSA key pair...');
  
  try {
    // Generate new RSA key pair
    const { publicKey, privateKey } = await cryptoUtils.generateRSAKeyPair();
    
    // Create key ID with timestamp
    const now = new Date();
    const kid = `key-${now.toISOString().split('T')[0]}-${now.getTime()}`;
    
    // Encrypt private key
    console.log('🔒 Encrypting private key...');
    const encryptedPrivateKey = await cryptoUtils.encrypt(privateKey);
    
    // Calculate expiry date
    const expiresAt = new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000);
    
    return {
      kid,
      publicKey,
      privateKeyEncrypted: encryptedPrivateKey,
      algorithm: 'RS256',
      isActive: true,
      expiresAt,
      createdAt: now,
    };
  } catch (error) {
    console.error('Error generating key pair:', error);
    throw error;
  }
}

async function rotateKeys(options: RotateKeysOptions): Promise<void> {
  try {
    console.log('🔄 JWT Key Rotation Process Starting...\n');

    // Get current keys
    console.log('📋 Fetching current keys...');
    const currentKeys = await getCurrentKeys();
    
    console.log(`Found ${currentKeys.length} existing keys:`);
    currentKeys.forEach(key => {
      const status = key.isActive ? '🟢 Active' : '🔴 Inactive';
      const expiry = new Date(key.expiresAt).toLocaleDateString();
      console.log(`   ${key.kid} - ${status} - Expires: ${expiry}`);
    });
    
    const activeKeys = currentKeys.filter(key => key.isActive);
    console.log(`\n${activeKeys.length} active keys found.`);

    if (activeKeys.length === 0) {
      console.log('⚠️  No active keys found. This is the first key generation.');
    }

    // Check if rotation is needed
    if (activeKeys.length > 0 && !options.force) {
      const newestKey = activeKeys[0];
      const daysUntilExpiry = Math.ceil(
        (new Date(newestKey.expiresAt).getTime() - Date.now()) / (1000 * 60 * 60 * 24)
      );
      
      if (daysUntilExpiry > 30) {
        console.log(`\n🔍 Current key expires in ${daysUntilExpiry} days.`);
        console.log('Consider rotation when less than 30 days remain.');
        
        const shouldContinue = await prompt('Continue with rotation anyway? (y/N): ');
        if (shouldContinue.toLowerCase() !== 'y' && shouldContinue.toLowerCase() !== 'yes') {
          console.log('❌ Key rotation cancelled.');
          rl.close();
          return;
        }
      }
    }

    if (options.dryRun) {
      console.log('\n🧪 DRY RUN MODE - No changes will be made');
    }

    // Create new key pair
    const newKey = await createNewKeyPair(options.expiryDays);
    
    console.log(`\n📝 New key details:`);
    console.log(`   Key ID: ${newKey.kid}`);
    console.log(`   Algorithm: ${newKey.algorithm}`);
    console.log(`   Expires: ${newKey.expiresAt.toLocaleDateString()}`);
    
    if (!options.dryRun) {
      const confirm = await prompt('\nProceed with key rotation? (y/N): ');
      if (confirm.toLowerCase() !== 'y' && confirm.toLowerCase() !== 'yes') {
        console.log('❌ Key rotation cancelled.');
        rl.close();
        return;
      }
    }

    if (!options.dryRun) {
      console.log('\n💾 Saving new key to database...');
      
      // Start transaction
      await db.transaction(async (tx) => {
        // Insert new key
        await tx.insert(jwksKeys).values(newKey);
        
        // Deactivate old keys (but keep them for token verification)
        if (activeKeys.length > 0) {
          console.log('🔄 Deactivating old keys...');
          for (const oldKey of activeKeys) {
            await tx.update(jwksKeys)
              .set({ isActive: false })
              .where((k) => k.kid === oldKey.kid);
          }
        }
        
        // Create audit log
        await tx.insert(auditLogs).values({
          id: randomUUID(),
          actorType: 'system',
          action: 'key_rotation',
          resource: 'system',
          metadata: {
            newKeyId: newKey.kid,
            deactivatedKeys: activeKeys.map(k => k.kid),
            rotationReason: options.force ? 'manual' : 'automatic',
          },
          success: true,
          createdAt: new Date(),
        });
      });
      
      console.log('✅ Key rotation completed successfully!');
      
      console.log('\n📝 Next steps:');
      console.log('1. New tokens will be signed with the new key');
      console.log('2. Old tokens remain valid until expiry');
      console.log('3. Old keys are kept for token verification');
      console.log('4. Update any external JWKS consumers');
      
      console.log('\n🔗 JWKS endpoint: /.well-known/jwks.json');
      console.log('🔍 Monitor logs for any verification issues');

    } else {
      console.log('\n✅ Dry run completed. No changes were made.');
      console.log('Remove --dry-run flag to perform actual rotation.');
    }

    // Clean up old expired keys (optional)
    if (!options.dryRun) {
      console.log('\n🧹 Cleaning up expired inactive keys...');
      const expiredKeys = currentKeys.filter(key => 
        !key.isActive && new Date(key.expiresAt) < new Date()
      );
      
      if (expiredKeys.length > 0) {
        const shouldCleanup = await prompt(`Found ${expiredKeys.length} expired keys. Remove them? (y/N): `);
        if (shouldCleanup.toLowerCase() === 'y' || shouldCleanup.toLowerCase() === 'yes') {
          for (const expiredKey of expiredKeys) {
            await db.delete(jwksKeys).where((k) => k.kid === expiredKey.kid);
          }
          console.log(`✅ Removed ${expiredKeys.length} expired keys.`);
        }
      } else {
        console.log('No expired keys found.');
      }
    }

  } catch (error) {
    console.error('❌ Key rotation failed:', error);
    throw error;
  } finally {
    rl.close();
  }
}

function parseArgs(): RotateKeysOptions {
  const args = process.argv.slice(2);
  const options: RotateKeysOptions = {};
  
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    switch (arg) {
      case '--force':
        options.force = true;
        break;
      case '--dry-run':
        options.dryRun = true;
        break;
      case '--expiry-days':
        if (args[i + 1]) {
          options.expiryDays = parseInt(args[i + 1], 10);
          if (isNaN(options.expiryDays) || options.expiryDays < 1) {
            console.error('❌ Invalid expiry days. Must be a positive number.');
            process.exit(1);
          }
          i++;
        }
        break;
      case '--help':
      case '-h':
        console.log(`
🔐 Identity Management System - JWT Key Rotation

Usage: tsx scripts/rotate-keys.ts [options]

Options:
  --force              Force rotation even if current key is not near expiry
  --dry-run            Preview changes without making them
  --expiry-days <n>    Set key expiry in days (default: 90)
  --help, -h           Show this help message

Examples:
  tsx scripts/rotate-keys.ts
  tsx scripts/rotate-keys.ts --dry-run
  tsx scripts/rotate-keys.ts --force --expiry-days 180

Best Practices:
  - Rotate keys before they expire (recommended: 30 days before)
  - Test in development before production rotation
  - Monitor application logs after rotation
  - Keep old keys until all tokens expire
  - Use --dry-run to preview changes

Security Notes:
  - Private keys are encrypted before storage
  - Old keys are kept for token verification
  - Audit logs are created for all rotations
  - JWKS endpoint is automatically updated
        `);
        process.exit(0);
      default:
        console.error(`❌ Unknown option: ${arg}`);
        console.error('Use --help for usage information.');
        process.exit(1);
    }
  }
  
  return options;
}

async function main() {
  try {
    const options = parseArgs();
    await rotateKeys(options);
  } catch (error) {
    console.error('❌ Script failed:', error);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}
