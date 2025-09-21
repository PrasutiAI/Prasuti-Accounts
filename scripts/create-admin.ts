#!/usr/bin/env tsx

/**
 * Create Admin User Script
 * 
 * This script creates an admin user for the Identity Management System.
 * Usage: tsx scripts/create-admin.ts [email] [password] [name]
 */

import { db } from '../server/db';
import { users } from '@shared/schema';
import bcrypt from 'bcrypt';
import { randomUUID } from 'crypto';
import readline from 'readline';

interface CreateAdminOptions {
  email?: string;
  password?: string;
  name?: string;
  force?: boolean;
}

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

function prompt(question: string): Promise<string> {
  return new Promise((resolve) => {
    rl.question(question, resolve);
  });
}

function promptPassword(question: string): Promise<string> {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer);
    });
    // Hide password input (basic implementation)
    (rl as any).input.on('keypress', (char: string, key: any) => {
      if (key && key.name === 'return') return;
      if (key && key.name === 'backspace') {
        process.stdout.write('\b \b');
      } else {
        process.stdout.write('*');
      }
    });
  });
}

async function validateEmail(email: string): Promise<boolean> {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

async function validatePassword(password: string): Promise<{ valid: boolean; errors: string[] }> {
  const errors: string[] = [];
  
  if (password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  }
  
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  if (!/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  
  if (!/[@$!%*?&]/.test(password)) {
    errors.push('Password must contain at least one special character (@$!%*?&)');
  }
  
  return {
    valid: errors.length === 0,
    errors,
  };
}

async function checkExistingUser(email: string): Promise<boolean> {
  try {
    const existingUsers = await db.query.users.findMany({
      where: (users, { eq }) => eq(users.email, email),
      limit: 1,
    });
    return existingUsers.length > 0;
  } catch (error) {
    console.error('Error checking existing user:', error);
    return false;
  }
}

async function createAdminUser(options: CreateAdminOptions): Promise<void> {
  try {
    console.log('🔐 Identity Management System - Create Admin User\n');

    let email = options.email;
    let password = options.password;
    let name = options.name;

    // Get email
    while (!email || !(await validateEmail(email))) {
      email = await prompt('Enter admin email: ');
      if (!(await validateEmail(email))) {
        console.log('❌ Invalid email format. Please try again.\n');
        email = '';
      }
    }

    // Check if user already exists
    if (await checkExistingUser(email)) {
      if (!options.force) {
        console.log(`❌ User with email ${email} already exists.`);
        console.log('Use --force flag to update existing user.\n');
        rl.close();
        return;
      } else {
        console.log(`⚠️  User with email ${email} already exists. Will update...`);
      }
    }

    // Get name
    while (!name || name.trim().length < 2) {
      name = await prompt('Enter admin full name: ');
      if (!name || name.trim().length < 2) {
        console.log('❌ Name must be at least 2 characters long. Please try again.\n');
        name = '';
      }
    }

    // Get password
    while (!password) {
      password = await promptPassword('Enter admin password (input hidden): ');
      console.log(''); // New line after password input
      
      const passwordValidation = await validatePassword(password);
      if (!passwordValidation.valid) {
        console.log('❌ Password does not meet requirements:');
        passwordValidation.errors.forEach(error => console.log(`   - ${error}`));
        console.log('');
        password = '';
      }
    }

    // Confirm password
    const confirmPassword = await promptPassword('Confirm admin password: ');
    console.log(''); // New line after password input
    
    if (password !== confirmPassword) {
      console.log('❌ Passwords do not match. Exiting...');
      rl.close();
      return;
    }

    console.log('\n📋 Creating admin user with the following details:');
    console.log(`   Email: ${email}`);
    console.log(`   Name: ${name}`);
    console.log(`   Role: admin`);
    console.log(`   Status: active`);
    console.log(`   Verified: true\n`);

    const confirm = await prompt('Proceed with creation? (y/N): ');
    if (confirm.toLowerCase() !== 'y' && confirm.toLowerCase() !== 'yes') {
      console.log('❌ Admin user creation cancelled.');
      rl.close();
      return;
    }

    // Get or create admin role
    console.log('🔍 Finding admin role...');
    let adminRole;
    try {
      const { storage } = await import('../server/storage');
      adminRole = await storage.getRoleByName('admin');
      if (!adminRole) {
        console.log('⚠️  Admin role not found, creating it...');
        adminRole = await storage.createRole({
          name: 'admin',
          description: 'Full system administrator access',
          permissions: ['*'], // All permissions
          isActive: true,
        });
      }
    } catch (error) {
      console.error('❌ Error handling admin role:', error);
      rl.close();
      return;
    }

    if (options.force && await checkExistingUser(email)) {
      // Update existing user using storage layer for proper hashing
      try {
        const existingUser = await storage.getUserByEmail(email);
        if (existingUser) {
          // Hash password for direct update (bypass storage.createUser)
          const passwordHash = await bcrypt.hash(password, 12);
          await storage.updateUser(existingUser.id, {
            name: name.trim(),
            passwordHash: passwordHash, // Already hashed for updateUser
            roleId: adminRole.id,
            isActive: true,
            isEmailVerified: true,
            updatedAt: new Date(),
          });
          console.log('✅ Admin user updated successfully!');
        }
      } catch (error) {
        console.error('❌ Error updating admin user:', error);
        rl.close();
        return;
      }
    } else {
      // Create new user using storage layer for proper hashing
      try {
        await storage.createUser({
          email: email.toLowerCase().trim(),
          name: name.trim(),
          password: password, // Let storage hash it
          roleId: adminRole.id,
          // Note: MFA will be disabled by default, email will be verified after creation
        });
        
        // Manually verify email since this is admin creation
        const createdUser = await storage.getUserByEmail(email.toLowerCase().trim());
        if (createdUser) {
          await storage.updateUser(createdUser.id, {
            isEmailVerified: true,
          });
        }
        
        console.log('✅ Admin user created successfully!');
      } catch (error) {
        console.error('❌ Error creating admin user:', error);
        rl.close();
        return;
      }
    }

    console.log('\n📝 Next steps:');
    console.log('1. Start the application with: npm run dev');
    console.log('2. Login at: http://localhost:5000/login');
    console.log('3. Consider enabling MFA for additional security');
    console.log('\n🚀 Your Identity Management System is ready!');

  } catch (error) {
    console.error('❌ Error creating admin user:', error);
    process.exit(1);
  } finally {
    rl.close();
  }
}

// Parse command line arguments
function parseArgs(): CreateAdminOptions {
  const args = process.argv.slice(2);
  const options: CreateAdminOptions = {};
  
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    if (arg === '--force') {
      options.force = true;
    } else if (arg === '--email' && args[i + 1]) {
      options.email = args[i + 1];
      i++;
    } else if (arg === '--password' && args[i + 1]) {
      options.password = args[i + 1];
      i++;
    } else if (arg === '--name' && args[i + 1]) {
      options.name = args[i + 1];
      i++;
    } else if (arg === '--help' || arg === '-h') {
      console.log(`
🔐 Identity Management System - Create Admin User

Usage: tsx scripts/create-admin.ts [options]

Options:
  --email <email>      Admin email address
  --password <pass>    Admin password
  --name <name>        Admin full name
  --force              Update existing user if email exists
  --help, -h           Show this help message

Interactive mode:
  If options are not provided, the script will prompt for input.

Examples:
  tsx scripts/create-admin.ts
  tsx scripts/create-admin.ts --email admin@example.com --name "Admin User"
  tsx scripts/create-admin.ts --force --email admin@example.com

Security Notes:
  - Passwords must be at least 8 characters long
  - Must contain uppercase, lowercase, numbers, and special characters
  - Admin users have full system access
  - Consider enabling MFA after creation
      `);
      process.exit(0);
    } else if (!options.email) {
      options.email = arg;
    } else if (!options.password) {
      options.password = arg;
    } else if (!options.name) {
      options.name = arg;
    }
  }
  
  return options;
}

// Main execution
async function main() {
  try {
    const options = parseArgs();
    await createAdminUser(options);
  } catch (error) {
    console.error('❌ Script failed:', error);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}
