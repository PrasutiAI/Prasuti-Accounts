import { storage } from '../server/storage';
import { insertRoleSchema } from '../shared/schema';

const defaultRoles = [
  {
    name: 'admin',
    description: 'Administrator with full system access',
    permissions: ['*'], // All permissions
    isActive: true,
  },
  {
    name: 'developer',
    description: 'Developer with technical access to users, API keys, and system settings',
    permissions: [
      'dashboard:read',
      'users:read', 'users:update',
      'roles:read', 
      'clients:*', 
      'api-keys:*', 
      'audit:read',
      'settings:read', 'settings:update',
      'profile:*'
    ],
    isActive: true,
  },
  {
    name: 'user',
    description: 'Regular user with access to dashboard and personal settings',
    permissions: [
      'dashboard:read',
      'profile:*',
      'settings:read'
    ],
    isActive: true,
  },
  {
    name: 'guest',
    description: 'Guest user with limited access',
    permissions: [
      'dashboard:read'
    ],
    isActive: true,
  }
];

export async function initDefaultRoles() {
  console.log('Initializing default roles...');
  
  for (const roleData of defaultRoles) {
    try {
      // Check if role already exists
      const existingRole = await storage.getRoleByName(roleData.name);
      
      if (existingRole) {
        console.log(`Role '${roleData.name}' already exists. Updating permissions...`);
        
        // Update permissions if they've changed
        await storage.updateRole(existingRole.id, {
          permissions: roleData.permissions,
          description: roleData.description,
        });
        
        console.log(`✅ Updated role '${roleData.name}'`);
      } else {
        // Create new role
        const validatedRole = insertRoleSchema.parse(roleData);
        const newRole = await storage.createRole(validatedRole);
        
        console.log(`✅ Created role '${newRole.name}' with ${newRole.permissions.length} permissions`);
      }
    } catch (error) {
      console.error(`❌ Error processing role '${roleData.name}':`, error);
    }
  }
  
  console.log('✅ Default roles initialization completed!');
}

// Auto-run when executed directly (only when run as a standalone script)
if (import.meta.url === `file://${process.argv[1]}`) {
  initDefaultRoles()
    .then(() => {
      console.log('Script completed successfully');
      process.exit(0);
    })
    .catch((error) => {
      console.error('Failed to initialize roles:', error);
      process.exit(1);
    });
}