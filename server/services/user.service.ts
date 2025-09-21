import bcrypt from 'bcrypt';
import { storage } from '../storage';
import { auditService } from './audit.service';
import type { InsertUser, User, SelectUser } from '@shared/schema';

export class UserService {
  private readonly saltRounds = 12;

  async getAllUsers(page = 1, limit = 50): Promise<{ users: SelectUser[]; total: number; pages: number }> {
    const offset = (page - 1) * limit;
    const [users, total] = await Promise.all([
      storage.getAllUsers(limit, offset),
      storage.getUsersCount(),
    ]);

    return {
      users,
      total,
      pages: Math.ceil(total / limit),
    };
  }

  async getUserById(id: string): Promise<SelectUser | undefined> {
    const user = await storage.getUser(id);
    if (!user) return undefined;

    const { passwordHash: _, mfaSecretEncrypted: __, ...userWithoutSensitiveData } = user;
    return userWithoutSensitiveData;
  }

  async createUser(userData: InsertUser & { sendWelcomeEmail?: boolean }, actorId?: string): Promise<SelectUser> {
    // Check if user already exists
    const existingUser = await storage.getUserByEmail(userData.email);
    if (existingUser) {
      throw new Error('User already exists with this email');
    }

    // Create user (password will be hashed in storage layer)
    const user = await storage.createUser(userData);

    // Log audit event
    await storage.createUserAuditLog({
      userId: user.id,
      action: 'user_create',
      details: {
        email: user.email,
        roleId: user.roleId,
        sendWelcomeEmail: userData.sendWelcomeEmail,
        success: true,
      },
    });

    const { passwordHash: _, mfaSecretEncrypted: __, ...userWithoutSensitiveData } = user;
    return userWithoutSensitiveData;
  }

  async updateUser(
    id: string,
    updates: Partial<Omit<User, 'id' | 'passwordHash' | 'createdAt' | 'updatedAt'>>,
    actorId?: string
  ): Promise<SelectUser | undefined> {
    const existingUser = await storage.getUser(id);
    if (!existingUser) {
      throw new Error('User not found');
    }

    const updatedUser = await storage.updateUser(id, updates);
    if (!updatedUser) return undefined;

    // Log audit event
    await auditService.log({
      actorId,
      action: 'user_update',
      resource: 'user',
      resourceId: id,
      metadata: {
        changes: updates,
      },
      success: true,
    });

    const { passwordHash: _, mfaSecretEncrypted: __, ...userWithoutSensitiveData } = updatedUser;
    return userWithoutSensitiveData;
  }

  async deleteUser(id: string, actorId?: string): Promise<boolean> {
    const existingUser = await storage.getUser(id);
    if (!existingUser) {
      throw new Error('User not found');
    }

    // Don't allow deletion of the last admin
    const userRole = await storage.getRole(existingUser.roleId);
    if (userRole?.name === 'admin') {
      const allUsers = await storage.getAllUsers();
      const adminRole = await storage.getRoleByName('admin');
      if (adminRole) {
        const adminCount = allUsers.filter(u => u.roleId === adminRole.id && u.id !== id).length;
        if (adminCount === 0) {
          throw new Error('Cannot delete the last admin user');
        }
      }
    }

    const deleted = await storage.deleteUser(id);

    if (deleted) {
      // Revoke all refresh tokens
      await storage.revokeUserSessions(id);

      // Log audit event
      await auditService.log({
        actorId,
        action: 'user_delete',
        resource: 'user',
        resourceId: id,
        metadata: {
          email: existingUser.email,
          roleId: existingUser.roleId,
        },
        success: true,
      });
    }

    return deleted;
  }

  async changeUserPassword(id: string, newPassword: string, actorId?: string): Promise<void> {
    const passwordHash = await bcrypt.hash(newPassword, this.saltRounds);
    
    const updatedUser = await storage.updateUser(id, { passwordHash });
    if (!updatedUser) {
      throw new Error('User not found');
    }

    // Revoke all refresh tokens to force re-login
    await storage.revokeUserSessions(id);

    // Log audit event
    await auditService.log({
      actorId,
      action: 'password_change',
      resource: 'user',
      resourceId: id,
      metadata: {
        changed_by_admin: actorId !== id,
      },
      success: true,
    });
  }

  async toggleUserStatus(id: string, isActive: boolean, actorId?: string): Promise<SelectUser | undefined> {
    const updatedUser = await storage.updateUser(id, { isActive });
    if (!updatedUser) return undefined;

    // If deactivating user, revoke all refresh tokens
    if (!isActive) {
      await storage.revokeUserSessions(id);
    }

    // Log audit event
    await auditService.log({
      actorId,
      action: 'user_update',
      resource: 'user',
      resourceId: id,
      metadata: {
        status_change: isActive ? 'active' : 'inactive',
      },
      success: true,
    });

    const { passwordHash: _, mfaSecretEncrypted: __, ...userWithoutSensitiveData } = updatedUser;
    return userWithoutSensitiveData;
  }

  async getUserStats(): Promise<{
    totalUsers: number;
    activeUsers: number;
    verifiedUsers: number;
    unverifiedUsers: number;
    usersByRole: Record<string, number>;
    mfaEnabledUsers: number;
  }> {
    const [allUsers, allRoles] = await Promise.all([
      storage.getAllUsers(1000), // Get more users for stats
      storage.getAllRoles()
    ]);
    
    const stats = {
      totalUsers: allUsers.length,
      activeUsers: allUsers.filter(u => u.isActive).length,
      verifiedUsers: allUsers.filter(u => u.isEmailVerified).length,
      unverifiedUsers: allUsers.filter(u => !u.isEmailVerified).length,
      usersByRole: {} as Record<string, number>,
      mfaEnabledUsers: 0,
    };

    // Count users by role and calculate MFA enabled users
    let mfaCount = 0;
    for (const user of allUsers) {
      // Count by role
      const role = allRoles.find(r => r.id === user.roleId);
      const roleName = role?.name || 'unknown';
      stats.usersByRole[roleName] = (stats.usersByRole[roleName] || 0) + 1;
      
      // Count MFA enabled (need full user record for this)
      const fullUser = await storage.getUser(user.id);
      if (fullUser?.mfaSecretEncrypted) {
        mfaCount++;
      }
    }
    
    stats.mfaEnabledUsers = mfaCount;

    return stats;
  }
}

export const userService = new UserService();
