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

    const { passwordHash: _, mfaSecret: __, ...userWithoutSensitiveData } = user;
    return userWithoutSensitiveData;
  }

  async createUser(userData: InsertUser & { sendWelcomeEmail?: boolean }, actorId?: string): Promise<SelectUser> {
    // Check if user already exists
    const existingUser = await storage.getUserByEmail(userData.email);
    if (existingUser) {
      throw new Error('User already exists with this email');
    }

    // Hash password
    const passwordHash = await bcrypt.hash(userData.password, this.saltRounds);

    // Create user
    const user = await storage.createUser({
      ...userData,
      passwordHash,
    });

    // Log audit event
    await auditService.log({
      actorId,
      action: 'user_create',
      resource: 'user',
      resourceId: user.id,
      metadata: {
        email: user.email,
        role: user.role,
        sendWelcomeEmail: userData.sendWelcomeEmail,
      },
      success: true,
    });

    const { passwordHash: _, mfaSecret: __, ...userWithoutSensitiveData } = user;
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

    const { passwordHash: _, mfaSecret: __, ...userWithoutSensitiveData } = updatedUser;
    return userWithoutSensitiveData;
  }

  async deleteUser(id: string, actorId?: string): Promise<boolean> {
    const existingUser = await storage.getUser(id);
    if (!existingUser) {
      throw new Error('User not found');
    }

    // Don't allow deletion of the last admin
    if (existingUser.role === 'admin') {
      const allUsers = await storage.getAllUsers();
      const adminCount = allUsers.filter(u => u.role === 'admin' && u.id !== id).length;
      if (adminCount === 0) {
        throw new Error('Cannot delete the last admin user');
      }
    }

    const deleted = await storage.deleteUser(id);

    if (deleted) {
      // Revoke all refresh tokens
      await storage.revokeUserRefreshTokens(id);

      // Log audit event
      await auditService.log({
        actorId,
        action: 'user_delete',
        resource: 'user',
        resourceId: id,
        metadata: {
          email: existingUser.email,
          role: existingUser.role,
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
    await storage.revokeUserRefreshTokens(id);

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

  async toggleUserStatus(id: string, status: 'active' | 'inactive' | 'blocked', actorId?: string): Promise<SelectUser | undefined> {
    const updatedUser = await storage.updateUser(id, { status });
    if (!updatedUser) return undefined;

    // If blocking user, revoke all refresh tokens
    if (status === 'blocked') {
      await storage.revokeUserRefreshTokens(id);
    }

    // Log audit event
    await auditService.log({
      actorId,
      action: 'user_update',
      resource: 'user',
      resourceId: id,
      metadata: {
        status_change: status,
      },
      success: true,
    });

    const { passwordHash: _, mfaSecret: __, ...userWithoutSensitiveData } = updatedUser;
    return userWithoutSensitiveData;
  }

  async getUserStats(): Promise<{
    totalUsers: number;
    activeUsers: number;
    pendingUsers: number;
    blockedUsers: number;
    usersByRole: Record<string, number>;
    mfaEnabledUsers: number;
  }> {
    const allUsers = await storage.getAllUsers(1000); // Get more users for stats
    
    const stats = {
      totalUsers: allUsers.length,
      activeUsers: allUsers.filter(u => u.status === 'active').length,
      pendingUsers: allUsers.filter(u => u.status === 'pending').length,
      blockedUsers: allUsers.filter(u => u.status === 'blocked').length,
      usersByRole: {} as Record<string, number>,
      mfaEnabledUsers: allUsers.filter(u => u.mfaEnabled).length,
    };

    // Count users by role
    allUsers.forEach(user => {
      stats.usersByRole[user.role] = (stats.usersByRole[user.role] || 0) + 1;
    });

    return stats;
  }
}

export const userService = new UserService();
