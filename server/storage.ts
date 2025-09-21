import { users, clients, refreshTokens, jwksKeys, verificationTokens, auditLogs, roles, permissions, rolePermissions } from "@shared/schema";
import { db } from "./db";
import { eq, and, desc, sql } from "drizzle-orm";
import type { 
  User, 
  InsertUser, 
  SelectUser, 
  Client, 
  InsertClient, 
  RefreshToken, 
  JwksKey, 
  VerificationToken, 
  AuditLog, 
  InsertAuditLog,
  Role,
  Permission
} from "@shared/schema";

export interface IStorage {
  // User operations
  getUser(id: string): Promise<User | undefined>;
  getUserByEmail(email: string): Promise<User | undefined>;
  createUser(user: Omit<InsertUser, 'id'>): Promise<User>;
  updateUser(id: string, updates: Partial<User>): Promise<User | undefined>;
  deleteUser(id: string): Promise<boolean>;
  getAllUsers(limit?: number, offset?: number): Promise<SelectUser[]>;
  getUsersCount(): Promise<number>;
  
  // Client operations
  getClient(clientId: string): Promise<Client | undefined>;
  createClient(client: Omit<InsertClient, 'id'>): Promise<Client>;
  updateClient(id: string, updates: Partial<Client>): Promise<Client | undefined>;
  deleteClient(id: string): Promise<boolean>;
  getAllClients(): Promise<Client[]>;
  
  // Refresh token operations
  createRefreshToken(token: Omit<RefreshToken, 'id' | 'createdAt'>): Promise<RefreshToken>;
  getRefreshToken(tokenHash: string): Promise<RefreshToken | undefined>;
  revokeRefreshToken(tokenHash: string): Promise<boolean>;
  revokeUserRefreshTokens(userId: string): Promise<boolean>;
  
  // JWT keys operations
  getActiveJwksKey(): Promise<JwksKey | undefined>;
  getAllJwksKeys(): Promise<JwksKey[]>;
  createJwksKey(key: Omit<JwksKey, 'createdAt'>): Promise<JwksKey>;
  deactivateJwksKey(kid: string): Promise<boolean>;
  
  // Verification tokens
  createVerificationToken(token: Omit<VerificationToken, 'id' | 'createdAt'>): Promise<VerificationToken>;
  getVerificationToken(token: string): Promise<VerificationToken | undefined>;
  markTokenAsUsed(token: string): Promise<boolean>;
  
  // Audit logs
  createAuditLog(log: InsertAuditLog): Promise<AuditLog>;
  getAuditLogs(limit?: number, offset?: number): Promise<AuditLog[]>;
  
  // Roles and permissions
  getAllRoles(): Promise<Role[]>;
  getRoleWithPermissions(roleId: string): Promise<Role & { permissions: Permission[] } | undefined>;
  getAllPermissions(): Promise<Permission[]>;
  
  // System metrics
  getSystemMetrics(): Promise<{
    totalUsers: number;
    activeUsers: number;
    totalClients: number;
    activeKeys: number;
    recentAuditLogs: AuditLog[];
  }>;
}

export class DatabaseStorage implements IStorage {
  async getUser(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id)).limit(1);
    return user || undefined;
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.email, email)).limit(1);
    return user || undefined;
  }

  async createUser(user: Omit<InsertUser, 'id'>): Promise<User> {
    const [newUser] = await db.insert(users).values(user).returning();
    return newUser;
  }

  async updateUser(id: string, updates: Partial<User>): Promise<User | undefined> {
    const [updatedUser] = await db
      .update(users)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(users.id, id))
      .returning();
    return updatedUser || undefined;
  }

  async deleteUser(id: string): Promise<boolean> {
    const result = await db.delete(users).where(eq(users.id, id));
    return result.rowCount > 0;
  }

  async getAllUsers(limit = 50, offset = 0): Promise<SelectUser[]> {
    const result = await db
      .select({
        id: users.id,
        email: users.email,
        name: users.name,
        role: users.role,
        status: users.status,
        isVerified: users.isVerified,
        mfaEnabled: users.mfaEnabled,
        lastLogin: users.lastLogin,
        createdAt: users.createdAt,
        updatedAt: users.updatedAt,
      })
      .from(users)
      .limit(limit)
      .offset(offset)
      .orderBy(desc(users.createdAt));
    return result;
  }

  async getUsersCount(): Promise<number> {
    const [result] = await db.select({ count: sql<number>`count(*)` }).from(users);
    return result.count;
  }

  async getClient(clientId: string): Promise<Client | undefined> {
    const [client] = await db.select().from(clients).where(eq(clients.clientId, clientId)).limit(1);
    return client || undefined;
  }

  async createClient(client: Omit<InsertClient, 'id'>): Promise<Client> {
    const [newClient] = await db.insert(clients).values(client).returning();
    return newClient;
  }

  async updateClient(id: string, updates: Partial<Client>): Promise<Client | undefined> {
    const [updatedClient] = await db
      .update(clients)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(clients.id, id))
      .returning();
    return updatedClient || undefined;
  }

  async deleteClient(id: string): Promise<boolean> {
    const result = await db.delete(clients).where(eq(clients.id, id));
    return result.rowCount > 0;
  }

  async getAllClients(): Promise<Client[]> {
    return db.select().from(clients).orderBy(desc(clients.createdAt));
  }

  async createRefreshToken(token: Omit<RefreshToken, 'id' | 'createdAt'>): Promise<RefreshToken> {
    const [newToken] = await db.insert(refreshTokens).values(token).returning();
    return newToken;
  }

  async getRefreshToken(tokenHash: string): Promise<RefreshToken | undefined> {
    const [token] = await db
      .select()
      .from(refreshTokens)
      .where(and(eq(refreshTokens.tokenHash, tokenHash), eq(refreshTokens.isRevoked, false)))
      .limit(1);
    return token || undefined;
  }

  async revokeRefreshToken(tokenHash: string): Promise<boolean> {
    const result = await db
      .update(refreshTokens)
      .set({ isRevoked: true })
      .where(eq(refreshTokens.tokenHash, tokenHash));
    return result.rowCount > 0;
  }

  async revokeUserRefreshTokens(userId: string): Promise<boolean> {
    const result = await db
      .update(refreshTokens)
      .set({ isRevoked: true })
      .where(eq(refreshTokens.userId, userId));
    return result.rowCount > 0;
  }

  async getActiveJwksKey(): Promise<JwksKey | undefined> {
    const [key] = await db
      .select()
      .from(jwksKeys)
      .where(eq(jwksKeys.isActive, true))
      .orderBy(desc(jwksKeys.createdAt))
      .limit(1);
    return key || undefined;
  }

  async getAllJwksKeys(): Promise<JwksKey[]> {
    return db.select().from(jwksKeys).orderBy(desc(jwksKeys.createdAt));
  }

  async createJwksKey(key: Omit<JwksKey, 'createdAt'>): Promise<JwksKey> {
    const [newKey] = await db.insert(jwksKeys).values(key).returning();
    return newKey;
  }

  async deactivateJwksKey(kid: string): Promise<boolean> {
    const result = await db
      .update(jwksKeys)
      .set({ isActive: false })
      .where(eq(jwksKeys.kid, kid));
    return result.rowCount > 0;
  }

  async createVerificationToken(token: Omit<VerificationToken, 'id' | 'createdAt'>): Promise<VerificationToken> {
    const [newToken] = await db.insert(verificationTokens).values(token).returning();
    return newToken;
  }

  async getVerificationToken(token: string): Promise<VerificationToken | undefined> {
    const [verificationToken] = await db
      .select()
      .from(verificationTokens)
      .where(and(eq(verificationTokens.token, token), eq(verificationTokens.isUsed, false)))
      .limit(1);
    return verificationToken || undefined;
  }

  async markTokenAsUsed(token: string): Promise<boolean> {
    const result = await db
      .update(verificationTokens)
      .set({ isUsed: true })
      .where(eq(verificationTokens.token, token));
    return result.rowCount > 0;
  }

  async createAuditLog(log: InsertAuditLog): Promise<AuditLog> {
    const [newLog] = await db.insert(auditLogs).values(log).returning();
    return newLog;
  }

  async getAuditLogs(limit = 50, offset = 0): Promise<AuditLog[]> {
    return db
      .select()
      .from(auditLogs)
      .orderBy(desc(auditLogs.createdAt))
      .limit(limit)
      .offset(offset);
  }

  async getAllRoles(): Promise<Role[]> {
    return db.select().from(roles).orderBy(roles.name);
  }

  async getRoleWithPermissions(roleId: string): Promise<Role & { permissions: Permission[] } | undefined> {
    const role = await db.select().from(roles).where(eq(roles.id, roleId)).limit(1);
    if (!role[0]) return undefined;

    const rolePerms = await db
      .select({ permission: permissions })
      .from(rolePermissions)
      .innerJoin(permissions, eq(rolePermissions.permissionId, permissions.id))
      .where(eq(rolePermissions.roleId, roleId));

    return {
      ...role[0],
      permissions: rolePerms.map(rp => rp.permission)
    };
  }

  async getAllPermissions(): Promise<Permission[]> {
    return db.select().from(permissions).orderBy(permissions.resource, permissions.action);
  }

  async getSystemMetrics() {
    const totalUsersResult = await db.select({ count: sql<number>`count(*)` }).from(users);
    const activeUsersResult = await db
      .select({ count: sql<number>`count(*)` })
      .from(users)
      .where(eq(users.status, 'active'));
    
    const totalClientsResult = await db.select({ count: sql<number>`count(*)` }).from(clients);
    
    const activeKeysResult = await db
      .select({ count: sql<number>`count(*)` })
      .from(jwksKeys)
      .where(eq(jwksKeys.isActive, true));
    
    const recentAuditLogs = await db
      .select()
      .from(auditLogs)
      .orderBy(desc(auditLogs.createdAt))
      .limit(10);

    return {
      totalUsers: totalUsersResult[0].count,
      activeUsers: activeUsersResult[0].count,
      totalClients: totalClientsResult[0].count,
      activeKeys: activeKeysResult[0].count,
      recentAuditLogs,
    };
  }
}

export const storage = new DatabaseStorage();
