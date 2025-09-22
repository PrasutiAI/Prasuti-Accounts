import { 
  users, 
  roles, 
  userSessions, 
  emailVerificationTokens, 
  passwordResetTokens, 
  userAuditLog, 
  clients, 
  jwksKeys 
} from "@shared/schema";
import { db } from "./db";
import { eq, and, desc, sql, gte, lt } from "drizzle-orm";
import { cryptoUtils } from "./utils/crypto";
import bcrypt from 'bcrypt';
import type { 
  User, 
  InsertUser, 
  SelectUser, 
  Role,
  InsertRole,
  SelectRole,
  UserSession,
  InsertUserSession,
  SelectUserSession,
  EmailVerificationToken,
  InsertEmailVerificationToken,
  PasswordResetToken,
  InsertPasswordResetToken,
  UserAuditLog,
  InsertUserAuditLog,
  Client, 
  InsertClient,
  SelectClient,
  JwksKey
} from "@shared/schema";

export interface IStorage {
  // User operations
  getUser(id: string): Promise<User | undefined>;
  getUserByEmail(email: string): Promise<User | undefined>;
  getUserByPhoneNumber(phoneNumber: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  updateUser(id: string, updates: Partial<User>): Promise<User | undefined>;
  deleteUser(id: string): Promise<boolean>;
  getAllUsers(limit?: number, offset?: number): Promise<SelectUser[]>;
  getUsersCount(): Promise<number>;
  getActiveUsers(): Promise<number>;
  
  // Role operations
  getRole(id: string): Promise<Role | undefined>;
  getRoleByName(name: string): Promise<Role | undefined>;
  createRole(role: InsertRole): Promise<Role>;
  updateRole(id: string, updates: Partial<Role>): Promise<Role | undefined>;
  deleteRole(id: string): Promise<boolean>;
  getAllRoles(): Promise<Role[]>;
  getActiveRoles(): Promise<Role[]>;
  
  // UserSession operations - Updated for token security
  getUserSession(id: string): Promise<UserSession | undefined>;
  getUserSessionByRefreshToken(refreshToken: string): Promise<UserSession | undefined>; // Now uses hashed token lookup
  createUserSession(session: InsertUserSession): Promise<UserSession>; // Now expects plaintext token, will hash internally
  updateUserSession(id: string, updates: Partial<UserSession>): Promise<UserSession | undefined>;
  revokeUserSession(id: string): Promise<boolean>;
  revokeUserSessions(userId: string): Promise<boolean>;
  getUserSessions(userId: string, limit?: number): Promise<UserSession[]>;
  cleanupExpiredSessions(): Promise<number>;
  
  // EmailVerificationToken operations - Updated for token hashing
  getEmailVerificationToken(token: string): Promise<EmailVerificationToken | undefined>; // Now uses hashed token lookup
  createEmailVerificationToken(token: InsertEmailVerificationToken): Promise<EmailVerificationToken>; // Now expects plaintext token, will hash internally
  markEmailTokenAsUsed(token: string): Promise<boolean>; // Now uses hashed token lookup
  deleteEmailVerificationToken(token: string): Promise<boolean>; // Now uses hashed token lookup
  getUserEmailTokens(userId: string): Promise<EmailVerificationToken[]>;
  cleanupExpiredEmailTokens(): Promise<number>;
  
  // PasswordResetToken operations - Updated for token hashing
  getPasswordResetToken(token: string): Promise<PasswordResetToken | undefined>; // Now uses hashed token lookup
  createPasswordResetToken(token: InsertPasswordResetToken): Promise<PasswordResetToken>; // Now expects plaintext token, will hash internally
  markPasswordTokenAsUsed(token: string): Promise<boolean>; // Now uses hashed token lookup
  deletePasswordResetToken(token: string): Promise<boolean>; // Now uses hashed token lookup
  getUserPasswordTokens(userId: string): Promise<PasswordResetToken[]>;
  cleanupExpiredPasswordTokens(): Promise<number>;
  
  // UserAuditLog operations - Updated for enum consistency
  createUserAuditLog(log: InsertUserAuditLog): Promise<UserAuditLog>;
  getUserAuditLogs(userId: string, limit?: number, offset?: number): Promise<UserAuditLog[]>;
  getAllAuditLogs(limit?: number, offset?: number): Promise<UserAuditLog[]>;
  getAuditLogsByAction(action: 'login' | 'logout' | 'register' | 'password_change' | 'mfa_enable' | 'mfa_disable' | 'role_change' | 'user_create' | 'user_update' | 'user_delete' | 'key_rotation' | 'api_key_create' | 'api_key_revoke', limit?: number): Promise<UserAuditLog[]>;
  
  // Client operations (for backward compatibility)
  getClient(clientId: string): Promise<Client | undefined>;
  createClient(client: InsertClient): Promise<Client>;
  updateClient(id: string, updates: Partial<Client>): Promise<Client | undefined>;
  deleteClient(id: string): Promise<boolean>;
  getAllClients(): Promise<Client[]>;
  
  // JWT keys operations (for backward compatibility)
  getActiveJwksKey(): Promise<JwksKey | undefined>;
  getAllJwksKeys(): Promise<JwksKey[]>;
  createJwksKey(key: Omit<JwksKey, 'createdAt'>): Promise<JwksKey>;
  deactivateJwksKey(kid: string): Promise<boolean>;
  
  // System metrics
  getSystemMetrics(): Promise<{
    totalUsers: number;
    activeUsers: number;
    verifiedUsers: number;
    totalSessions: number;
    activeSessions: number;
    totalRoles: number;
    activeRoles: number;
    totalClients: number;
    activeKeys: number;
    recentAuditLogs: UserAuditLog[];
  }>;
  
  // Cleanup operations
  cleanupExpiredData(): Promise<{
    expiredSessions: number;
    expiredEmailTokens: number;
    expiredPasswordTokens: number;
  }>;
}

export class DatabaseStorage implements IStorage {
  private readonly saltRounds = 12; // Match AuthService salt rounds
  
  // User operations
  async getUser(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id)).limit(1);
    return user || undefined;
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.email, email)).limit(1);
    return user || undefined;
  }

  async getUserByPhoneNumber(phoneNumber: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.phoneNumber, phoneNumber)).limit(1);
    return user || undefined;
  }

  async createUser(user: InsertUser): Promise<User> {
    // Handle password hashing and MFA secret encryption
    const userData: any = { ...user };
    
    // Encrypt MFA secret if provided
    if (userData.mfaSecret) {
      userData.mfaSecretEncrypted = await cryptoUtils.encrypt(userData.mfaSecret);
      delete userData.mfaSecret;
    }
    
    // Hash password with bcrypt before storing
    if (userData.password) {
      userData.passwordHash = await bcrypt.hash(userData.password, this.saltRounds);
      delete userData.password;
    }

    const [newUser] = await db.insert(users).values(userData).returning();
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
    return (result.rowCount ?? 0) > 0;
  }

  async getAllUsers(limit = 50, offset = 0): Promise<SelectUser[]> {
    return db
      .select({
        id: users.id,
        email: users.email,
        name: users.name,
        roleId: users.roleId,
        isEmailVerified: users.isEmailVerified,
        isActive: users.isActive,
        lastLogin: users.lastLogin,
        createdAt: users.createdAt,
        updatedAt: users.updatedAt,
      })
      .from(users)
      .limit(limit)
      .offset(offset)
      .orderBy(desc(users.createdAt));
  }

  async getUsersCount(): Promise<number> {
    const [result] = await db.select({ count: sql<number>`count(*)` }).from(users);
    return result.count;
  }

  async getActiveUsers(): Promise<number> {
    const [result] = await db
      .select({ count: sql<number>`count(*)` })
      .from(users)
      .where(eq(users.isActive, true));
    return result.count;
  }

  // Role operations
  async getRole(id: string): Promise<Role | undefined> {
    const [role] = await db.select().from(roles).where(eq(roles.id, id)).limit(1);
    return role || undefined;
  }

  async getRoleByName(name: string): Promise<Role | undefined> {
    const [role] = await db.select().from(roles).where(eq(roles.name, name)).limit(1);
    return role || undefined;
  }

  async createRole(role: InsertRole): Promise<Role> {
    const [newRole] = await db.insert(roles).values(role).returning();
    return newRole;
  }

  async updateRole(id: string, updates: Partial<Role>): Promise<Role | undefined> {
    const [updatedRole] = await db
      .update(roles)
      .set(updates)
      .where(eq(roles.id, id))
      .returning();
    return updatedRole || undefined;
  }

  async deleteRole(id: string): Promise<boolean> {
    const result = await db.delete(roles).where(eq(roles.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async getAllRoles(): Promise<Role[]> {
    return db.select().from(roles).orderBy(roles.name);
  }

  async getActiveRoles(): Promise<Role[]> {
    return db.select().from(roles).where(eq(roles.isActive, true)).orderBy(roles.name);
  }

  // UserSession operations
  async getUserSession(id: string): Promise<UserSession | undefined> {
    const [session] = await db.select().from(userSessions).where(eq(userSessions.id, id)).limit(1);
    return session || undefined;
  }

  // Removed getUserSessionByAccessToken as access tokens are no longer stored

  async getUserSessionByRefreshToken(refreshToken: string): Promise<UserSession | undefined> {
    // Hash the token to compare with stored hash
    const refreshTokenHash = cryptoUtils.hashToken(refreshToken);
    const [session] = await db
      .select()
      .from(userSessions)
      .where(
        and(
          eq(userSessions.refreshTokenHash, refreshTokenHash),
          eq(userSessions.isRevoked, false)
        )
      )
      .limit(1);
    return session || undefined;
  }

  async createUserSession(session: InsertUserSession): Promise<UserSession> {
    // Hash the refresh token before storing
    const sessionData: any = { ...session };
    if (sessionData.refreshToken) {
      sessionData.refreshTokenHash = cryptoUtils.hashToken(sessionData.refreshToken);
      delete sessionData.refreshToken;
    }
    
    const [newSession] = await db.insert(userSessions).values(sessionData).returning();
    return newSession;
  }

  async updateUserSession(id: string, updates: Partial<UserSession>): Promise<UserSession | undefined> {
    const [updatedSession] = await db
      .update(userSessions)
      .set(updates)
      .where(eq(userSessions.id, id))
      .returning();
    return updatedSession || undefined;
  }

  async revokeUserSession(id: string): Promise<boolean> {
    const result = await db
      .update(userSessions)
      .set({ isRevoked: true })
      .where(eq(userSessions.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async revokeUserSessions(userId: string): Promise<boolean> {
    const result = await db
      .update(userSessions)
      .set({ isRevoked: true })
      .where(eq(userSessions.userId, userId));
    return (result.rowCount ?? 0) > 0;
  }

  async getUserSessions(userId: string, limit = 10): Promise<UserSession[]> {
    return db
      .select()
      .from(userSessions)
      .where(eq(userSessions.userId, userId))
      .orderBy(desc(userSessions.createdAt))
      .limit(limit);
  }

  async cleanupExpiredSessions(): Promise<number> {
    const result = await db
      .delete(userSessions)
      .where(and(lt(userSessions.expiresAt, new Date()), eq(userSessions.isRevoked, false)));
    return result.rowCount || 0;
  }

  // EmailVerificationToken operations - Updated with token hashing
  async getEmailVerificationToken(token: string): Promise<EmailVerificationToken | undefined> {
    // Hash the token to compare with stored hash
    const tokenHash = cryptoUtils.hashToken(token);
    const [verificationToken] = await db
      .select()
      .from(emailVerificationTokens)
      .where(
        and(
          eq(emailVerificationTokens.tokenHash, tokenHash),
          eq(emailVerificationTokens.isUsed, false),
          gte(emailVerificationTokens.expiresAt, new Date())
        )
      )
      .limit(1);
    return verificationToken || undefined;
  }

  async createEmailVerificationToken(token: InsertEmailVerificationToken): Promise<EmailVerificationToken> {
    // Hash the token before storing
    const tokenData: any = { ...token };
    if (tokenData.token) {
      tokenData.tokenHash = cryptoUtils.hashToken(tokenData.token);
      delete tokenData.token;
    }
    
    const [newToken] = await db.insert(emailVerificationTokens).values(tokenData).returning();
    return newToken;
  }

  async markEmailTokenAsUsed(token: string): Promise<boolean> {
    // Hash the token to find the correct record
    const tokenHash = cryptoUtils.hashToken(token);
    const result = await db
      .update(emailVerificationTokens)
      .set({ isUsed: true })
      .where(eq(emailVerificationTokens.tokenHash, tokenHash));
    return (result.rowCount ?? 0) > 0;
  }

  async deleteEmailVerificationToken(token: string): Promise<boolean> {
    // Hash the token to find the correct record
    const tokenHash = cryptoUtils.hashToken(token);
    const result = await db.delete(emailVerificationTokens).where(eq(emailVerificationTokens.tokenHash, tokenHash));
    return (result.rowCount ?? 0) > 0;
  }

  async getUserEmailTokens(userId: string): Promise<EmailVerificationToken[]> {
    return db
      .select()
      .from(emailVerificationTokens)
      .where(eq(emailVerificationTokens.userId, userId))
      .orderBy(desc(emailVerificationTokens.createdAt));
  }

  async cleanupExpiredEmailTokens(): Promise<number> {
    const result = await db
      .delete(emailVerificationTokens)
      .where(lt(emailVerificationTokens.expiresAt, new Date()));
    return result.rowCount || 0;
  }

  // PasswordResetToken operations - Updated with token hashing
  async getPasswordResetToken(token: string): Promise<PasswordResetToken | undefined> {
    // Hash the token to compare with stored hash
    const tokenHash = cryptoUtils.hashToken(token);
    const [resetToken] = await db
      .select()
      .from(passwordResetTokens)
      .where(
        and(
          eq(passwordResetTokens.tokenHash, tokenHash),
          eq(passwordResetTokens.isUsed, false),
          gte(passwordResetTokens.expiresAt, new Date())
        )
      )
      .limit(1);
    return resetToken || undefined;
  }

  async createPasswordResetToken(token: InsertPasswordResetToken): Promise<PasswordResetToken> {
    // Hash the token before storing
    const tokenData: any = { ...token };
    if (tokenData.token) {
      tokenData.tokenHash = cryptoUtils.hashToken(tokenData.token);
      delete tokenData.token;
    }
    
    const [newToken] = await db.insert(passwordResetTokens).values(tokenData).returning();
    return newToken;
  }

  async markPasswordTokenAsUsed(token: string): Promise<boolean> {
    // Hash the token to find the correct record
    const tokenHash = cryptoUtils.hashToken(token);
    const result = await db
      .update(passwordResetTokens)
      .set({ isUsed: true })
      .where(eq(passwordResetTokens.tokenHash, tokenHash));
    return (result.rowCount ?? 0) > 0;
  }

  async deletePasswordResetToken(token: string): Promise<boolean> {
    // Hash the token to find the correct record
    const tokenHash = cryptoUtils.hashToken(token);
    const result = await db.delete(passwordResetTokens).where(eq(passwordResetTokens.tokenHash, tokenHash));
    return (result.rowCount ?? 0) > 0;
  }

  async getUserPasswordTokens(userId: string): Promise<PasswordResetToken[]> {
    return db
      .select()
      .from(passwordResetTokens)
      .where(eq(passwordResetTokens.userId, userId))
      .orderBy(desc(passwordResetTokens.createdAt));
  }

  async cleanupExpiredPasswordTokens(): Promise<number> {
    const result = await db
      .delete(passwordResetTokens)
      .where(lt(passwordResetTokens.expiresAt, new Date()));
    return result.rowCount || 0;
  }

  // UserAuditLog operations
  async createUserAuditLog(log: InsertUserAuditLog): Promise<UserAuditLog> {
    const [newLog] = await db.insert(userAuditLog).values(log).returning();
    return newLog;
  }

  async getUserAuditLogs(userId: string, limit = 50, offset = 0): Promise<UserAuditLog[]> {
    return db
      .select()
      .from(userAuditLog)
      .where(eq(userAuditLog.userId, userId))
      .orderBy(desc(userAuditLog.createdAt))
      .limit(limit)
      .offset(offset);
  }

  async getAllAuditLogs(limit = 50, offset = 0): Promise<UserAuditLog[]> {
    return db
      .select()
      .from(userAuditLog)
      .orderBy(desc(userAuditLog.createdAt))
      .limit(limit)
      .offset(offset);
  }

  async getAuditLogsByAction(action: 'login' | 'logout' | 'register' | 'password_change' | 'mfa_enable' | 'mfa_disable' | 'role_change' | 'user_create' | 'user_update' | 'user_delete' | 'key_rotation' | 'api_key_create' | 'api_key_revoke', limit = 50): Promise<UserAuditLog[]> {
    return db
      .select()
      .from(userAuditLog)
      .where(eq(userAuditLog.action, action))
      .orderBy(desc(userAuditLog.createdAt))
      .limit(limit);
  }

  // Client operations (for backward compatibility)
  async getClient(clientId: string): Promise<Client | undefined> {
    const [client] = await db.select().from(clients).where(eq(clients.clientId, clientId)).limit(1);
    return client || undefined;
  }

  async createClient(client: InsertClient): Promise<Client> {
    const { clientSecret, ...clientData } = client;
    const clientSecretHash = cryptoUtils.hashApiKey(clientSecret);
    
    const [newClient] = await db.insert(clients).values({
      ...clientData,
      clientSecretHash,
    }).returning();
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
    return (result.rowCount ?? 0) > 0;
  }

  async getAllClients(): Promise<Client[]> {
    return db.select().from(clients).orderBy(desc(clients.createdAt));
  }

  // JWT keys operations (for backward compatibility)
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
    return (result.rowCount ?? 0) > 0;
  }

  // System metrics
  async getSystemMetrics() {
    const [totalUsersResult] = await db.select({ count: sql<number>`count(*)` }).from(users);
    const [activeUsersResult] = await db
      .select({ count: sql<number>`count(*)` })
      .from(users)
      .where(eq(users.isActive, true));
    const [verifiedUsersResult] = await db
      .select({ count: sql<number>`count(*)` })
      .from(users)
      .where(and(eq(users.isActive, true), eq(users.isEmailVerified, true)));
    
    const [totalSessionsResult] = await db.select({ count: sql<number>`count(*)` }).from(userSessions);
    const [activeSessionsResult] = await db
      .select({ count: sql<number>`count(*)` })
      .from(userSessions)
      .where(and(eq(userSessions.isRevoked, false), gte(userSessions.expiresAt, new Date())));
    
    const [totalRolesResult] = await db.select({ count: sql<number>`count(*)` }).from(roles);
    const [activeRolesResult] = await db
      .select({ count: sql<number>`count(*)` })
      .from(roles)
      .where(eq(roles.isActive, true));
    
    const [totalClientsResult] = await db.select({ count: sql<number>`count(*)` }).from(clients);
    const [activeKeysResult] = await db
      .select({ count: sql<number>`count(*)` })
      .from(jwksKeys)
      .where(eq(jwksKeys.isActive, true));
    
    const recentAuditLogs = await db
      .select()
      .from(userAuditLog)
      .orderBy(desc(userAuditLog.createdAt))
      .limit(10);

    return {
      totalUsers: totalUsersResult.count,
      activeUsers: activeUsersResult.count,
      verifiedUsers: verifiedUsersResult.count,
      totalSessions: totalSessionsResult.count,
      activeSessions: activeSessionsResult.count,
      totalRoles: totalRolesResult.count,
      activeRoles: activeRolesResult.count,
      totalClients: totalClientsResult.count,
      activeKeys: activeKeysResult.count,
      recentAuditLogs,
    };
  }

  // Cleanup operations
  async cleanupExpiredData() {
    const expiredSessions = await this.cleanupExpiredSessions();
    const expiredEmailTokens = await this.cleanupExpiredEmailTokens();
    const expiredPasswordTokens = await this.cleanupExpiredPasswordTokens();

    return {
      expiredSessions,
      expiredEmailTokens,
      expiredPasswordTokens,
    };
  }
}

export const storage = new DatabaseStorage();