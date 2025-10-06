import { sql, relations } from "drizzle-orm";
import { pgTable, text, uuid, timestamp, boolean, jsonb, pgEnum, index } from "drizzle-orm/pg-core";
import { createInsertSchema, createSelectSchema } from "drizzle-zod";
import { z } from "zod";

// Enums
export const roleEnum = pgEnum('role', ['admin', 'developer', 'user', 'guest']);
export const auditActionEnum = pgEnum('audit_action', ['login', 'logout', 'register', 'password_change', 'mfa_enable', 'mfa_disable', 'role_change', 'user_create', 'user_update', 'user_delete', 'key_rotation', 'api_key_create', 'api_key_revoke']);

// Users table - Updated with security fixes and Google OAuth support
export const users = pgTable("users", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  email: text("email").notNull().unique(),
  phoneNumber: text("phone_number"), // Temporary: unique constraint removed to allow migration without prompts
  name: text("name").notNull(),
  passwordHash: text("password_hash"), // Made optional for OAuth users
  roleId: uuid("role_id").notNull().references(() => roles.id), // FK to roles table instead of enum
  isEmailVerified: boolean("is_email_verified").notNull().default(false),
  isActive: boolean("is_active").notNull().default(true),
  mfaSecretEncrypted: text("mfa_secret_encrypted"), // Encrypted at rest for security
  googleId: text("google_id"), // Google OAuth user ID
  linkedInId: text("linkedin_id"), // LinkedIn OAuth user ID
  profilePicture: text("profile_picture"), // Profile picture URL
  requirePasswordChange: boolean("require_password_change").notNull().default(false), // Force password change on first login
  lastLogin: timestamp("last_login"),
  createdAt: timestamp("created_at").notNull().default(sql`now()`),
  updatedAt: timestamp("updated_at").notNull().default(sql`now()`),
}, (table) => ({
  emailIdx: index("users_email_idx").on(table.email),
  phoneNumberIdx: index("users_phone_number_idx").on(table.phoneNumber),
  roleIdx: index("users_role_idx").on(table.roleId),
  activeIdx: index("users_active_idx").on(table.isActive),
  emailVerifiedIdx: index("users_email_verified_idx").on(table.isEmailVerified),
}));

// Roles table - Updated to match requirements
export const roles = pgTable("roles", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull().unique(),
  description: text("description"),
  permissions: text("permissions").array().notNull().default(sql`ARRAY[]::text[]`),
  isActive: boolean("is_active").notNull().default(true),
}, (table) => ({
  nameIdx: index("roles_name_idx").on(table.name),
  activeIdx: index("roles_active_idx").on(table.isActive),
}));

// UserSessions table - Updated with token security fixes
export const userSessions = pgTable("user_sessions", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: uuid("user_id").notNull().references(() => users.id, { onDelete: 'cascade' }),
  refreshTokenHash: text("refresh_token_hash").notNull(), // Store only hashed refresh token
  expiresAt: timestamp("expires_at").notNull(),
  isRevoked: boolean("is_revoked").notNull().default(false),
  deviceInfo: text("device_info"),
  ipAddress: text("ip_address"),
  createdAt: timestamp("created_at").notNull().default(sql`now()`),
}, (table) => ({
  userIdx: index("sessions_user_idx").on(table.userId),
  refreshTokenHashIdx: index("sessions_refresh_token_hash_idx").on(table.refreshTokenHash),
  expiresIdx: index("sessions_expires_idx").on(table.expiresAt),
  revokedIdx: index("sessions_revoked_idx").on(table.isRevoked),
}));

// EmailVerificationTokens table - Updated with token hashing and redirect support
export const emailVerificationTokens = pgTable("email_verification_tokens", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: uuid("user_id").notNull().references(() => users.id, { onDelete: 'cascade' }),
  tokenHash: text("token_hash").notNull().unique(), // Store only hashed token
  redirectUrl: text("redirect_url"), // Optional redirect URL after verification
  expiresAt: timestamp("expires_at").notNull(),
  isUsed: boolean("is_used").notNull().default(false),
  createdAt: timestamp("created_at").notNull().default(sql`now()`),
}, (table) => ({
  userIdx: index("email_verification_user_idx").on(table.userId),
  tokenHashIdx: index("email_verification_token_hash_idx").on(table.tokenHash),
  expiresIdx: index("email_verification_expires_idx").on(table.expiresAt),
  usedIdx: index("email_verification_used_idx").on(table.isUsed),
}));

// PasswordResetTokens table - Updated with token hashing
export const passwordResetTokens = pgTable("password_reset_tokens", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: uuid("user_id").notNull().references(() => users.id, { onDelete: 'cascade' }),
  tokenHash: text("token_hash").notNull().unique(), // Store only hashed token
  expiresAt: timestamp("expires_at").notNull(),
  isUsed: boolean("is_used").notNull().default(false),
  createdAt: timestamp("created_at").notNull().default(sql`now()`),
}, (table) => ({
  userIdx: index("password_reset_user_idx").on(table.userId),
  tokenHashIdx: index("password_reset_token_hash_idx").on(table.tokenHash),
  expiresIdx: index("password_reset_expires_idx").on(table.expiresAt),
  usedIdx: index("password_reset_used_idx").on(table.isUsed),
}));

// UserAuditLog table - Updated with enum for action consistency
export const userAuditLog = pgTable("user_audit_log", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: uuid("user_id").references(() => users.id, { onDelete: 'set null' }),
  action: auditActionEnum("action").notNull(), // Use enum for consistency
  ipAddress: text("ip_address"),
  deviceInfo: text("device_info"),
  details: jsonb("details"),
  createdAt: timestamp("created_at").notNull().default(sql`now()`),
}, (table) => ({
  userIdx: index("audit_user_idx").on(table.userId),
  actionIdx: index("audit_action_idx").on(table.action),
  createdIdx: index("audit_created_idx").on(table.createdAt),
}));

// Additional tables for backward compatibility and full functionality
// API clients for machine-to-machine authentication
export const clients = pgTable("clients", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  clientId: text("client_id").notNull().unique(),
  clientSecretHash: text("client_secret_hash").notNull(),
  name: text("name").notNull(),
  grantTypes: text("grant_types").array().notNull().default(sql`ARRAY['client_credentials']`),
  scopes: text("scopes").array().notNull().default(sql`ARRAY['read']`),
  isActive: boolean("is_active").notNull().default(true),
  createdAt: timestamp("created_at").notNull().default(sql`now()`),
  updatedAt: timestamp("updated_at").notNull().default(sql`now()`),
}, (table) => ({
  clientIdIdx: index("clients_client_id_idx").on(table.clientId),
  activeIdx: index("clients_active_idx").on(table.isActive),
}));

// JWT signing keys
export const jwksKeys = pgTable("jwks_keys", {
  kid: text("kid").primaryKey(),
  publicKey: text("public_key").notNull(),
  privateKeyEncrypted: text("private_key_encrypted").notNull(),
  algorithm: text("algorithm").notNull().default('RS256'),
  isActive: boolean("is_active").notNull().default(true),
  createdAt: timestamp("created_at").notNull().default(sql`now()`),
  expiresAt: timestamp("expires_at").notNull(),
}, (table) => ({
  activeIdx: index("jwks_keys_active_idx").on(table.isActive),
  expiresIdx: index("jwks_keys_expires_idx").on(table.expiresAt),
}));

// Allowed domains table - for redirect URL validation
export const allowedDomains = pgTable("allowed_domains", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  domain: text("domain").notNull().unique(),
  description: text("description"),
  isActive: boolean("is_active").notNull().default(true),
  createdAt: timestamp("created_at").notNull().default(sql`now()`),
  updatedAt: timestamp("updated_at").notNull().default(sql`now()`),
}, (table) => ({
  domainIdx: index("allowed_domains_domain_idx").on(table.domain),
  activeIdx: index("allowed_domains_active_idx").on(table.isActive),
}));

// Relations
export const usersRelations = relations(users, ({ one, many }) => ({
  role: one(roles, { fields: [users.roleId], references: [roles.id] }),
  userSessions: many(userSessions),
  emailVerificationTokens: many(emailVerificationTokens),
  passwordResetTokens: many(passwordResetTokens),
  userAuditLog: many(userAuditLog),
}));

export const rolesRelations = relations(roles, ({ many }) => ({
  users: many(users),
}));

export const userSessionsRelations = relations(userSessions, ({ one }) => ({
  user: one(users, { fields: [userSessions.userId], references: [users.id] }),
}));

export const emailVerificationTokensRelations = relations(emailVerificationTokens, ({ one }) => ({
  user: one(users, { fields: [emailVerificationTokens.userId], references: [users.id] }),
}));

export const passwordResetTokensRelations = relations(passwordResetTokens, ({ one }) => ({
  user: one(users, { fields: [passwordResetTokens.userId], references: [users.id] }),
}));

export const userAuditLogRelations = relations(userAuditLog, ({ one }) => ({
  user: one(users, { fields: [userAuditLog.userId], references: [users.id] }),
}));

export const clientsRelations = relations(clients, ({ many }) => ({
  // clients don't have direct relations to other tables in this schema
}));

// Zod schemas for the new tables
export const insertUserSchema = createInsertSchema(users).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  lastLogin: true,
  passwordHash: true, // Handle password separately for hashing
  mfaSecretEncrypted: true, // Handle MFA secret separately for encryption
}).extend({
  password: z.string().min(8).describe("Password must be at least 8 characters long"),
  mfaSecret: z.string().optional().describe("MFA secret (will be encrypted before storage)"),
  phoneNumber: z.string()
    .regex(/^\+?[1-9]\d{1,14}$/, "Please enter a valid international phone number (e.g., +1234567890)")
    .optional()
    .describe("International phone number in E.164 format"),
});

export const selectUserSchema = createSelectSchema(users).omit({
  passwordHash: true, // Never include password hash in select schema
  mfaSecretEncrypted: true, // Never include encrypted MFA secret in select schema
});

export const updateUserSchema = insertUserSchema.partial().omit({
  password: true, // Handle password updates separately
  mfaSecret: true, // Handle MFA secret updates separately
});

export const insertRoleSchema = createInsertSchema(roles).omit({
  id: true,
}).extend({
  permissions: z.array(z.string()).default([]),
});

export const selectRoleSchema = createSelectSchema(roles);

export const insertUserSessionSchema = createInsertSchema(userSessions).omit({
  id: true,
  createdAt: true,
  refreshTokenHash: true, // Handle token hashing separately
}).extend({
  refreshToken: z.string().describe("Refresh token (will be hashed before storage)"),
});

export const selectUserSessionSchema = createSelectSchema(userSessions).omit({
  refreshTokenHash: true, // For security, don't expose token hash in select
});

export const insertEmailVerificationTokenSchema = createInsertSchema(emailVerificationTokens).omit({
  id: true,
  createdAt: true,
  tokenHash: true, // Handle token hashing separately
}).extend({
  token: z.string().describe("Verification token (will be hashed before storage)"),
  redirectUrl: z.string().url().optional().describe("Optional redirect URL after successful verification"),
});

export const selectEmailVerificationTokenSchema = createSelectSchema(emailVerificationTokens).omit({
  tokenHash: true, // For security, don't expose token hash in select
});

export const insertPasswordResetTokenSchema = createInsertSchema(passwordResetTokens).omit({
  id: true,
  createdAt: true,
  tokenHash: true, // Handle token hashing separately
}).extend({
  token: z.string().describe("Reset token (will be hashed before storage)"),
});

export const selectPasswordResetTokenSchema = createSelectSchema(passwordResetTokens).omit({
  tokenHash: true, // For security, don't expose token hash in select
});

export const insertUserAuditLogSchema = createInsertSchema(userAuditLog).omit({
  id: true,
  createdAt: true,
});

export const selectUserAuditLogSchema = createSelectSchema(userAuditLog);

export const insertClientSchema = createInsertSchema(clients).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  clientSecretHash: true,
}).extend({
  clientSecret: z.string().min(32),
});

export const selectClientSchema = createSelectSchema(clients).omit({
  clientSecretHash: true,
});

export const insertAllowedDomainSchema = createInsertSchema(allowedDomains).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const selectAllowedDomainSchema = createSelectSchema(allowedDomains);

export const updateAllowedDomainSchema = insertAllowedDomainSchema.partial();

// Types
export type User = typeof users.$inferSelect;
export type InsertUser = z.infer<typeof insertUserSchema>;
export type SelectUser = z.infer<typeof selectUserSchema>;
export type UpdateUser = z.infer<typeof updateUserSchema>;

export type Role = typeof roles.$inferSelect;
export type InsertRole = z.infer<typeof insertRoleSchema>;
export type SelectRole = z.infer<typeof selectRoleSchema>;

export type UserSession = typeof userSessions.$inferSelect;
export type InsertUserSession = z.infer<typeof insertUserSessionSchema>;
export type SelectUserSession = z.infer<typeof selectUserSessionSchema>;

export type EmailVerificationToken = typeof emailVerificationTokens.$inferSelect;
export type InsertEmailVerificationToken = z.infer<typeof insertEmailVerificationTokenSchema>;
export type SelectEmailVerificationToken = z.infer<typeof selectEmailVerificationTokenSchema>;

export type PasswordResetToken = typeof passwordResetTokens.$inferSelect;
export type InsertPasswordResetToken = z.infer<typeof insertPasswordResetTokenSchema>;
export type SelectPasswordResetToken = z.infer<typeof selectPasswordResetTokenSchema>;

export type UserAuditLog = typeof userAuditLog.$inferSelect;
export type InsertUserAuditLog = z.infer<typeof insertUserAuditLogSchema>;
export type SelectUserAuditLog = z.infer<typeof selectUserAuditLogSchema>;

export type Client = typeof clients.$inferSelect;
export type InsertClient = z.infer<typeof insertClientSchema>;
export type SelectClient = z.infer<typeof selectClientSchema>;

export type JwksKey = typeof jwksKeys.$inferSelect;

export type AllowedDomain = typeof allowedDomains.$inferSelect;
export type InsertAllowedDomain = z.infer<typeof insertAllowedDomainSchema>;
export type SelectAllowedDomain = z.infer<typeof selectAllowedDomainSchema>;
export type UpdateAllowedDomain = z.infer<typeof updateAllowedDomainSchema>;

// Authentication-related schemas
export const loginSchema = z.object({
  identifier: z.string()
    .min(1, "Email or phone number is required")
    .refine((value) => {
      // Check if it's a valid email
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      // Check if it's a valid international phone number
      const phoneRegex = /^\+?[1-9]\d{1,14}$/;
      return emailRegex.test(value) || phoneRegex.test(value);
    }, "Please enter a valid email address or phone number"),
  password: z.string().min(1, "Password is required"),
  mfaCode: z.string().optional(),
  redirectUrl: z.string().url().optional(),
});

// Registration schema excludes roleId since it's assigned automatically by AuthService
export const registerSchema = insertUserSchema.omit({
  roleId: true, // Role is assigned automatically during registration
}).extend({
  redirectUrl: z.string().url().optional().describe("Optional redirect URL after successful registration and verification"),
});

export const refreshTokenSchema = z.object({
  refreshToken: z.string(),
});

export const verifyEmailSchema = z.object({
  token: z.string(),
});

export const verifyTokenSchema = z.object({
  token: z.string(),
});

export const resetPasswordSchema = z.object({
  token: z.string(),
  password: z.string().min(8, "Password must be at least 8 characters long"),
});

export const changePasswordSchema = z.object({
  currentPassword: z.string(),
  newPassword: z.string().min(8, "Password must be at least 8 characters long"),
});

export const enableMfaSchema = z.object({
  mfaCode: z.string().length(6, "MFA code must be 6 digits"),
});

export const forgotPasswordSchema = z.object({
  email: z.string().email("Please enter a valid email address"),
});

// Auth request/response types
export type LoginRequest = z.infer<typeof loginSchema>;
export type RegisterRequest = z.infer<typeof registerSchema>;
export type RefreshTokenRequest = z.infer<typeof refreshTokenSchema>;
export type VerifyEmailRequest = z.infer<typeof verifyEmailSchema>;
export type ResetPasswordRequest = z.infer<typeof resetPasswordSchema>;
export type ChangePasswordRequest = z.infer<typeof changePasswordSchema>;
export type EnableMfaRequest = z.infer<typeof enableMfaSchema>;
export type ForgotPasswordRequest = z.infer<typeof forgotPasswordSchema>;