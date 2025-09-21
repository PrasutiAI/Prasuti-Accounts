import bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';
import { storage } from '../storage';
import { jwtService } from './jwt.service';
import { auditService } from './audit.service';
import type { LoginRequest, RegisterRequest, User } from '@shared/schema';

export class AuthService {
  private readonly saltRounds = 12;
  private readonly refreshTokenTtl = 30 * 24 * 60 * 60 * 1000; // 30 days

  async register(userData: RegisterRequest): Promise<{ user: Omit<User, 'passwordHash'>, verificationToken: string }> {
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
      status: 'pending',
    });

    // Generate verification token
    const verificationToken = randomBytes(32).toString('hex');
    await storage.createVerificationToken({
      userId: user.id,
      token: verificationToken,
      type: 'email_verification',
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
    });

    // Log audit event
    await auditService.log({
      actorId: user.id,
      action: 'register',
      resource: 'user',
      resourceId: user.id,
      success: true,
    });

    const { passwordHash: _, ...userWithoutPassword } = user;
    return { user: userWithoutPassword, verificationToken };
  }

  async login(credentials: LoginRequest, ipAddress?: string, userAgent?: string): Promise<{
    user: Omit<User, 'passwordHash'>;
    accessToken: string;
    refreshToken: string;
  }> {
    // Get user
    const user = await storage.getUserByEmail(credentials.email);
    if (!user) {
      await auditService.log({
        action: 'login',
        resource: 'user',
        metadata: { email: credentials.email },
        ipAddress,
        userAgent,
        success: false,
      });
      throw new Error('Invalid credentials');
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(credentials.password, user.passwordHash);
    if (!isValidPassword) {
      await auditService.log({
        actorId: user.id,
        action: 'login',
        resource: 'user',
        resourceId: user.id,
        metadata: { reason: 'invalid_password' },
        ipAddress,
        userAgent,
        success: false,
      });
      throw new Error('Invalid credentials');
    }

    // Check if user is verified
    if (!user.isVerified) {
      throw new Error('Email not verified');
    }

    // Check if user is active
    if (user.status !== 'active') {
      throw new Error('Account is not active');
    }

    // Check MFA if enabled
    if (user.mfaEnabled) {
      if (!credentials.mfaCode) {
        throw new Error('MFA code required');
      }
      
      const { mfaService } = await import('./mfa.service');
      const isMfaValid = await mfaService.verifyToken(user.id, credentials.mfaCode);
      if (!isMfaValid) {
        await auditService.log({
          actorId: user.id,
          action: 'login',
          resource: 'user',
          resourceId: user.id,
          metadata: { reason: 'invalid_mfa' },
          ipAddress,
          userAgent,
          success: false,
        });
        throw new Error('Invalid MFA code');
      }
    }

    // Generate tokens
    const accessToken = await jwtService.generateAccessToken(user);
    const refreshToken = await this.generateRefreshToken(user.id);

    // Update last login
    await storage.updateUser(user.id, { lastLogin: new Date() });

    // Log successful login
    await auditService.log({
      actorId: user.id,
      action: 'login',
      resource: 'user',
      resourceId: user.id,
      ipAddress,
      userAgent,
      success: true,
    });

    const { passwordHash: _, ...userWithoutPassword } = user;
    return { user: userWithoutPassword, accessToken, refreshToken };
  }

  async logout(refreshToken: string, userId?: string): Promise<void> {
    // Revoke refresh token
    await this.revokeRefreshToken(refreshToken);

    // Log logout
    if (userId) {
      await auditService.log({
        actorId: userId,
        action: 'logout',
        resource: 'user',
        resourceId: userId,
        success: true,
      });
    }
  }

  async refreshAccessToken(refreshToken: string): Promise<{ accessToken: string; refreshToken: string }> {
    // Verify refresh token
    const hashedToken = await bcrypt.hash(refreshToken, 1);
    const storedToken = await storage.getRefreshToken(hashedToken);
    
    if (!storedToken || storedToken.expiresAt < new Date()) {
      throw new Error('Invalid or expired refresh token');
    }

    // Get user
    const user = await storage.getUser(storedToken.userId);
    if (!user) {
      throw new Error('User not found');
    }

    // Generate new tokens
    const newAccessToken = await jwtService.generateAccessToken(user);
    const newRefreshToken = await this.generateRefreshToken(user.id);

    // Revoke old refresh token
    await storage.revokeRefreshToken(storedToken.tokenHash);

    return { accessToken: newAccessToken, refreshToken: newRefreshToken };
  }

  async verifyEmail(token: string): Promise<void> {
    const verificationToken = await storage.getVerificationToken(token);
    if (!verificationToken || verificationToken.expiresAt < new Date()) {
      throw new Error('Invalid or expired verification token');
    }

    if (verificationToken.type !== 'email_verification') {
      throw new Error('Invalid token type');
    }

    // Verify user
    await storage.updateUser(verificationToken.userId, {
      isVerified: true,
      status: 'active',
    });

    // Mark token as used
    await storage.markTokenAsUsed(token);

    // Log audit event
    await auditService.log({
      actorId: verificationToken.userId,
      action: 'register',
      resource: 'user',
      resourceId: verificationToken.userId,
      metadata: { email_verified: true },
      success: true,
    });
  }

  async requestPasswordReset(email: string): Promise<string> {
    const user = await storage.getUserByEmail(email);
    if (!user) {
      // Still return success to avoid email enumeration
      return 'reset_email_sent';
    }

    // Generate reset token
    const resetToken = randomBytes(32).toString('hex');
    await storage.createVerificationToken({
      userId: user.id,
      token: resetToken,
      type: 'password_reset',
      expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
    });

    return resetToken;
  }

  async resetPassword(token: string, newPassword: string): Promise<void> {
    const verificationToken = await storage.getVerificationToken(token);
    if (!verificationToken || verificationToken.expiresAt < new Date()) {
      throw new Error('Invalid or expired reset token');
    }

    if (verificationToken.type !== 'password_reset') {
      throw new Error('Invalid token type');
    }

    // Hash new password
    const passwordHash = await bcrypt.hash(newPassword, this.saltRounds);

    // Update password
    await storage.updateUser(verificationToken.userId, { passwordHash });

    // Mark token as used
    await storage.markTokenAsUsed(token);

    // Revoke all refresh tokens for this user
    await storage.revokeUserRefreshTokens(verificationToken.userId);

    // Log audit event
    await auditService.log({
      actorId: verificationToken.userId,
      action: 'password_change',
      resource: 'user',
      resourceId: verificationToken.userId,
      success: true,
    });
  }

  private async generateRefreshToken(userId: string): Promise<string> {
    const token = randomBytes(32).toString('hex');
    const tokenHash = await bcrypt.hash(token, this.saltRounds);

    await storage.createRefreshToken({
      userId,
      tokenHash,
      expiresAt: new Date(Date.now() + this.refreshTokenTtl),
    });

    return token;
  }

  private async revokeRefreshToken(token: string): Promise<void> {
    const tokenHash = await bcrypt.hash(token, 1);
    await storage.revokeRefreshToken(tokenHash);
  }
}

export const authService = new AuthService();
