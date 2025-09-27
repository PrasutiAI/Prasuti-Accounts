import bcrypt from 'bcrypt';
import { storage } from '../storage';
import { jwtService } from './jwt.service';
import { auditService } from './audit.service';
import { cryptoUtils } from '../utils/crypto';
import { emailService } from './email.service';
import type { LoginRequest, RegisterRequest, User } from '@shared/schema';
import { appendTokensToUrl } from '../utils/token-url';
import { validateRedirectUrl } from '../utils/domain-validation';

export class AuthService {
  private readonly saltRounds = 12;
  private readonly refreshTokenTtl = 30 * 24 * 60 * 60 * 1000; // 30 days

  async register(userData: RegisterRequest & { redirectUrl?: string }): Promise<{ user: Omit<User, 'passwordHash'>, message: string }> {
    // Check if user already exists
    const existingUser = await storage.getUserByEmail(userData.email);
    if (existingUser) {
      throw new Error('User already exists with this email');
    }

    // Get default user role
    const defaultRole = await storage.getRoleByName('user');
    if (!defaultRole) {
      throw new Error('Default user role not found');
    }

    // Create user with new secure schema
    const user = await storage.createUser({
      email: userData.email,
      name: userData.name,
      password: userData.password, // Will be hashed in storage layer with bcrypt
      phoneNumber: userData.phoneNumber, // Include phone number from registration data
      roleId: defaultRole.id,
      mfaSecret: userData.mfaSecret, // Will be encrypted in storage layer
    });

    // Generate verification token
    const verificationToken = cryptoUtils.generateEmailVerificationToken();
    await storage.createEmailVerificationToken({
      userId: user.id,
      token: verificationToken, // Will be hashed in storage layer
      redirectUrl: userData.redirectUrl, // Include redirectUrl if provided
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
    });

    // Send verification email
    const baseUrl = process.env.APP_URL || process.env.VITE_APP_URL || 'http://localhost:5000';
    let verificationUrl = `${baseUrl}/verify-email?token=${verificationToken}`;
    
    // Add redirectUrl to verification link if provided
    if (userData.redirectUrl) {
      verificationUrl += `&redirectUrl=${encodeURIComponent(userData.redirectUrl)}`;
    }
    const emailSent = await emailService.sendVerificationEmail({
      to: user.email,
      name: user.name,
      verificationUrl
    });

    // Log audit event
    await storage.createUserAuditLog({
      userId: user.id,
      action: 'register',
      details: { 
        email: user.email,
        verificationEmailSent: emailSent 
      },
    });

    const { passwordHash: _, mfaSecretEncrypted: __, ...userWithoutSensitiveData } = user;
    return { 
      user: userWithoutSensitiveData as any, 
      message: emailSent 
        ? 'Registration successful. Please check your email for verification instructions.'
        : 'Registration successful. Email verification could not be sent - please contact support.'
    };
  }

  async login(credentials: LoginRequest, ipAddress?: string, userAgent?: string): Promise<{
    user: Omit<User, 'passwordHash'>;
    accessToken: string;
    refreshToken: string;
  }> {
    // Determine if identifier is email or phone number
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const isEmail = emailRegex.test(credentials.identifier);
    
    // Get user by email or phone number
    const user = isEmail 
      ? await storage.getUserByEmail(credentials.identifier)
      : await storage.getUserByPhoneNumber(credentials.identifier);
      
    if (!user) {
      await storage.createUserAuditLog({
        userId: null,
        action: 'login',
        ipAddress,
        deviceInfo: userAgent,
        details: { 
          [isEmail ? 'email' : 'phoneNumber']: credentials.identifier, 
          success: false, 
          reason: 'user_not_found' 
        },
      });
      throw new Error('Invalid credentials');
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(credentials.password, user.passwordHash);
    if (!isValidPassword) {
      await storage.createUserAuditLog({
        userId: user.id,
        action: 'login',
        ipAddress,
        deviceInfo: userAgent,
        details: { success: false, reason: 'invalid_password' },
      });
      throw new Error('Invalid credentials');
    }

    // Check if user is verified (relaxed in development)
    if (!user.isEmailVerified && process.env.NODE_ENV === 'production') {
      throw new Error('Email not verified');
    }

    // Check if user is active
    if (!user.isActive) {
      throw new Error('Account is not active');
    }

    // Check MFA if enabled
    if (user.mfaSecretEncrypted) {
      if (!credentials.mfaCode) {
        throw new Error('MFA code required');
      }
      
      const { mfaService } = await import('./mfa.service');
      const isMfaValid = await mfaService.verifyToken(user.id, credentials.mfaCode);
      if (!isMfaValid) {
        await storage.createUserAuditLog({
          userId: user.id,
          action: 'login',
          ipAddress,
          deviceInfo: userAgent,
          details: { success: false, reason: 'invalid_mfa' },
        });
        throw new Error('Invalid MFA code');
      }
    }

    // Generate tokens
    const accessToken = await jwtService.generateAccessToken(user);
    const refreshToken = await this.generateRefreshToken(user.id, ipAddress, userAgent);

    // Update last login
    await storage.updateUser(user.id, { lastLogin: new Date() });

    // Log successful login
    await storage.createUserAuditLog({
      userId: user.id,
      action: 'login',
      ipAddress,
      deviceInfo: userAgent,
      details: { success: true },
    });

    const { passwordHash: _, mfaSecretEncrypted: __, ...userWithoutSensitiveData } = user;
    return { user: userWithoutSensitiveData as any, accessToken, refreshToken };
  }

  async logout(refreshToken: string, userId?: string): Promise<void> {
    // Get session to revoke
    const session = await storage.getUserSessionByRefreshToken(refreshToken);
    if (session) {
      await storage.revokeUserSession(session.id);
    }

    // Log logout
    if (userId) {
      await storage.createUserAuditLog({
        userId,
        action: 'logout',
        details: { success: true },
      });
    }
  }

  async refreshAccessToken(refreshToken: string): Promise<{ accessToken: string; refreshToken: string }> {
    // Get session using hashed token lookup
    const session = await storage.getUserSessionByRefreshToken(refreshToken);
    
    if (!session || session.expiresAt < new Date() || session.isRevoked) {
      throw new Error('Invalid or expired refresh token');
    }

    // Get user
    const user = await storage.getUser(session.userId);
    if (!user) {
      throw new Error('User not found');
    }

    // Generate new tokens
    const newAccessToken = await jwtService.generateAccessToken(user);
    const newRefreshToken = await this.generateRefreshToken(user.id, session.ipAddress || undefined, session.deviceInfo || undefined);

    // Revoke old session
    await storage.revokeUserSession(session.id);

    return { accessToken: newAccessToken, refreshToken: newRefreshToken };
  }

  async verifyEmail(token: string, ipAddress?: string, userAgent?: string): Promise<{ redirectUrl?: string; accessToken?: string; refreshToken?: string }> {
    const verificationToken = await storage.getEmailVerificationToken(token);
    if (!verificationToken || verificationToken.expiresAt < new Date() || verificationToken.isUsed) {
      throw new Error('Invalid or expired verification token');
    }

    // Verify user
    await storage.updateUser(verificationToken.userId, {
      isEmailVerified: true,
    });

    // Mark token as used
    await storage.markEmailTokenAsUsed(token);

    // Log audit event
    await storage.createUserAuditLog({
      userId: verificationToken.userId,
      action: 'register',
      details: { email_verified: true, success: true },
    });

    let result: { redirectUrl?: string; accessToken?: string; refreshToken?: string } = {};

    // If there's a redirectUrl, generate tokens and potentially append them
    if (verificationToken.redirectUrl) {
      // Get the user to generate tokens
      const user = await storage.getUser(verificationToken.userId);
      if (user) {
        // Generate tokens for the verified user
        const accessToken = await jwtService.generateAccessToken(user);
        const refreshToken = await this.generateRefreshToken(user.id, ipAddress, userAgent);
        
        // Get allowed domains and validate redirect URL first
        const allowedDomains = await storage.getActiveAllowedDomains();
        const validation = validateRedirectUrl(verificationToken.redirectUrl, allowedDomains);
        
        if (validation.isValid && validation.normalizedUrl) {
          const urlWithTokens = appendTokensToUrl(validation.normalizedUrl, allowedDomains, {
            accessToken,
            refreshToken,
            includeRefreshToken: false // Only include access token for security
          });
          
          result = {
            redirectUrl: urlWithTokens,
            accessToken,
            refreshToken
          };
        } else {
          // Invalid redirect URL - don't return tokens or redirectUrl for security
          result = {};
        }
      } else {
        result.redirectUrl = verificationToken.redirectUrl;
      }
    }

    return result;
  }

  async requestPasswordReset(email: string): Promise<{ success: boolean, message: string }> {
    const user = await storage.getUserByEmail(email);
    if (!user) {
      // Return success to avoid email enumeration attacks
      return {
        success: true,
        message: 'If an account with that email exists, a password reset link has been sent.'
      };
    }

    // Generate reset token
    const resetToken = cryptoUtils.generatePasswordResetToken();
    await storage.createPasswordResetToken({
      userId: user.id,
      token: resetToken, // Will be hashed in storage layer
      expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
    });

    // Send password reset email
    const baseUrl = process.env.APP_URL || process.env.VITE_APP_URL || 'http://localhost:5000';
    const resetUrl = `${baseUrl}/reset-password?token=${resetToken}`;
    const emailSent = await emailService.sendPasswordResetEmail({
      to: user.email,
      name: user.name,
      resetUrl
    });

    // Log audit event
    await storage.createUserAuditLog({
      userId: user.id,
      action: 'password_change',
      details: { 
        email: user.email,
        resetEmailSent: emailSent,
        action: 'reset_requested'
      },
    });

    return {
      success: true,
      message: 'If an account with that email exists, a password reset link has been sent.'
    };
  }

  async resetPassword(token: string, newPassword: string): Promise<void> {
    const resetToken = await storage.getPasswordResetToken(token);
    if (!resetToken || resetToken.expiresAt < new Date() || resetToken.isUsed) {
      throw new Error('Invalid or expired reset token');
    }

    // Hash new password
    const passwordHash = await bcrypt.hash(newPassword, this.saltRounds);

    // Update password
    await storage.updateUser(resetToken.userId, { passwordHash });

    // Mark token as used
    await storage.markPasswordTokenAsUsed(token);

    // Revoke all user sessions for this user
    await storage.revokeUserSessions(resetToken.userId);

    // Log audit event
    await storage.createUserAuditLog({
      userId: resetToken.userId,
      action: 'password_change',
      details: { success: true },
    });
  }

  async changePassword(userId: string, currentPassword: string, newPassword: string): Promise<void> {
    // Get user to verify current password
    const user = await storage.getUser(userId);
    if (!user) {
      throw new Error('User not found');
    }

    // Verify current password
    const isValidPassword = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!isValidPassword) {
      await storage.createUserAuditLog({
        userId,
        action: 'password_change',
        details: { success: false, reason: 'invalid_current_password' },
      });
      throw new Error('Current password is incorrect');
    }

    // Hash new password
    const passwordHash = await bcrypt.hash(newPassword, this.saltRounds);

    // Update password
    await storage.updateUser(userId, { passwordHash });

    // Revoke all user sessions except current one (user can revoke all if they want)
    // await storage.revokeUserSessions(userId);

    // Log audit event
    await storage.createUserAuditLog({
      userId,
      action: 'password_change',
      details: { success: true, initiated_by_user: true },
    });
  }

  async deleteUserAccount(userId: string, currentPassword: string): Promise<void> {
    // Get user to verify password
    const user = await storage.getUser(userId);
    if (!user) {
      throw new Error('User not found');
    }

    // Verify current password for security
    const isValidPassword = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!isValidPassword) {
      await storage.createUserAuditLog({
        userId,
        action: 'user_delete',
        details: { success: false, reason: 'invalid_password' },
      });
      throw new Error('Current password is incorrect');
    }

    // Log audit event before deletion
    await storage.createUserAuditLog({
      userId,
      action: 'user_delete',
      details: { success: true, initiated_by_user: true, email: user.email },
    });

    // Revoke all user sessions
    await storage.revokeUserSessions(userId);

    // Soft delete or hard delete depending on business requirements
    // For now, we'll just deactivate the account
    await storage.updateUser(userId, { 
      isActive: false,
      // Note: In a real system, you might want to anonymize the data
      // or implement a proper deletion process with retention policies
    });
  }

  private async generateRefreshToken(userId: string, ipAddress?: string, deviceInfo?: string): Promise<string> {
    const token = cryptoUtils.generateRefreshToken();

    await storage.createUserSession({
      userId,
      refreshToken: token, // Will be hashed in storage layer
      expiresAt: new Date(Date.now() + this.refreshTokenTtl),
      ipAddress,
      deviceInfo,
    });

    return token;
  }
}

export const authService = new AuthService();
