import { google } from 'googleapis';
import { storage } from '../storage';
import { jwtService } from './jwt.service';
import { authService } from './auth.service';

export class GoogleOAuthService {
  private oauth2Client: any;

  constructor() {
    this.oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      process.env.GOOGLE_REDIRECT_URI
    );
  }

  /**
   * Generate authorization URL for Google OAuth
   */
  getAuthUrl(state?: string): string {
    const scopes = [
      'https://www.googleapis.com/auth/userinfo.profile',
      'https://www.googleapis.com/auth/userinfo.email',
      'openid'
    ];

    return this.oauth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: scopes.join(' '), // Join scopes with space for proper URL encoding
      state: state, // Used to pass redirect URL or other state
      prompt: 'consent', // Force consent screen to get refresh token
    });
  }

  /**
   * Exchange authorization code for tokens and user info
   */
  async exchangeCodeForTokens(code: string): Promise<{
    accessToken: string;
    refreshToken: string;
    userInfo: any;
  }> {
    try {
      // Exchange code for tokens
      const { tokens } = await this.oauth2Client.getToken(code);
      this.oauth2Client.setCredentials(tokens);

      // Get user profile information
      const oauth2 = google.oauth2({ version: 'v2', auth: this.oauth2Client });
      const { data: userInfo } = await oauth2.userinfo.get();

      return {
        accessToken: tokens.access_token!,
        refreshToken: tokens.refresh_token!,
        userInfo
      };
    } catch (error) {
      throw new Error(`Failed to exchange code for tokens: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Handle Google OAuth login/signup flow
   */
  async handleOAuthCallback(
    code: string, 
    ipAddress?: string, 
    userAgent?: string
  ): Promise<{
    user: any;
    accessToken: string;
    refreshToken: string;
    isNewUser: boolean;
  }> {
    // Exchange code for Google tokens and user info
    const { userInfo } = await this.exchangeCodeForTokens(code);

    if (!userInfo.email) {
      throw new Error('Email is required from Google profile');
    }

    // Check if user exists
    let user = await storage.getUserByEmail(userInfo.email);
    let isNewUser = false;

    if (!user) {
      // Create new user account
      isNewUser = true;
      
      // Get default user role
      const defaultRole = await storage.getRoleByName('user');
      if (!defaultRole) {
        throw new Error('Default user role not found');
      }

      user = await storage.createUser({
        email: userInfo.email,
        name: userInfo.name || userInfo.email,
        password: '', // No password for OAuth users
        phoneNumber: '', // Not provided by Google
        roleId: defaultRole.id,
        isEmailVerified: true, // Google emails are pre-verified
        googleId: userInfo.id, // Store Google ID for future logins
        profilePicture: userInfo.picture, // Store profile picture URL
      });

      // Log registration audit event
      await storage.createUserAuditLog({
        userId: user.id,
        action: 'register',
        ipAddress,
        deviceInfo: userAgent,
        details: { 
          email: user.email,
          provider: 'google',
          googleId: userInfo.id
        },
      });
    } else {
      // Update existing user with Google info if not already set
      const updateData: any = {};
      if (!user.googleId) {
        updateData.googleId = userInfo.id;
      }
      if (!user.isEmailVerified) {
        updateData.isEmailVerified = true;
      }
      if (userInfo.picture && !user.profilePicture) {
        updateData.profilePicture = userInfo.picture;
      }
      
      if (Object.keys(updateData).length > 0) {
        const updatedUser = await storage.updateUser(user.id, updateData);
        user = updatedUser || user;
      }

      // Update last login
      await storage.updateUser(user.id, { lastLogin: new Date() });
    }

    // Ensure user exists before proceeding
    if (!user) {
      throw new Error('Failed to create or retrieve user');
    }

    // Check if user is active
    if (!user.isActive) {
      throw new Error('Account is not active');
    }

    // Generate JWT tokens for the user
    const accessToken = await jwtService.generateAccessToken(user);
    const refreshToken = await authService['generateRefreshToken'](user.id, ipAddress, userAgent);

    // Log successful login
    await storage.createUserAuditLog({
      userId: user.id,
      action: 'login',
      ipAddress,
      deviceInfo: userAgent,
      details: { 
        success: true, 
        provider: 'google',
        isNewUser 
      },
    });

    const { passwordHash: _, mfaSecretEncrypted: __, ...userWithoutSensitiveData } = user;
    return { 
      user: userWithoutSensitiveData as any, 
      accessToken, 
      refreshToken,
      isNewUser 
    };
  }
}

export const googleOAuthService = new GoogleOAuthService();