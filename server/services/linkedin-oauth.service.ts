import { storage } from '../storage';
import { jwtService } from './jwt.service';
import { cryptoUtils } from '../utils/crypto';

interface LinkedInUserInfo {
  sub: string;
  name: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  email?: string;
  email_verified?: boolean;
}

interface LinkedInTokenResponse {
  access_token: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
}

export class LinkedInOAuthService {
  private clientId: string;
  private clientSecret: string;
  private redirectUri: string;

  constructor() {
    this.clientId = process.env.LINKEDIN_CLIENT_ID || '';
    this.clientSecret = process.env.LINKEDIN_CLIENT_SECRET || '';
    this.redirectUri = process.env.LINKEDIN_REDIRECT_URI || '';
  }

  /**
   * Generate authorization URL for LinkedIn OAuth
   */
  getAuthUrl(state?: string): string {
    const scopes = ['openid', 'profile', 'email'];
    
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope: scopes.join(' '),
      ...(state && { state }),
    });

    return `https://www.linkedin.com/oauth/v2/authorization?${params.toString()}`;
  }

  /**
   * Exchange authorization code for access token
   */
  async exchangeCodeForTokens(code: string): Promise<{
    accessToken: string;
    refreshToken?: string;
    userInfo: LinkedInUserInfo;
  }> {
    try {
      // Exchange code for access token
      const tokenResponse = await fetch('https://www.linkedin.com/oauth/v2/accessToken', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: this.clientId,
          client_secret: this.clientSecret,
          redirect_uri: this.redirectUri,
        }),
      });

      if (!tokenResponse.ok) {
        const errorText = await tokenResponse.text();
        throw new Error(`LinkedIn token exchange failed: ${errorText}`);
      }

      const tokenData: LinkedInTokenResponse = await tokenResponse.json();

      // Get user profile using the access token
      const profileResponse = await fetch('https://api.linkedin.com/v2/userinfo', {
        headers: {
          'Authorization': `Bearer ${tokenData.access_token}`,
        },
      });

      if (!profileResponse.ok) {
        const errorText = await profileResponse.text();
        throw new Error(`LinkedIn profile fetch failed: ${errorText}`);
      }

      const userInfo: LinkedInUserInfo = await profileResponse.json();

      return {
        accessToken: tokenData.access_token,
        refreshToken: tokenData.refresh_token,
        userInfo,
      };
    } catch (error) {
      throw new Error(`Failed to exchange code for tokens: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Handle LinkedIn OAuth login/signup flow
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
    // Exchange code for LinkedIn tokens and user info
    const { userInfo } = await this.exchangeCodeForTokens(code);

    if (!userInfo.email) {
      throw new Error('Email is required from LinkedIn profile');
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
        password: '',
        phoneNumber: '',
        roleId: defaultRole.id,
        isEmailVerified: userInfo.email_verified ?? false,
        linkedInId: userInfo.sub,
        profilePicture: userInfo.picture,
      });

      // Log registration audit event
      await storage.createUserAuditLog({
        userId: user.id,
        action: 'register',
        ipAddress,
        deviceInfo: userAgent,
        details: {
          email: user.email,
          provider: 'linkedin',
          linkedInId: userInfo.sub,
        },
      });
    } else {
      // Update existing user with LinkedIn info if not already set
      const updateData: any = {};
      if (user.linkedInId !== userInfo.sub) {
        updateData.linkedInId = userInfo.sub;
      }
      if (!user.isEmailVerified && userInfo.email_verified) {
        updateData.isEmailVerified = true;
      }
      if (!user.profilePicture && userInfo.picture) {
        updateData.profilePicture = userInfo.picture;
      }

      if (Object.keys(updateData).length > 0) {
        const updatedUser = await storage.updateUser(user.id, updateData);
        if (updatedUser) {
          user = updatedUser;
        }
      }

      // Log login audit event
      await storage.createUserAuditLog({
        userId: user.id,
        action: 'login',
        ipAddress,
        deviceInfo: userAgent,
        details: {
          email: user.email,
          provider: 'linkedin',
          linkedInId: userInfo.sub,
        },
      });
    }

    // Ensure user is defined
    if (!user) {
      throw new Error('User creation or retrieval failed');
    }

    // Generate JWT tokens
    const accessToken = await jwtService.generateAccessToken(user);
    
    // Generate refresh token
    const refreshToken = cryptoUtils.generateRefreshToken();
    await storage.createUserSession({
      userId: user.id,
      refreshToken,
      deviceInfo: userAgent,
      ipAddress,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
    });

    return {
      user,
      accessToken,
      refreshToken,
      isNewUser,
    };
  }
}

export const linkedInOAuthService = new LinkedInOAuthService();
