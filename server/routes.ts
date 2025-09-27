import type { Express } from "express";
import { createServer, type Server } from "http";
import express from 'express';
import { storage } from "./storage";
import { authService } from "./services/auth.service";
import { userService } from "./services/user.service";
import { jwtService } from "./services/jwt.service";
import { mfaService } from "./services/mfa.service";
import { auditService } from "./services/audit.service";
import { cryptoUtils } from "./utils/crypto";
import { validateBody, validateQuery, validateParams, commonSchemas } from "./utils/validation";
import { validateRedirectUrl } from "./utils/domain-validation";
import { appendTokensToUrl } from "./utils/token-url";
import { googleOAuthService } from "./services/google-oauth.service";
import { authenticateToken, requireRole, requirePermissions, optionalAuth, rateLimit } from "./middleware/auth.middleware";
import { 
  authRateLimit, 
  strictAuthRateLimit, 
  apiRateLimit, 
  heavyApiRateLimit, 
  createUserRateLimit,
  enforceSessionLimitAtLogin,
  sessionMonitoring 
} from "./middleware/security.middleware";
import bcrypt from 'bcrypt';
import { z } from 'zod';
import {
  loginSchema,
  registerSchema,
  refreshTokenSchema,
  verifyTokenSchema,
  resetPasswordSchema,
  changePasswordSchema,
  enableMfaSchema,
  insertClientSchema,
  insertAllowedDomainSchema,
  updateAllowedDomainSchema,
} from "@shared/schema";

export async function registerRoutes(app: Express): Promise<Server> {
  // Health check endpoints
  app.get('/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
  });

  app.get('/ready', async (req, res) => {
    try {
      // Check database connectivity
      await storage.getUsersCount();
      res.json({ status: 'ready', timestamp: new Date().toISOString() });
    } catch (error) {
      res.status(503).json({ status: 'not ready', error: error instanceof Error ? error.message : String(error) });
    }
  });

  // Basic metrics endpoint (secured)
  app.get('/metrics', 
    authenticateToken,
    requirePermissions('system', 'read'),
    async (req, res) => {
    try {
      const metrics = await storage.getSystemMetrics();
      const failedLogins = await auditService.getFailedLoginAttempts();
      
      // Simple Prometheus-style metrics
      const prometheusMetrics = `
# HELP idm_users_total Total number of users
# TYPE idm_users_total gauge
idm_users_total ${metrics.totalUsers}

# HELP idm_active_users Total number of active users
# TYPE idm_active_users gauge
idm_active_users ${metrics.activeUsers}

# HELP idm_clients_total Total number of API clients
# TYPE idm_clients_total gauge
idm_clients_total ${metrics.totalClients}

# HELP idm_active_keys Total number of active JWT keys
# TYPE idm_active_keys gauge
idm_active_keys ${metrics.activeKeys}

# HELP idm_failed_logins_24h Failed login attempts in last 24 hours
# TYPE idm_failed_logins_24h gauge
idm_failed_logins_24h ${failedLogins.count}
      `.trim();

      res.set('Content-Type', 'text/plain');
      res.send(prometheusMetrics);
    } catch (error) {
      res.status(500).json({ error: 'Failed to retrieve metrics' });
    }
  });

  // JWKS endpoint
  app.get('/.well-known/jwks.json', async (req, res) => {
    try {
      const jwks = await jwtService.getJwksResponse();
      res.json(jwks);
    } catch (error) {
      res.status(500).json({ message: 'Failed to retrieve JWKS' });
    }
  });

  // Authentication routes
  const authRouter = express.Router();

  authRouter.post('/register', 
    strictAuthRateLimit, // 3 attempts per 15 minutes
    validateBody(registerSchema),
    async (req, res) => {
      try {
        // Validate redirect URL if provided
        if (req.body.redirectUrl) {
          const allowedDomains = await storage.getActiveAllowedDomains();
          const validation = validateRedirectUrl(req.body.redirectUrl, allowedDomains);
          if (!validation.isValid) {
            return res.status(400).json({ 
              message: `Invalid redirect URL: ${validation.error}`
            });
          }
          // Use normalized URL
          req.body.redirectUrl = validation.normalizedUrl;
        }

        const result = await authService.register(req.body);
        
        res.status(201).json({
          message: result.message,
          verificationSent: true,
        });
      } catch (error) {
        res.status(400).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  authRouter.post('/login',
    authRateLimit, // 5 attempts per 15 minutes
    enforceSessionLimitAtLogin(5), // Limit to 5 concurrent sessions per user
    validateBody(loginSchema.extend({ redirectUrl: z.string().optional() })),
    async (req, res) => {
      try {
        const result = await authService.login(
          req.body,
          req.ip,
          req.headers['user-agent']
        );
        
        // Handle redirect URL with JWT details appended
        let redirectUrlWithTokens: string | undefined;
        
        if (req.body.redirectUrl) {
          const allowedDomains = await storage.getActiveAllowedDomains();
          const validation = validateRedirectUrl(req.body.redirectUrl, allowedDomains);
          
          if (validation.isValid && validation.normalizedUrl) {
            redirectUrlWithTokens = appendTokensToUrl(validation.normalizedUrl, allowedDomains, {
              accessToken: result.accessToken,
              refreshToken: result.refreshToken,
              includeRefreshToken: false // Only include access token for security
            });
          }
        }
        
        res.json({
          accessToken: result.accessToken,
          refreshToken: result.refreshToken,
          user: result.user,
          redirectUrl: redirectUrlWithTokens,
        });
      } catch (error) {
        res.status(401).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  authRouter.post('/logout',
    authenticateToken,
    validateBody(refreshTokenSchema),
    async (req, res) => {
      try {
        await authService.logout(req.body.refreshToken, req.user?.id);
        res.json({ message: 'Logged out successfully' });
      } catch (error) {
        res.status(400).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  // Redirect URL validation endpoint
  authRouter.post('/validate-redirect',
    apiRateLimit,
    async (req, res) => {
      try {
        const { redirectUrl } = req.body;
        
        if (!redirectUrl) {
          return res.status(400).json({ message: 'Redirect URL is required' });
        }
        
        const allowedDomains = await storage.getActiveAllowedDomains();
        const validation = validateRedirectUrl(redirectUrl, allowedDomains);
        
        if (validation.isValid) {
          res.json({ 
            valid: true, 
            normalizedUrl: validation.normalizedUrl 
          });
        } else {
          res.json({ 
            valid: false, 
            error: validation.error 
          });
        }
      } catch (error) {
        res.status(500).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  // Append tokens to URL for allowed domains (token validation endpoint)
  authRouter.post('/append-tokens-to-url',
    apiRateLimit,
    async (req, res) => {
      try {
        const { url, accessToken } = req.body;
        
        if (!url) {
          return res.status(400).json({ message: 'URL is required' });
        }
        
        if (!accessToken) {
          return res.status(400).json({ message: 'Access token is required' });
        }
        
        // Validate the provided access token
        try {
          const payload = await jwtService.verifyToken(accessToken);
          
          // Verify user still exists and is active
          const user = await storage.getUser(payload.sub);
          if (!user || !user.isActive) {
            return res.status(401).json({ message: 'User not found or inactive' });
          }
          
          // Validate and normalize the URL against allowed domains
          const allowedDomains = await storage.getActiveAllowedDomains();
          const validation = validateRedirectUrl(url, allowedDomains);
          
          if (!validation.isValid || !validation.normalizedUrl) {
            return res.status(400).json({ message: 'Invalid or disallowed redirect URL' });
          }
          
          // Generate fresh access token for URL appending (no refresh token needed)
          const freshAccessToken = await jwtService.generateAccessToken(user);
          
          const urlWithTokens = appendTokensToUrl(validation.normalizedUrl, allowedDomains, {
            accessToken: freshAccessToken,
            includeRefreshToken: false // Always false for security
          });
          
          // Normalize response to avoid domain probing
          res.json({ 
            urlWithTokens: urlWithTokens
          });
        } catch (tokenError) {
          return res.status(401).json({ message: 'Invalid or expired access token' });
        }
      } catch (error) {
        res.status(500).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  authRouter.post('/verify',
    validateBody(verifyTokenSchema),
    async (req, res) => {
      try {
        const result = await authService.verifyEmail(
          req.body.token,
          req.ip,
          req.headers['user-agent']
        );
        
        // Critical: Re-validate redirect URL for security
        if (result.redirectUrl) {
          const allowedDomains = await storage.getActiveAllowedDomains();
          const validation = validateRedirectUrl(result.redirectUrl, allowedDomains);
          if (!validation.isValid) {
            // Remove invalid redirect URL and tokens for security
            result.redirectUrl = undefined;
            result.accessToken = undefined;
            result.refreshToken = undefined;
          }
        }
        
        res.json({ 
          message: 'Email verified successfully',
          redirectUrl: result.redirectUrl,
          accessToken: result.accessToken,
          refreshToken: result.refreshToken
        });
      } catch (error) {
        res.status(400).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  authRouter.post('/forgot-password',
    strictAuthRateLimit, // 3 attempts per 15 minutes
    validateBody(z.object({ email: commonSchemas.email })),
    async (req, res) => {
      try {
        const result = await authService.requestPasswordReset(req.body.email);
        res.json({ message: result.message });
      } catch (error) {
        res.status(400).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  authRouter.post('/reset-password',
    validateBody(resetPasswordSchema),
    async (req, res) => {
      try {
        await authService.resetPassword(req.body.token, req.body.password);
        res.json({ message: 'Password reset successfully' });
      } catch (error) {
        res.status(400).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  authRouter.post('/change-password',
    authenticateToken,
    createUserRateLimit({ windowMs: 15 * 60 * 1000, maxRequests: 5 }), // 5 attempts per 15 minutes per user
    validateBody(changePasswordSchema),
    async (req, res) => {
      try {
        await authService.changePassword(
          req.user!.id,
          req.body.currentPassword,
          req.body.newPassword
        );
        res.json({ message: 'Password changed successfully' });
      } catch (error) {
        res.status(400).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  authRouter.delete('/account',
    authenticateToken,
    createUserRateLimit({ windowMs: 60 * 60 * 1000, maxRequests: 3 }), // 3 attempts per hour per user
    validateBody(z.object({ currentPassword: z.string() })),
    async (req, res) => {
      try {
        await authService.deleteUserAccount(req.user!.id, req.body.currentPassword);
        res.json({ message: 'Account deleted successfully' });
      } catch (error) {
        res.status(400).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  // Google OAuth routes
  authRouter.get('/google',
    apiRateLimit,
    async (req, res) => {
      try {
        const redirectUrl = req.query.redirectUrl as string;
        const state = redirectUrl ? Buffer.from(JSON.stringify({ redirectUrl })).toString('base64') : undefined;
        
        const authUrl = googleOAuthService.getAuthUrl(state);
        res.redirect(authUrl);
      } catch (error) {
        res.status(500).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  authRouter.get('/google/callback',
    apiRateLimit,
    async (req, res) => {
      try {
        const { code, state } = req.query;
        
        if (!code) {
          return res.status(400).json({ message: 'Authorization code is required' });
        }

        // Handle OAuth callback
        const result = await googleOAuthService.handleOAuthCallback(
          code as string,
          req.ip,
          req.headers['user-agent']
        );

        // Parse state to get redirect URL
        let redirectUrl = '/dashboard'; // Default redirect
        if (state) {
          try {
            const stateData = JSON.parse(Buffer.from(state as string, 'base64').toString());
            if (stateData.redirectUrl) {
              // Validate redirect URL
              const allowedDomains = await storage.getActiveAllowedDomains();
              const validation = validateRedirectUrl(stateData.redirectUrl, allowedDomains);
              if (validation.isValid && validation.normalizedUrl) {
                // Append tokens to allowed domain URLs
                redirectUrl = appendTokensToUrl(validation.normalizedUrl, allowedDomains, {
                  accessToken: result.accessToken,
                  refreshToken: result.refreshToken,
                  includeRefreshToken: false
                });
              }
            }
          } catch (error) {
            // Invalid state, use default redirect
            console.warn('Invalid OAuth state:', error);
          }
        }

        // For same-origin redirects, store tokens and redirect
        try {
          const redirectUrlObj = new URL(redirectUrl);
          const currentOrigin = req.get('origin') || `${req.protocol}://${req.get('host')}`;
          
          if (redirectUrlObj.origin === currentOrigin) {
            // Same-origin: redirect to a page that will handle token storage
            const params = new URLSearchParams({
              access_token: result.accessToken,
              refresh_token: result.refreshToken,
              redirect: redirectUrl
            });
            res.redirect(`/oauth/success?${params.toString()}`);
          } else {
            // Cross-origin: redirect with tokens in URL fragment
            res.redirect(redirectUrl);
          }
        } catch (error) {
          // If URL parsing fails, treat as same-origin
          const params = new URLSearchParams({
            access_token: result.accessToken,
            refresh_token: result.refreshToken,
            redirect: redirectUrl
          });
          res.redirect(`/oauth/success?${params.toString()}`);
        }
      } catch (error) {
        console.error('Google OAuth callback error:', error);
        res.redirect(`/login?error=${encodeURIComponent('OAuth authentication failed')}`);
      }
    }
  );

  app.use('/api/auth', authRouter);

  // OAuth2 token endpoint
  app.post('/api/oauth/token', 
    authRateLimit, // 5 attempts per 15 minutes
    async (req, res) => {
    const { grant_type, refresh_token, client_id, client_secret, username, password } = req.body;

    try {
      switch (grant_type) {
        case 'refresh_token':
          if (!refresh_token) {
            return res.status(400).json({ error: 'refresh_token required' });
          }
          const result = await authService.refreshAccessToken(refresh_token);
          res.json({
            access_token: result.accessToken,
            refresh_token: result.refreshToken,
            token_type: 'Bearer',
            expires_in: 900, // 15 minutes
          });
          break;

        case 'password':
          if (!username || !password) {
            return res.status(400).json({ error: 'username and password required' });
          }
          const loginResult = await authService.login({ identifier: username, password });
          res.json({
            access_token: loginResult.accessToken,
            refresh_token: loginResult.refreshToken,
            token_type: 'Bearer',
            expires_in: 900,
          });
          break;

        case 'client_credentials':
          if (!client_id || !client_secret) {
            return res.status(400).json({ error: 'client_id and client_secret required' });
          }
          
          // Verify client credentials
          const client = await storage.getClient(client_id);
          if (!client || !client.isActive) {
            return res.status(401).json({ error: 'invalid_client' });
          }

          const isValidSecret = await bcrypt.compare(client_secret, client.clientSecretHash);
          if (!isValidSecret) {
            return res.status(401).json({ error: 'invalid_client' });
          }

          // Generate client access token (no refresh token for client credentials)
          const clientToken = await jwtService.generateAccessToken({
            id: client.id,
            email: client.clientId,
            name: client.name,
            role: 'client',
          } as any);

          res.json({
            access_token: clientToken,
            token_type: 'Bearer',
            expires_in: 3600, // 1 hour for client tokens
          });
          break;

        default:
          res.status(400).json({ error: 'unsupported_grant_type' });
      }
    } catch (error) {
      res.status(400).json({ error: 'invalid_grant', error_description: error instanceof Error ? error.message : String(error) });
    }
  });

  // User management routes
  const userRouter = express.Router();
  userRouter.use(sessionMonitoring); // Track user activity after authentication

  userRouter.get('/',
    authenticateToken,
    apiRateLimit,
    requirePermissions('users', 'read'),
    validateQuery(commonSchemas.pagination as any),
    async (req, res) => {
      try {
        const { page = 1, limit = 50 } = req.query as any;
        const result = await userService.getAllUsers(page, limit);
        res.json(result);
      } catch (error) {
        res.status(500).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  userRouter.get('/:id',
    authenticateToken,
    validateParams(z.object({ id: commonSchemas.uuid })),
    async (req, res) => {
      try {
        const user = await userService.getUserById(req.params.id);
        if (!user) {
          return res.status(404).json({ message: 'User not found' });
        }

        // Check if user can access this profile
        if (req.user?.role !== 'admin' && req.user?.id !== req.params.id) {
          return res.status(403).json({ message: 'Access denied' });
        }

        res.json(user);
      } catch (error) {
        res.status(500).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  userRouter.post('/',
    authenticateToken,
    heavyApiRateLimit,
    requirePermissions('users', 'create'),
    validateBody(registerSchema.extend({
      sendWelcomeEmail: z.boolean().optional(),
      requireMfa: z.boolean().optional(),
    })),
    async (req, res) => {
      try {
        const user = await userService.createUser(req.body, req.user?.id);
        res.status(201).json(user);
      } catch (error) {
        res.status(400).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  userRouter.patch('/:id',
    authenticateToken,
    validateParams(z.object({ id: commonSchemas.uuid })),
    async (req, res) => {
      try {
        // Check permissions
        if (req.user?.role !== 'admin' && req.user?.id !== req.params.id) {
          return res.status(403).json({ message: 'Access denied' });
        }

        const user = await userService.updateUser(req.params.id, req.body, req.user?.id);
        if (!user) {
          return res.status(404).json({ message: 'User not found' });
        }

        res.json(user);
      } catch (error) {
        res.status(400).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  userRouter.delete('/:id',
    authenticateToken,
    heavyApiRateLimit,
    requirePermissions('users', 'delete'),
    validateParams(z.object({ id: commonSchemas.uuid })),
    async (req, res) => {
      try {
        const deleted = await userService.deleteUser(req.params.id, req.user?.id);
        if (deleted) {
          res.json({ message: 'User deleted successfully' });
        } else {
          res.status(404).json({ message: 'User not found' });
        }
      } catch (error) {
        res.status(400).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  app.use('/api/users', userRouter);

  // Admin routes
  const adminRouter = express.Router();

  adminRouter.get('/users',
    authenticateToken,
    requirePermissions('users', 'read'),
    validateQuery(commonSchemas.pagination as any),
    async (req, res) => {
      try {
        const { page = 1, limit = 50 } = req.query as any;
        const result = await userService.getAllUsers(page, limit);
        res.json(result);
      } catch (error) {
        res.status(500).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  adminRouter.get('/stats',
    authenticateToken,
    requirePermissions('system', 'read'),
    async (req, res) => {
      try {
        const [userStats, systemMetrics] = await Promise.all([
          userService.getUserStats(),
          storage.getSystemMetrics(),
        ]);

        res.json({
          users: userStats,
          system: systemMetrics,
        });
      } catch (error) {
        res.status(500).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  adminRouter.post('/keys/rotate',
    authenticateToken,
    heavyApiRateLimit,
    requirePermissions('system', 'admin'),
    async (req, res) => {
      try {
        const result = await jwtService.rotateKeys();
        
        await auditService.log({
          actorId: req.user?.id,
          action: 'key_rotation',
          resource: 'system',
          success: true,
        });

        res.json({ message: 'Keys rotated successfully', kid: result.kid });
      } catch (error) {
        res.status(500).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  // Allowed domains routes
  adminRouter.get('/allowed-domains',
    authenticateToken,
    requirePermissions('system', 'read'),
    async (req, res) => {
      try {
        const domains = await storage.getAllAllowedDomains();
        res.json(domains);
      } catch (error) {
        res.status(500).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  adminRouter.post('/allowed-domains',
    authenticateToken,
    heavyApiRateLimit,
    requirePermissions('system', 'admin'),
    validateBody(insertAllowedDomainSchema),
    async (req, res) => {
      try {
        const domain = await storage.createAllowedDomain(req.body);
        
        await auditService.log({
          actorId: req.user?.id,
          action: 'user_create', // Closest available action for domain creation
          resource: 'allowed_domain',
          resourceId: domain.id,
          metadata: { domain: domain.domain, description: domain.description },
          success: true,
        });

        res.status(201).json(domain);
      } catch (error) {
        res.status(400).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  adminRouter.put('/allowed-domains/:id',
    authenticateToken,
    heavyApiRateLimit,
    requirePermissions('system', 'admin'),
    validateParams(z.object({ id: z.string().uuid() })),
    validateBody(updateAllowedDomainSchema),
    async (req, res) => {
      try {
        const domain = await storage.updateAllowedDomain(req.params.id, req.body);
        
        if (!domain) {
          return res.status(404).json({ message: 'Allowed domain not found' });
        }

        await auditService.log({
          actorId: req.user?.id,
          action: 'user_update', // Closest available action for domain update
          resource: 'allowed_domain',
          resourceId: domain.id,
          metadata: { domain: domain.domain, description: domain.description },
          success: true,
        });

        res.json(domain);
      } catch (error) {
        res.status(400).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  adminRouter.delete('/allowed-domains/:id',
    authenticateToken,
    heavyApiRateLimit,
    requirePermissions('system', 'admin'),
    validateParams(z.object({ id: z.string().uuid() })),
    async (req, res) => {
      try {
        const domain = await storage.getAllowedDomain(req.params.id);
        if (!domain) {
          return res.status(404).json({ message: 'Allowed domain not found' });
        }

        const deleted = await storage.deleteAllowedDomain(req.params.id);
        
        if (deleted) {
          await auditService.log({
            actorId: req.user?.id,
            action: 'user_delete', // Closest available action for domain deletion
            resource: 'allowed_domain',
            resourceId: req.params.id,
            metadata: { domain: domain.domain },
            success: true,
          });

          res.json({ message: 'Allowed domain deleted successfully' });
        } else {
          res.status(404).json({ message: 'Allowed domain not found' });
        }
      } catch (error) {
        res.status(500).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  app.use('/api/admin', adminRouter);

  // MFA routes
  const mfaRouter = express.Router();

  mfaRouter.get('/setup',
    authenticateToken,
    apiRateLimit,
    async (req, res) => {
      try {
        const result = await mfaService.generateMfaSecret(req.user!.id);
        res.json(result);
      } catch (error) {
        res.status(400).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  mfaRouter.post('/enable',
    authenticateToken,
    createUserRateLimit({ windowMs: 15 * 60 * 1000, maxRequests: 3 }),
    validateBody(enableMfaSchema),
    async (req, res) => {
      try {
        await mfaService.enableMfa(req.user!.id, req.body.mfaCode);
        res.json({ message: 'MFA enabled successfully' });
      } catch (error) {
        res.status(400).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  mfaRouter.post('/disable',
    authenticateToken,
    createUserRateLimit({ windowMs: 15 * 60 * 1000, maxRequests: 3 }),
    validateBody(enableMfaSchema),
    async (req, res) => {
      try {
        await mfaService.disableMfa(req.user!.id, req.body.mfaCode);
        res.json({ message: 'MFA disabled successfully' });
      } catch (error) {
        res.status(400).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  mfaRouter.get('/status',
    authenticateToken,
    apiRateLimit,
    async (req, res) => {
      try {
        const status = await mfaService.getMfaStatus(req.user!.id);
        res.json(status);
      } catch (error) {
        res.status(500).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  app.use('/api/mfa', mfaRouter);

  // API Clients routes
  const clientsRouter = express.Router();

  clientsRouter.get('/',
    authenticateToken,
    apiRateLimit,
    requirePermissions('clients', 'read'),
    async (req, res) => {
      try {
        const clients = await storage.getAllClients();
        // Don't return client secrets
        const safeClients = clients.map(({ clientSecretHash: _, ...client }) => client);
        res.json(safeClients);
      } catch (error) {
        res.status(500).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  clientsRouter.post('/',
    authenticateToken,
    heavyApiRateLimit,
    requirePermissions('clients', 'create'),
    validateBody(insertClientSchema),
    async (req, res) => {
      try {
        const clientId = `client_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const clientSecret = cryptoUtils.generateApiKey();
        const clientSecretHash = await bcrypt.hash(clientSecret, 12);

        const client = await storage.createClient({
          ...req.body,
          clientId,
          clientSecretHash,
        });

        await auditService.log({
          actorId: req.user?.id,
          action: 'api_key_create',
          resource: 'client',
          resourceId: client.id,
          metadata: { clientId, name: client.name },
          success: true,
        });

        // Return client secret only once
        res.status(201).json({
          ...client,
          clientSecret,
          clientSecretHash: undefined,
        });
      } catch (error) {
        res.status(400).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  app.use('/api/clients', clientsRouter);

  // Audit logs routes
  const auditRouter = express.Router();

  auditRouter.get('/',
    authenticateToken,
    apiRateLimit,
    requirePermissions('audit', 'read'),
    validateQuery(commonSchemas.pagination as any),
    async (req, res) => {
      try {
        const { page = 1, limit = 50 } = req.query as any;
        const result = await auditService.getAuditLogs({ page, limit });
        res.json(result);
      } catch (error) {
        res.status(500).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  auditRouter.get('/security-events',
    authenticateToken,
    apiRateLimit,
    requirePermissions('audit', 'read'),
    async (req, res) => {
      try {
        const events = await auditService.getSecurityEvents();
        res.json(events);
      } catch (error) {
        res.status(500).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  app.use('/api/audit', auditRouter);

  // Emergency JWT key rotation endpoint (for development debugging)
  app.post('/api/system/emergency-rotate-jwt', async (req, res) => {
    if (process.env.NODE_ENV === 'production') {
      return res.status(403).json({ message: 'Not available in production' });
    }
    
    try {
      console.log('🔑 Emergency JWT key rotation triggered...');
      
      // Deactivate all existing keys first  
      const allKeys = await storage.getAllJwksKeys();
      for (const key of allKeys) {
        await storage.deactivateJwksKey(key.kid);
      }
      console.log(`🗑️ Deactivated ${allKeys.length} existing JWT keys`);
      
      // Generate new keys with current encryption key
      const result = await jwtService.rotateKeys();
      console.log('✅ Successfully generated new JWT keys:', result.kid);
      
      res.json({ 
        success: true, 
        message: 'JWT keys rotated successfully', 
        newKeyId: result.kid,
        deactivatedKeys: allKeys.length
      });
    } catch (error) {
      console.error('❌ Failed to rotate JWT keys:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Failed to rotate JWT keys', 
        error: error instanceof Error ? error.message : String(error) 
      });
    }
  });

  // OpenAPI/Swagger documentation
  app.get('/api/openapi.json', async (req, res) => {
    try {
      const fs = await import('fs/promises');
      const path = await import('path');
      const openapi = await fs.readFile(path.join(process.cwd(), 'openapi.json'), 'utf-8');
      res.json(JSON.parse(openapi));
    } catch (error) {
      res.status(404).json({ message: 'OpenAPI documentation not found' });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
