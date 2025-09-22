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
import { authenticateToken, requireRole, requirePermissions, optionalAuth, rateLimit } from "./middleware/auth.middleware";
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
    rateLimit(3, 15 * 60 * 1000), // 3 attempts per 15 minutes
    validateBody(registerSchema),
    async (req, res) => {
      try {
        const result = await authService.register(req.body);
        
        // In production, send email verification
        if (process.env.NODE_ENV !== 'production') {
          console.log('Email verification token (dev only):', result.verificationToken);
        }
        
        res.status(201).json({
          message: 'User registered successfully. Please check your email for verification.',
          verificationSent: true,
        });
      } catch (error) {
        res.status(400).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  authRouter.post('/login',
    rateLimit(5, 15 * 60 * 1000), // 5 attempts per 15 minutes
    validateBody(loginSchema),
    async (req, res) => {
      try {
        const result = await authService.login(
          req.body,
          req.ip,
          req.headers['user-agent']
        );
        
        res.json({
          accessToken: result.accessToken,
          refreshToken: result.refreshToken,
          user: result.user,
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

  authRouter.post('/verify',
    validateBody(verifyTokenSchema),
    async (req, res) => {
      try {
        await authService.verifyEmail(req.body.token);
        res.json({ message: 'Email verified successfully' });
      } catch (error) {
        res.status(400).json({ message: error instanceof Error ? error.message : String(error) });
      }
    }
  );

  authRouter.post('/forgot-password',
    rateLimit(3, 60 * 60 * 1000), // 3 attempts per hour
    validateBody(z.object({ email: commonSchemas.email })),
    async (req, res) => {
      try {
        const resetToken = await authService.requestPasswordReset(req.body.email);
        
        // In production, send email with reset link
        if (process.env.NODE_ENV !== 'production') {
          console.log('Password reset token (dev only):', resetToken);
        }
        
        res.json({ message: 'Password reset instructions sent to your email' });
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
    rateLimit(5, 15 * 60 * 1000), // 5 attempts per 15 minutes
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
    rateLimit(3, 60 * 60 * 1000), // 3 attempts per hour
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

  app.use('/api/auth', authRouter);

  // OAuth2 token endpoint
  app.post('/api/oauth/token', 
    rateLimit(10, 15 * 60 * 1000), // 10 attempts per 15 minutes
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
          const loginResult = await authService.login({ email: username, password });
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

  userRouter.get('/',
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

  app.use('/api/admin', adminRouter);

  // MFA routes
  const mfaRouter = express.Router();

  mfaRouter.get('/setup',
    authenticateToken,
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
