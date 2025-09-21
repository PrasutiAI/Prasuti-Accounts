import { describe, it, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import request from 'supertest';
import { createServer } from 'http';
import express from 'express';
import { registerRoutes } from '../server/routes';
import { storage } from '../server/storage';
import bcrypt from 'bcrypt';

describe('Authentication API', () => {
  let app: express.Application;
  let server: any;
  let testUser: any;

  beforeAll(async () => {
    app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: false }));
    
    const httpServer = await registerRoutes(app);
    server = httpServer;
  });

  afterAll(async () => {
    if (server) {
      server.close();
    }
  });

  beforeEach(async () => {
    // Get or create user role
    let userRole = await storage.getRoleByName('user');
    if (!userRole) {
      userRole = await storage.createRole({
        name: 'user',
        description: 'Regular user access',
        permissions: ['read'],
        isActive: true,
      });
    }
    
    // Create a test user with proper schema
    testUser = await storage.createUser({
      email: 'test@example.com',
      name: 'Test User',
      password: 'TestPassword123!', // Let storage hash it
      roleId: userRole.id,
    });
    
    // Manually verify email for testing
    await storage.updateUser(testUser.id, {
      isEmailVerified: true,
      isActive: true,
    });
  });

  describe('POST /api/auth/register', () => {
    it('should register a new user', async () => {
      const userData = {
        email: 'newuser@example.com',
        password: 'StrongPassword123!',
        name: 'New User',
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(201);

      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('verificationSent', true);
    });

    it('should reject registration with weak password', async () => {
      const userData = {
        email: 'newuser@example.com',
        password: 'weak',
        name: 'New User',
      };

      await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(400);
    });

    it('should reject registration with invalid email', async () => {
      const userData = {
        email: 'invalid-email',
        password: 'StrongPassword123!',
        name: 'New User',
      };

      await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(400);
    });

    it('should reject registration with existing email', async () => {
      const userData = {
        email: testUser.email,
        password: 'StrongPassword123!',
        name: 'Another User',
      };

      await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(400);
    });
  });

  describe('POST /api/auth/login', () => {
    it('should login with valid credentials', async () => {
      const credentials = {
        email: testUser.email,
        password: 'TestPassword123!',
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(credentials)
        .expect(200);

      expect(response.body).toHaveProperty('accessToken');
      expect(response.body).toHaveProperty('refreshToken');
      expect(response.body).toHaveProperty('user');
      expect(response.body.user).not.toHaveProperty('passwordHash');
    });

    it('should reject login with invalid password', async () => {
      const credentials = {
        email: testUser.email,
        password: 'WrongPassword123!',
      };

      await request(app)
        .post('/api/auth/login')
        .send(credentials)
        .expect(401);
    });

    it('should reject login with non-existent email', async () => {
      const credentials = {
        email: 'nonexistent@example.com',
        password: 'TestPassword123!',
      };

      await request(app)
        .post('/api/auth/login')
        .send(credentials)
        .expect(401);
    });

    it('should reject login for unverified user', async () => {
      // Create unverified user
      const passwordHash = await bcrypt.hash('TestPassword123!', 12);
      const unverifiedUser = await storage.createUser({
        email: 'unverified@example.com',
        name: 'Unverified User',
        passwordHash,
        role: 'user',
        status: 'pending',
        isVerified: false,
      });

      const credentials = {
        email: unverifiedUser.email,
        password: 'TestPassword123!',
      };

      await request(app)
        .post('/api/auth/login')
        .send(credentials)
        .expect(400);
    });
  });

  describe('POST /api/auth/logout', () => {
    let authToken: string;
    let refreshToken: string;

    beforeEach(async () => {
      const credentials = {
        email: testUser.email,
        password: 'TestPassword123!',
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(credentials);

      authToken = response.body.accessToken;
      refreshToken = response.body.refreshToken;
    });

    it('should logout successfully with valid refresh token', async () => {
      await request(app)
        .post('/api/auth/logout')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ refreshToken })
        .expect(200);
    });

    it('should reject logout without authentication', async () => {
      await request(app)
        .post('/api/auth/logout')
        .send({ refreshToken })
        .expect(401);
    });
  });

  describe('POST /api/oauth/token', () => {
    let refreshToken: string;

    beforeEach(async () => {
      const credentials = {
        email: testUser.email,
        password: 'TestPassword123!',
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(credentials);

      refreshToken = response.body.refreshToken;
    });

    it('should refresh access token with valid refresh token', async () => {
      const tokenRequest = {
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
      };

      const response = await request(app)
        .post('/api/oauth/token')
        .send(tokenRequest)
        .expect(200);

      expect(response.body).toHaveProperty('access_token');
      expect(response.body).toHaveProperty('refresh_token');
      expect(response.body).toHaveProperty('token_type', 'Bearer');
      expect(response.body).toHaveProperty('expires_in');
    });

    it('should support password grant type', async () => {
      const tokenRequest = {
        grant_type: 'password',
        username: testUser.email,
        password: 'TestPassword123!',
      };

      const response = await request(app)
        .post('/api/oauth/token')
        .send(tokenRequest)
        .expect(200);

      expect(response.body).toHaveProperty('access_token');
      expect(response.body).toHaveProperty('refresh_token');
    });

    it('should reject invalid grant type', async () => {
      const tokenRequest = {
        grant_type: 'invalid_grant',
      };

      await request(app)
        .post('/api/oauth/token')
        .send(tokenRequest)
        .expect(400);
    });
  });

  describe('GET /.well-known/jwks.json', () => {
    it('should return JWKS', async () => {
      const response = await request(app)
        .get('/.well-known/jwks.json')
        .expect(200);

      expect(response.body).toHaveProperty('keys');
      expect(Array.isArray(response.body.keys)).toBe(true);
    });
  });

  describe('POST /api/auth/verify', () => {
    it('should verify email with valid token', async () => {
      // Create verification token
      const token = 'test-verification-token';
      await storage.createVerificationToken({
        userId: testUser.id,
        token,
        type: 'email_verification',
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      });

      await request(app)
        .post('/api/auth/verify')
        .send({ token })
        .expect(200);
    });

    it('should reject invalid verification token', async () => {
      await request(app)
        .post('/api/auth/verify')
        .send({ token: 'invalid-token' })
        .expect(400);
    });
  });
});
