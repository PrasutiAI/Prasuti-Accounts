import { describe, it, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import request from 'supertest';
import express from 'express';
import { registerRoutes } from '../server/routes';
import { storage } from '../server/storage';
import { jwtService } from '../server/services/jwt.service';
import bcrypt from 'bcrypt';

describe('User Management API', () => {
  let app: express.Application;
  let server: any;
  let adminUser: any;
  let regularUser: any;
  let adminToken: string;
  let userToken: string;

  beforeAll(async () => {
    app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: false }));
    
    const httpServer = await registerRoutes(app);
    server = httpServer;

    // Get or create admin role
    let adminRole = await storage.getRoleByName('admin');
    if (!adminRole) {
      adminRole = await storage.createRole({
        name: 'admin',
        description: 'Full system administrator access',
        permissions: ['*'],
        isActive: true,
      });
    }
    
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

    // Create admin user with proper schema
    adminUser = await storage.createUser({
      email: 'admin@example.com',
      name: 'Admin User',
      password: 'AdminPassword123!', // Let storage hash it
      roleId: adminRole.id,
    });
    
    // Manually verify and activate admin
    await storage.updateUser(adminUser.id, {
      isEmailVerified: true,
      isActive: true,
    });

    // Create regular user with proper schema
    regularUser = await storage.createUser({
      email: 'user@example.com',
      name: 'Regular User',
      password: 'UserPassword123!', // Let storage hash it
      roleId: userRole.id,
    });
    
    // Manually verify and activate user
    await storage.updateUser(regularUser.id, {
      isEmailVerified: true,
      isActive: true,
    });

    // Generate tokens
    adminToken = await jwtService.generateAccessToken(adminUser);
    userToken = await jwtService.generateAccessToken(regularUser);
  });

  afterAll(async () => {
    if (server) {
      server.close();
    }
  });

  describe('GET /api/users', () => {
    it('should return users list for admin', async () => {
      const response = await request(app)
        .get('/api/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body).toHaveProperty('users');
      expect(response.body).toHaveProperty('total');
      expect(response.body).toHaveProperty('pages');
      expect(Array.isArray(response.body.users)).toBe(true);
    });

    it('should reject unauthorized access', async () => {
      await request(app)
        .get('/api/users')
        .expect(401);
    });

    it('should reject access for regular users', async () => {
      await request(app)
        .get('/api/users')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(403);
    });

    it('should support pagination', async () => {
      const response = await request(app)
        .get('/api/users?page=1&limit=1')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body.users).toHaveLength(1);
    });
  });

  describe('GET /api/users/:id', () => {
    it('should return user details for admin', async () => {
      const response = await request(app)
        .get(`/api/users/${regularUser.id}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body).toHaveProperty('id', regularUser.id);
      expect(response.body).toHaveProperty('email', regularUser.email);
      expect(response.body).not.toHaveProperty('passwordHash');
    });

    it('should allow users to access their own profile', async () => {
      const response = await request(app)
        .get(`/api/users/${regularUser.id}`)
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body).toHaveProperty('id', regularUser.id);
    });

    it('should reject access to other users profiles for regular users', async () => {
      await request(app)
        .get(`/api/users/${adminUser.id}`)
        .set('Authorization', `Bearer ${userToken}`)
        .expect(403);
    });

    it('should return 404 for non-existent user', async () => {
      await request(app)
        .get('/api/users/00000000-0000-0000-0000-000000000000')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(404);
    });
  });

  describe('POST /api/users', () => {
    it('should create new user for admin', async () => {
      const userData = {
        email: 'newuser@example.com',
        name: 'New User',
        password: 'NewUserPassword123!',
      };

      const response = await request(app)
        .post('/api/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(userData)
        .expect(201);

      expect(response.body).toHaveProperty('email', userData.email);
      expect(response.body).toHaveProperty('name', userData.name);
      expect(response.body).not.toHaveProperty('passwordHash');
    });

    it('should reject user creation for regular users', async () => {
      const userData = {
        email: 'another@example.com',
        name: 'Another User',
        password: 'AnotherPassword123!',
      };

      await request(app)
        .post('/api/users')
        .set('Authorization', `Bearer ${userToken}`)
        .send(userData)
        .expect(403);
    });

    it('should reject duplicate email', async () => {
      const userData = {
        email: adminUser.email,
        name: 'Duplicate User',
        password: 'DuplicatePassword123!',
      };

      await request(app)
        .post('/api/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(userData)
        .expect(400);
    });

    it('should validate required fields', async () => {
      const userData = {
        email: 'incomplete@example.com',
        // missing name and password
      };

      await request(app)
        .post('/api/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(userData)
        .expect(400);
    });
  });

  describe('PATCH /api/users/:id', () => {
    it('should update user for admin', async () => {
      const updates = {
        name: 'Updated Name',
        role: 'developer',
      };

      const response = await request(app)
        .patch(`/api/users/${regularUser.id}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send(updates)
        .expect(200);

      expect(response.body).toHaveProperty('name', updates.name);
      expect(response.body).toHaveProperty('role', updates.role);
    });

    it('should allow users to update their own profile', async () => {
      const updates = {
        name: 'Self Updated Name',
      };

      const response = await request(app)
        .patch(`/api/users/${regularUser.id}`)
        .set('Authorization', `Bearer ${userToken}`)
        .send(updates)
        .expect(200);

      expect(response.body).toHaveProperty('name', updates.name);
    });

    it('should reject updates to other users for regular users', async () => {
      const updates = {
        name: 'Unauthorized Update',
      };

      await request(app)
        .patch(`/api/users/${adminUser.id}`)
        .set('Authorization', `Bearer ${userToken}`)
        .send(updates)
        .expect(403);
    });

    it('should return 404 for non-existent user', async () => {
      const updates = {
        name: 'Non-existent User',
      };

      await request(app)
        .patch('/api/users/00000000-0000-0000-0000-000000000000')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(updates)
        .expect(404);
    });
  });

  describe('DELETE /api/users/:id', () => {
    let userToDelete: any;

    beforeEach(async () => {
      const passwordHash = await bcrypt.hash('DeletePassword123!', 12);
      userToDelete = await storage.createUser({
        email: `delete-${Date.now()}@example.com`,
        name: 'User To Delete',
        passwordHash,
        role: 'user',
        status: 'active',
        isVerified: true,
      });
    });

    it('should delete user for admin', async () => {
      await request(app)
        .delete(`/api/users/${userToDelete.id}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      // Verify user is deleted
      const deletedUser = await storage.getUser(userToDelete.id);
      expect(deletedUser).toBeUndefined();
    });

    it('should reject deletion for regular users', async () => {
      await request(app)
        .delete(`/api/users/${userToDelete.id}`)
        .set('Authorization', `Bearer ${userToken}`)
        .expect(403);
    });

    it('should prevent deletion of last admin', async () => {
      await request(app)
        .delete(`/api/users/${adminUser.id}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(400);
    });

    it('should return 404 for non-existent user', async () => {
      await request(app)
        .delete('/api/users/00000000-0000-0000-0000-000000000000')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(404);
    });
  });

  describe('GET /api/admin/users', () => {
    it('should return users for admin', async () => {
      const response = await request(app)
        .get('/api/admin/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body).toHaveProperty('users');
      expect(Array.isArray(response.body.users)).toBe(true);
    });

    it('should reject access for regular users', async () => {
      await request(app)
        .get('/api/admin/users')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(403);
    });
  });

  describe('GET /api/admin/stats', () => {
    it('should return system statistics for admin', async () => {
      const response = await request(app)
        .get('/api/admin/stats')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body).toHaveProperty('users');
      expect(response.body).toHaveProperty('system');
      expect(response.body.users).toHaveProperty('totalUsers');
      expect(response.body.users).toHaveProperty('activeUsers');
      expect(response.body.system).toHaveProperty('totalUsers');
    });

    it('should reject access for regular users', async () => {
      await request(app)
        .get('/api/admin/stats')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(403);
    });
  });
});
